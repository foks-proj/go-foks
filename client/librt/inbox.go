// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package librt

import (
	"cmp"
	"errors"
	"slices"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

// The inbox syncer persists the inbox-version delta (issue #303) to local soft
// SQLite so app starts render instantly/offline and resync incrementally from
// the stored cursor instead of a since=0 full sync.
//
// Storage layout, all soft state under scope lcl.RTInboxScope{fqu, appID} (the
// inbox is viewer-scoped state spanning many parties):
//   - DataType_RTInboxChannel, key = channelID: one wire-shape rem.RTInboxChannel
//     per channel, denormalized like the server's user_channels. The channel
//     name/desc inside remain in their secretboxes -- plaintext never hits the
//     local DB; LocalInbox decrypts at render time.
//   - DataType_RTInboxSyncState, key = EmptyKey: the sync cursor plus the index
//     of persisted channelIDs (the KV layer can't enumerate keys in a scope).
//
// Each page applies atomically (rows + cursor in one DbPutTx), with the cursor
// advanced to the highest version *applied*, never the server-reported head --
// a crash mid-multi-page sync resumes at the last applied page. Merge is
// whole-row overwrite; server-side monotonicity makes the server copy win.
// All of it is self-healing soft state: wiping it just costs a full resync.

func (d *Minder) inboxScope(appID proto.RTAppID) lcl.RTInboxScope {
	return lcl.RTInboxScope{Fqu: d.au.FQU(), AppID: appID}
}

func (d *Minder) dbGetInboxSyncState(
	m MetaContext,
	appID proto.RTAppID,
) (
	lcl.RTInboxSyncState,
	error,
) {
	var ret lcl.RTInboxSyncState
	scope := d.inboxScope(appID)
	_, err := m.DbGet(&ret, libclient.DbTypeSoft, &scope,
		lcl.DataType_RTInboxSyncState, core.EmptyKey{})
	if errors.Is(err, core.RowNotFoundError{}) {
		return lcl.RTInboxSyncState{}, nil // never synced; cursor 0 = full sync
	}
	if err != nil {
		return ret, err
	}
	return ret, nil
}

// SyncInbox pages rtGetChangedThreads from the locally-stored cursor and
// applies each page transactionally (channel rows + advanced cursor). Syncs
// for the same (user × app) are serialized so they can't interleave. Returns
// what changed: the post-sync cursor and how many channel rows were applied.
func (d *Minder) SyncInbox(
	m MetaContext,
	appID proto.RTAppID,
) (
	*lcl.RTInboxSyncSummary,
	error,
) {
	return d.SyncInboxWithPageSize(m, appID, 0)
}

// SyncInboxWithPageSize is SyncInbox with an explicit page size for the
// underlying rtGetChangedThreads calls; 0 = server default. Tests use small
// pages to exercise the per-page atomic apply and crash-resume cursor.
func (d *Minder) SyncInboxWithPageSize(
	m MetaContext,
	appID proto.RTAppID,
	pageSize uint64,
) (
	*lcl.RTInboxSyncSummary,
	error,
) {
	app, err := GetApp(d.au)
	if err != nil {
		return nil, err
	}
	lk := app.inboxSyncLock(appID)
	lk.Lock()
	defer lk.Unlock()

	scope := d.inboxScope(appID)
	state, err := d.dbGetInboxSyncState(m, appID)
	if err != nil {
		return nil, err
	}
	indexed := make(map[proto.RTChannelID]struct{}, len(state.Channels))
	for _, chid := range state.Channels {
		indexed[chid] = struct{}{}
	}

	var numChanged uint64
	for {
		delta, err := d.GetChangedThreads(m, appID, state.Vers, pageSize)
		if err != nil {
			return nil, err
		}
		if len(delta.Channels) == 0 {
			break
		}
		pageVers := state.Vers
		args := make([]libclient.PutArg, 0, len(delta.Channels)+1)
		for i := range delta.Channels {
			ch := &delta.Channels[i]
			if ch.InboxVersion > pageVers {
				pageVers = ch.InboxVersion
			}
			if _, ok := indexed[ch.Md.Id]; !ok {
				indexed[ch.Md.Id] = struct{}{}
				state.Channels = append(state.Channels, ch.Md.Id)
			}
			args = append(args, libclient.PutArg{
				Scope: &scope,
				Typ:   lcl.DataType_RTInboxChannel,
				Key:   ch.Md.Id,
				Val:   ch,
			})
		}
		// A page that doesn't advance the cursor would loop forever; the server
		// guarantees returned bumps are strictly past `since`.
		if pageVers <= state.Vers {
			return nil, core.BadServerDataError("inbox delta did not advance the cursor")
		}
		state.Vers = pageVers
		args = append(args, libclient.PutArg{
			Scope: &scope,
			Typ:   lcl.DataType_RTInboxSyncState,
			Key:   core.EmptyKey{},
			Val:   &state,
		})
		err = m.DbPutTx(libclient.DbTypeSoft, args)
		if err != nil {
			return nil, err
		}
		numChanged += uint64(len(delta.Channels))

		// The head rides along on every page purely as a termination hint; it
		// is never stored (there may be unapplied bumps at versions between the
		// cursor and the head).
		if state.Vers >= delta.InboxVersion {
			break
		}
	}
	return &lcl.RTInboxSyncSummary{Vers: state.Vers, NumChanged: numChanged}, nil
}

// LocalInbox renders the inbox for (user × app) entirely from local storage --
// no network. Channel names/descs are decrypted at render time with the parent
// team's keys; a row that can't be read anymore (lost access, left team) is
// skipped rather than failing the render, since this is all soft state. Rows
// come back newest bump first.
func (d *Minder) LocalInbox(
	m MetaContext,
	appID proto.RTAppID,
) (
	*lcl.RTInboxView,
	error,
) {
	scope := d.inboxScope(appID)
	state, err := d.dbGetInboxSyncState(m, appID)
	if err != nil {
		return nil, err
	}
	ret := lcl.RTInboxView{Vers: state.Vers}
	for _, chid := range state.Channels {
		var row rem.RTInboxChannel
		_, err := m.DbGet(&row, libclient.DbTypeSoft, &scope,
			lcl.DataType_RTInboxChannel, chid)
		if err != nil {
			m.Warnw("LocalInbox", "stage", "dbGet", "chid", chid, "err", err)
			continue
		}
		rv, err := d.renderInboxRow(m, &row)
		if err != nil {
			m.Warnw("LocalInbox", "stage", "render", "chid", chid, "err", err)
			continue
		}
		ret.Rows = append(ret.Rows, *rv)
	}
	slices.SortFunc(ret.Rows, func(a, b lcl.RTInboxRowView) int {
		return cmp.Compare(b.InboxVersion, a.InboxVersion)
	})
	return &ret, nil
}

// renderInboxRow decrypts one stored inbox row into its view form, loading the
// parent team's party (and keys) by ID via the shared party-loader cache.
func (d *Minder) renderInboxRow(
	m MetaContext,
	row *rem.RTInboxChannel,
) (
	*lcl.RTInboxRowView,
	error,
) {
	cfgTeam := team.WrapNamed(proto.FQTeamParsed{
		Team: proto.NewParsedTeamWithFalse(row.Md.ParentTeam),
	})
	rtp, err := d.base.GetParty(m.Base(), cfgTeam)
	if err != nil {
		return nil, err
	}
	md, err := d.decryptChannelMetadata(m, rtp, row.Md)
	if err != nil {
		return nil, err
	}
	ret := lcl.RTInboxRowView{
		Ch:           *md,
		InboxVersion: row.InboxVersion,
		ReadThrough:  row.ReadThrough,
		Hidden:       row.Hidden,
		Muted:        row.Muted,
	}
	if row.Md.LastMsg != nil {
		ret.LastSeq = row.Md.LastMsg.Seq
		ret.LastTime = row.Md.LastMsg.InsertTime
		if ret.LastSeq > ret.ReadThrough {
			ret.Unread = uint64(ret.LastSeq - ret.ReadThrough)
		}
	}
	return &ret, nil
}
