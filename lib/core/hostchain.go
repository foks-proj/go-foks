// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sort"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type ShortHostID uint16

func (s ShortHostID) ExportToDB() int {
	return int(s)
}

type HostID struct {
	Id proto.HostID

	// When storing a HostID locally, we use a short integer like a ShortHostID,
	// to save storage.
	Short ShortHostID

	// If a vanity host is in the the process of being created, it will have a vhostID, but not
	// a hostID yet. However, every established host or vhost should have a vhostID. Unlike
	// a hostID, which is 32-bytes and the hash of the first public key of the host, the vhostID
	// is a random 16-byte value with no cryptographic significance.
	VId proto.VHostID
}

func (h HostID) IDp() *proto.HostID {
	tmp := h.Id
	return &tmp
}

func (h *HostID) Eq(other *HostID) bool {
	return h.Id.Eq(other.Id)
}

func (h HostID) IsZero() bool {
	return h.Id.IsZero() && h.Short == 0
}

func (h *HostID) UnmarshalJSON(data []byte) error {
	type AuxType struct {
		Id    string `json:"host_id"`
		Local uint32 `json:"short"`
	}
	var aux AuxType
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Id) > 0 {
		eid, err := proto.ImportEntityIDFromString(aux.Id)
		if err != nil {
			return err
		}
		hid, err := eid.ToHostID()
		if err != nil {
			return err
		}
		h.Id = hid
	}
	h.Short = ShortHostID(aux.Local)
	return nil
}

type HostIDAndName struct {
	HostID
	Hostname proto.Hostname
}

// code for *reading* host chains
// writing hostchains is on server/shared

type Hostchain struct {
	keys    map[proto.EntityType][]proto.KeyAtSeqno
	raw     proto.HostchainState
	tails   []proto.HostchainTail
	revoked map[proto.FixedEntityID]bool
}

// Keys returns all of the keys of the given type, sorted in order of
// most recent to oldest. If verifying a sig against these keys, and
// you don't know which one is the signer, consume them in the returned
// order. It will be exceedingly rare for the first key not to work, and
// shoudl only be true as the server manages a key upgrade, etc.
func (h Hostchain) Keys(t proto.EntityType) []proto.EntityID {
	v := h.keys[t]
	var ret []proto.EntityID
	if len(v) == 0 {
		return nil
	}
	for i := len(v) - 1; i >= 0; i-- {
		ret = append(ret, v[i].Eid)
	}
	return ret
}

func (h Hostchain) Tail() proto.HostchainTail {
	return proto.HostchainTail{
		Seqno: h.raw.Seqno,
		Hash:  h.raw.Tail,
	}
}

func (h Hostchain) CheckIsSuperChainOf(other Hostchain) error {
	if h.HostID() != other.HostID() {
		return HostchainError("hostchain host mismatch")
	}
	if h.raw.Seqno < other.raw.Seqno {
		return HostchainError("new hostchain was from the past")
	}
	if h.raw.Seqno == other.raw.Seqno {
		if !h.raw.Tail.Eq(other.raw.Tail) {
			return HostchainError("hostchains were same length but had different hashes")
		}
		return nil
	}

	// We can do this more efficiently, in O(log n) or even O(1) time, but
	// this is simpler for now.
	var found *proto.HostchainTail
	for _, t := range h.tails {
		if t.Seqno == other.raw.Seqno {
			found = &t
			break
		}
	}
	if found == nil {
		return HostchainError("hostchain was not a superchain; seqno not found")
	}

	if !found.Hash.Eq(other.raw.Tail) {
		return HostchainError("hostchain was not a superchain; hash mismatch")
	}

	return nil
}

func NewHostchainWithAddr(a proto.TCPAddr) Hostchain {
	ret := NewHostchain()
	ret.raw.Addr = a
	return ret
}

func NewHostchain() Hostchain {
	ret := Hostchain{
		keys:    make(map[proto.EntityType][]proto.KeyAtSeqno),
		revoked: make(map[proto.FixedEntityID]bool),
	}
	return ret
}

func (h Hostchain) HostID() proto.HostID {
	return h.raw.Host
}

func (h Hostchain) copy() Hostchain {
	keys := make(map[proto.EntityType][]proto.KeyAtSeqno)
	for k, v := range h.keys {
		keys[k] = append([]proto.KeyAtSeqno{}, v...)
	}
	revoked := make(map[proto.FixedEntityID]bool)
	for k, v := range h.revoked {
		revoked[k] = v
	}
	return Hostchain{
		keys:    keys,
		raw:     h.raw,
		revoked: revoked,
	}
}

func (h *Hostchain) Import(x proto.HostchainState) error {
	h.keys = make(map[proto.EntityType][]proto.KeyAtSeqno)
	h.raw = x
	for _, k := range x.Keys {
		typ := k.Eid.Type()
		h.keys[typ] = append(h.keys[typ], k)
	}
	for typ, v := range h.keys {
		sort.Slice(v, func(i, j int) bool {
			return v[i].Seqno < v[j].Seqno
		})
		h.keys[typ] = v
	}
	// Zero this out so we don't use it by accident.
	h.raw.Keys = nil
	return nil
}

var HostSubkeyTypes = []proto.EntityType{
	proto.EntityType_HostTLSCA,
	proto.EntityType_HostMerkleSigner,
	proto.EntityType_HostMetadataSigner,
}

var AllHostKeyTypes = append([]proto.EntityType{
	proto.EntityType_Host,
}, HostSubkeyTypes...)

func (h *Hostchain) Export() (proto.HostchainState, error) {
	var keys []proto.KeyAtSeqno
	for _, typ := range AllHostKeyTypes {
		v := h.keys[typ]
		if len(v) == 0 {
			continue
		}
		keys = append(keys, v...)
	}
	h.raw.Keys = keys
	return h.raw, nil
}

func removeIndices[T any](slice []T, indices []int) []T {
	// Sort the indices in descending order so that removing elements
	// from the slice does not change the indices of the remaining elements.
	sort.Sort(sort.Reverse(sort.IntSlice(indices)))

	// Remove the elements at the specified indices.
	for _, i := range indices {
		slice = append(slice[:i], slice[i+1:]...)
	}

	return slice
}

func (h *Hostchain) revokeTLSCA(e proto.EntityID) error {
	var indices []int
	for i, k := range h.raw.Cas {
		if k.Ca.Id.Eq(e) {
			indices = append(indices, i)
		}
	}
	h.raw.Cas = removeIndices(h.raw.Cas, indices)
	return nil
}

func (h *Hostchain) revokeKey(e proto.EntityID) error {
	var indices []int
	lst := h.keys[e.Type()]
	for i, k := range lst {
		if k.Eid.Eq(e) {
			indices = append(indices, i)
		}
	}
	h.keys[e.Type()] = removeIndices(lst, indices)
	feid, err := e.Fixed()
	if err != nil {
		return err
	}
	h.revoked[feid] = true
	return nil
}

func (h *Hostchain) revoke(e proto.EntityID) error {
	if e.Type() == proto.EntityType_HostTLSCA {
		return h.revokeTLSCA(e)
	}
	return h.revokeKey(e)
}

func (h *Hostchain) Addr() proto.TCPAddr {
	return h.raw.Addr
}

func (h Hostchain) checkChainer(c proto.BaseChainer) error {
	if !c.Seqno.IsValid() {
		return HostchainError("seqno 0 not allowed")
	}
	if c.Seqno != h.raw.Seqno+1 {
		return HostchainError("seqno must be exactly 1 greater than previous")
	}
	if c.Seqno == proto.HostchainEldestSeqno {
		if c.Prev != nil {
			return HostchainError("eldest seqno must not have prev")
		}
		return nil
	}
	if c.Prev == nil {
		return HostchainError("prev must not be nil")
	}
	if !c.Prev.Eq(h.raw.Tail) {
		return HostchainError("prev did not match tail")
	}
	return nil
}

func (h Hostchain) checkHostAndSigner(q proto.Seqno, host, signer proto.HostID) error {

	if q == proto.HostchainEldestSeqno && !host.Eq(signer) {
		return HostchainError("hostkey must sign first change")
	}

	if q > proto.HostchainEldestSeqno && !h.raw.Host.Eq(host) {
		return HostchainError("cannot change hostID once established")
	}

	return nil
}

func (h Hostchain) playChanges(
	c proto.HostchainChange,
	hsh proto.LinkHash,
) (
	Hostchain,
	[]EntityPublicEd25519,
	error,
) {
	var keys []EntityPublicEd25519
	ret := h.copy()

	var err error
	err = h.checkChainer(c.Chainer)
	if err != nil {
		return h, nil, err
	}

	err = h.checkHostAndSigner(c.Chainer.Seqno, c.Host, c.Signer)
	if err != nil {
		return h, nil, err
	}

	ret.raw.Seqno = c.Chainer.Seqno
	ret.raw.Tail = hsh
	ret.raw.Time = c.Chainer.Time
	ret.raw.Host = c.Host

	for _, i := range c.Changes {
		keys, err = ret.playChange(i, keys)
		if err != nil {
			return h, nil, err
		}
	}

	// This is a very important line --- it requires that the last signer
	// is the adveritsed signer in the chainlink.
	keys = append(keys, EntityPublicEd25519{EntityID: c.Signer.EntityID()})

	// First link needs to establish the hostID/eldest signer, so
	// it's added implicitly as a key.
	if c.Chainer.Seqno == proto.HostchainEldestSeqno {
		err := ret.addKey(c.Signer.EntityID())
		if err != nil {
			return h, nil, err
		}
	}

	return ret, keys, nil
}

func (h *Hostchain) addKey(eid proto.EntityID) error {
	h.keys[eid.Type()] = append(h.keys[eid.Type()], proto.KeyAtSeqno{
		Eid:   eid,
		Seqno: h.raw.Seqno,
	})
	return nil
}

func (h *Hostchain) playChange(
	c proto.HostchainChangeItem,
	keys []EntityPublicEd25519,
) ([]EntityPublicEd25519, error) {

	typ, err := c.GetT()
	if err != nil {
		return keys, err
	}
	switch typ {
	case proto.HostchainChangeType_Revoke:
		err = h.revoke(c.Revoke())
		if err != nil {
			return nil, err
		}
		return keys, nil
	case proto.HostchainChangeType_Key:
		eid := c.Key()
		err := h.addKey(eid)
		if err != nil {
			return nil, err
		}
		keys = append(keys, EntityPublicEd25519{EntityID: eid})
		return keys, nil
	case proto.HostchainChangeType_TLSCA:
		cert, err := x509.ParseCertificate(c.Tlsca().Cert)
		if err != nil {
			return nil, err
		}
		pk, ok := cert.PublicKey.(crypto.PublicKey)
		if !ok {
			return nil, HostchainError("could not cast public key from cert")
		}
		eid := c.Tlsca().Id.EntityID()
		eidPk := eid.PublicKeyEd25519()
		if !eidPk.Equal(pk) {
			return nil, HostchainError("certificate does not match entity ID")
		}
		keys = append(keys, EntityPublicEd25519{EntityID: eid})
		h.raw.Cas = append(h.raw.Cas, proto.HostTLSCAAtSeqno{
			Ca:    c.Tlsca(),
			Seqno: h.raw.Seqno,
		})
		return keys, nil
	default:
		// Don't die on types we don't recognize, but likely it will
		// fail verification if we need keys, etc.
		return keys, nil
	}
}

func (h Hostchain) findHostKey(e proto.EntityID) bool {
	for _, k := range h.keys[proto.EntityType_Host] {
		if k.Eid.Eq(e) {
			return true
		}
	}
	return false
}

type OpenHostchainChangeLinkRes struct {
	Change proto.HostchainChange
	Hash   proto.LinkHash
	L1     proto.HostchainLinkOuterV1
}

func OpenHostchainChangeLink(
	l proto.HostchainLinkOuter,
) (
	*OpenHostchainChangeLinkRes,
	error,
) {
	v, err := l.GetV()
	if err != nil {
		return nil, err
	}
	if v != proto.HostchainLinkVersion_V1 {
		return nil, VersionNotSupportedError("hostchain link")
	}
	l1 := l.V1()
	var inner proto.HostchainLinkInner
	err = DecodeFromBytes(&inner, l1.Inner)
	if err != nil {
		return nil, err
	}
	hsh, err := HostchainLinkHash(&l)
	if err != nil {
		return nil, err
	}

	typ, err := inner.GetT()
	if err != nil {
		return nil, err
	}
	switch typ {
	case proto.HostchainLinkType_Change:
		ret := OpenHostchainChangeLinkRes{
			Change: inner.Change(),
			Hash:   *hsh,
			L1:     l1,
		}
		return &ret, nil
	}
	return nil, VersionNotSupportedError("hostchain link type unknown")
}

func (h Hostchain) Play(l proto.HostchainLinkOuter) (Hostchain, error) {
	var ret Hostchain
	chng, err := OpenHostchainChangeLink(l)
	if err != nil {
		return h, err
	}
	var verifyEntities []EntityPublicEd25519
	ret, verifyEntities, err = h.playChanges(chng.Change, chng.Hash)
	if err != nil {
		return h, err
	}

	var verifyKeys []Verifier
	for _, e := range verifyEntities {
		verifyKeys = append(verifyKeys, e)
	}
	err = VerifyStackedSignature(&chng.L1, verifyKeys)
	if err != nil {
		return h, err
	}

	if ret.raw.Seqno != proto.HostchainEldestSeqno {

		lst := Last(verifyEntities).EntityID
		flst, err := lst.Fixed()
		if err != nil {
			return h, err
		}
		if h.revoked[flst] {
			return h, HostchainError("revoked key used")
		}
		if !h.findHostKey(lst) {
			return h, HostchainError("existing host signing key not found")
		}

		lastTail := proto.HostchainTail{
			Seqno: h.raw.Seqno,
			Hash:  h.raw.Tail,
		}

		// Keep track of all tails that we've played so far, so we can
		// check against whatever we have in storage.
		ret.tails = append(h.tails, lastTail)
	}

	return ret, nil
}

func (h Hostchain) MultiPlay(v []proto.HostchainLinkOuter) (Hostchain, error) {
	var err error
	r := h
	for _, i := range v {
		r, err = r.Play(i)
		if err != nil {
			return h, err
		}
	}
	return r, nil

}

func (h Hostchain) RootCACertPool() (*x509.CertPool, error) {
	ret := x509.NewCertPool()
	for _, i := range h.raw.Cas {
		raw := i.Ca.Cert
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, err
		}
		ret.AddCert(cert)
	}
	return ret, nil
}

func NewHostchainSkeleton(h proto.HostID, l proto.LinkHash, s proto.Seqno) *Hostchain {
	return &Hostchain{
		tails: []proto.HostchainTail{{Seqno: s, Hash: l}},
		raw: proto.HostchainState{
			Seqno: s,
			Tail:  l,
			Host:  h,
		},
	}
}

func PlayChain(addr proto.TCPAddr, links []proto.HostchainLinkOuter, hostID *proto.HostID) (*Hostchain, error) {
	ch := NewHostchainWithAddr(addr)
	var err error
	ch, err = ch.MultiPlay(links)
	if err != nil {
		return nil, err
	}
	tmp := ch.HostID()
	if tmp.IsZero() {
		return nil, BadServerDataError(
			fmt.Sprintf("empty hostID in hostchain reply (nlink=%d)",
				len(links),
			),
		)
	}
	if hostID != nil && !hostID.Eq(tmp) {
		return nil, HostMismatchError{Which: "hostID"}
	}
	return &ch, nil
}

func CheckChainAgainstPriorChains(this Hostchain, prior *Hostchain) error {
	if prior == nil {
		return nil
	}
	err := this.CheckIsSuperChainOf(*prior)
	if err != nil {
		return err
	}
	return nil

}

func CheckZoneSig(ch Hostchain, pres rem.ProbeRes) (*proto.PublicZone, error) {
	keys := ch.Keys(proto.EntityType_HostMetadataSigner)
	var err error
	var pz *proto.PublicZone

	for _, key := range keys {
		var ep EntityPublic
		ep, err = ImportEntityPublic(key)

		if err != nil {
			return nil, err
		}

		pz, err = Verify2(
			ep,
			pres.Zone.Sig,
			&pres.Zone.Inner,
		)

		if err == nil {
			return pz, nil
		}
	}

	return nil, VerifyError("public zone did not verify")
}
