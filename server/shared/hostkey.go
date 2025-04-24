// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"encoding/base64"
	"os"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
)

type HostKeyIOer interface {
	Write(ctx context.Context, raw string) error
	Read(ctx context.Context) (string, error)
	Filename() core.Path
}

type HostKeyFile struct {
	fn core.Path
}

func (h *HostKeyFile) Filename() core.Path {
	return h.fn
}

func (h *HostKeyFile) Write(ctx context.Context, raw string) error {

	err := h.fn.MakeParentDirs()
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(h.fn.String(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = fh.Write([]byte(raw))
	if err != nil {
		fh.Close()
		return err
	}
	err = fh.Close()
	if err != nil {
		return err
	}
	return nil
}

func (h *HostKeyFile) Read(ctx context.Context) (string, error) {
	dat, err := h.fn.ReadFile()
	if err != nil {
		return "", err
	}
	return string(dat), nil
}

func NewHostKeyFile(fn core.Path) *HostKeyFile {
	return &HostKeyFile{fn: fn}
}

type HostKey struct {
	core.EntityPrivateEd25519
	io HostKeyIOer
}

func NewHostKeyUnbacked(k core.EntityPrivateEd25519) *HostKey {
	return &HostKey{EntityPrivateEd25519: k}
}

func (k *HostKey) txWritePubToDB(m MetaContext, tx pgx.Tx, typ proto.EntityType, seqno proto.Seqno, host *core.HostID) error {
	pub, err := k.EntityPublic()
	if err != nil {
		return err
	}
	eid := pub.GetEntityID()
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO host_keys (short_host_id, type, key_id, state, seqno, ctime, mtime)
		 VALUES($1, $2, $3, 'valid', $4, NOW(), NOW())`,
		int(host.Short), typ, eid.ExportToDB(), seqno,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("hostkey pub")
	}
	return nil
}

func NewHostKeyGenerate(ctx context.Context, fn core.Path, typ proto.EntityType) (*HostKey, error) {
	h := &HostKey{io: NewHostKeyFile(fn)}
	err := h.generate(ctx, typ)
	if err != nil {
		return nil, err
	}
	err = h.write(ctx)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func NewHostKey(ctx context.Context, fn core.Path, ep *core.EntityPrivateEd25519) (*HostKey, error) {
	h := &HostKey{io: NewHostKeyFile(fn), EntityPrivateEd25519: *ep}
	err := h.write(ctx)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (h *HostKey) generate(ctx context.Context, typ proto.EntityType) error {
	key, err := core.NewEntityPrivateEd25519(typ)
	if err != nil {
		return err
	}
	h.set(key)
	return nil
}

func (h *HostKey) set(key *core.EntityPrivateEd25519) {
	h.EntityPrivateEd25519 = *key
}

func (h *HostKey) write(ctx context.Context) error {
	key := h.EntityPrivateEd25519
	dat := h.PrivateSeed()

	v1 := proto.HostKeyPrivateStorageV1{
		Seed: dat,
		Type: key.Type(),
		Time: proto.Now(),
	}
	x := proto.NewHostKeyPrivateStorageWithV1(v1)
	buf, err := core.EncodeToBytes(&x)
	if err != nil {
		return err
	}
	edat := base64.StdEncoding.EncodeToString(buf)
	return h.io.Write(ctx, edat)
}

func ReadHostKey(ctx context.Context, io HostKeyIOer) (*HostKey, error) {
	dat, err := io.Read(ctx)
	if err != nil {
		return nil, err
	}
	edat, err := base64.StdEncoding.DecodeString(string(dat))
	if err != nil {
		return nil, err
	}
	var x proto.HostKeyPrivateStorage
	err = core.DecodeFromBytes(&x, edat)
	if err != nil {
		return nil, err
	}
	v, err := x.GetV()
	if err != nil {
		return nil, err
	}
	if v != proto.HostKeyPrivateStorageVersion_V1 {
		return nil, core.VersionNotSupportedError("private storage version from the future")
	}
	v1 := x.V1()
	var seed proto.Ed25519SecretKey
	err = seed.Import(v1.Seed[:])
	if err != nil {
		return nil, err
	}
	priv := core.NewEntityPrivateEd25519WithSeed(v1.Type, seed)
	return &HostKey{EntityPrivateEd25519: *priv, io: io}, nil
}

func ReadHostKeyFromFile(ctx context.Context, fn core.Path) (*HostKey, error) {
	io := NewHostKeyFile(fn)
	return ReadHostKey(ctx, io)
}

func NewVHostKeyGenSub(m MetaContext, hid proto.HostID, typ proto.EntityType) (*HostKey, error) {
	ioer, err := m.PrivateHostKeyIOer(hid, typ)
	if err != nil {
		return nil, err
	}
	ret := &HostKey{io: ioer}
	err = ret.generate(m.Ctx(), typ)
	if err != nil {
		return nil, err
	}
	err = ret.write(m.Ctx())
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func NewVHostKeyGen(m MetaContext) (*HostKey, error) {
	ret := &HostKey{}
	typ := proto.EntityType_Host
	err := ret.generate(m.Ctx(), typ)
	if err != nil {
		return nil, err
	}
	hostID, err := ret.HostID()
	if err != nil {
		return nil, err
	}

	ioer, err := m.PrivateHostKeyIOer(*hostID, typ)
	if err != nil {
		return nil, err
	}
	ret.io = ioer
	err = ret.write(m.Ctx())
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func hostKeyFilename(t proto.EntityType) string {
	switch t {
	case proto.EntityType_Host:
		return "main.host.key"
	case proto.EntityType_HostTLSCA:
		return "main.rootca.key"
	case proto.EntityType_HostMerkleSigner:
		return "merkle.host.key"
	case proto.EntityType_HostMetadataSigner:
		return "metadata.host.key"
	default:
		return "generic.host.key"
	}
}

func (h HostKey) EntityID() (*proto.EntityID, error) {
	pub, err := h.EntityPublic()
	if err != nil {
		return nil, err
	}
	ret := pub.GetEntityID()
	return &ret, nil
}

func (h HostKey) HostID() (*proto.HostID, error) {
	eid, err := h.EntityID()
	if err != nil {
		return nil, err
	}
	tmp, err := eid.HostID()
	if err != nil {
		return nil, err
	}
	return &tmp, nil
}

func (h HostKey) HostTLSCAID() (*proto.HostTLSCAID, error) {
	eid, err := h.EntityID()
	if err != nil {
		return nil, err
	}
	tmp, err := eid.ToHostTLSCAID()
	if err != nil {
		return nil, err
	}
	return &tmp, nil
}
