// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/keybase/saltpack/encoding/basex"
	"golang.org/x/crypto/curve25519"
)

type DataError string

func (p DataError) Error() string {
	return "protocol data error: " + string(p)
}

func (f FQUser) Eq(f2 FQUser) bool {
	return hmac.Equal(f.Uid[:], f2.Uid[:]) && hmac.Equal(f.HostID[:], f2.HostID[:])
}

func (f FQUser) ToFQEntity() FQEntity {
	return FQEntity{
		Entity: f.Uid.EntityID(),
		Host:   f.HostID,
	}
}

func (h HostID) EntityID() EntityID {
	return EntityID(h[:])
}

func (t TeamID) EntityID() EntityID {
	return EntityID(t[:])
}

func (s *Curve25519SecretKey) PublicKey() *Curve25519PublicKey {
	var ret Curve25519PublicKey
	curve25519.ScalarBaseMult((*[32]byte)(&ret), (*[32]byte)(s))
	return &ret
}

func (e EntityID) PublicKeyEd25519() ed25519.PublicKey {
	if e.Type().IsEd25519() {
		return ed25519.PublicKey(e[1:])
	} else {
		return nil
	}
}

func (e EntityID) HostID() (HostID, error) {
	if e.Type() != EntityType_Host || len(e) != e.Type().Len() {
		return HostID{}, EntityError("not a host")
	}
	var ret HostID
	copy(ret[:], e[:])
	return ret, nil
}

func (e EntityID) ScopeToHost(h HostID) FQEntity {
	return FQEntity{
		Entity: e,
		Host:   h,
	}
}

func (e EntityID) ToHostTLSCAID() (HostTLSCAID, error) {
	if e.Type() != EntityType_HostTLSCA || len(e) != e.Type().Len() {
		return HostTLSCAID{}, EntityError("not a host tls ca")
	}
	var ret HostTLSCAID
	copy(ret[:], e[:])
	return ret, nil
}

func (h HostTLSCAID) EntityID() EntityID {
	return EntityID(h[:])
}

func (s *Ed25519SecretKey) PublicKey() *Ed25519PublicKey {
	sk := ed25519.NewKeyFromSeed((*s)[:])
	pk := sk.Public().(ed25519.PublicKey)
	var ret Ed25519PublicKey
	copy(ret[:], pk[:])
	return &ret
}

func (s *Ed25519SecretKey) SecretKeyEd25519() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed((*s)[:])
}

func (s *Ed25519SecretKey) ImportFromEd21559Private(e ed25519.PrivateKey) error {
	seed := e.Seed()
	if len(seed) != len(*s) {
		return DataError("wrong length")
	}
	copy((*s)[:], seed[:])
	return nil
}

func (s *Ed25519SecretKey) EntityID(t EntityType) (EntityID, error) {
	pub := s.PublicKey()
	return t.MakeEntityIDFromKey(*pub)
}

type EntityError string

func (e EntityError) Error() string {
	return "entity error: " + string(e)
}

type LinkHashError string

func (l LinkHashError) Error() string {
	return "link hash error: " + string(l)
}

func (t EntityType) MakeEntityIDFromKey(k Ed25519PublicKey) (EntityID, error) {
	return t.MakeEntityID(k[:])
}
func (t EntityType) MakeEntityID(b []byte) (EntityID, error) {
	if t.Len() < 0 {
		return nil, EntityError("unknown entity type")
	}

	raw := make([]byte, len(b)+1)
	copy(raw[1:], b)
	raw[0] = byte(t)
	ret := EntityID(raw)

	if len(ret) != t.Len() {
		return nil, EntityError("input raw was wrong size")
	}

	return ret, nil
}

func (t EntityType) Len() int {
	switch {
	case t.IsEd25519():
		return 33
	case t == EntityType_Name:
		return 33
	case t == EntityType_Yubi:
		return 34
	case t == EntityType_PKIXCert:
		return 33
	default:
		return -1
	}
}

func (t EntityType) IsValid() bool {
	return t.Len() > 0
}

func ImportUIDFromBytes(b []byte) (*UID, error) {
	tmp, err := ImportEntityIDFromBytes(b)
	if err != nil {
		return nil, err
	}
	ret, err := tmp.ToUID()
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func ImportTeamIDFromBytes(b []byte) (*TeamID, error) {
	tmp, err := ImportEntityIDFromBytes(b)
	if err != nil {
		return nil, err
	}
	ret, err := tmp.ToTeamID()
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (t *TeamID) ImportFromBytes(b []byte) error {
	tmp, err := ImportTeamIDFromBytes(b)
	if err != nil {
		return err
	}
	*t = *tmp
	return nil
}

func (u *UID) ImportFromDB(b []byte) error {
	tmp, err := ImportUIDFromBytes(b)
	if err != nil {
		return err
	}
	*u = *tmp
	return nil
}

func (x *X509CertID) ImportFromDB(b []byte) error {
	eid, err := ImportEntityIDFromBytes(b)
	if err != nil {
		return err
	}
	ret, err := eid.ToX509CertID()
	if err != nil {
		return err
	}
	*x = ret
	return nil
}

func ImportEntityIDFromBytes(b []byte) (EntityID, error) {
	if len(b) < 33 {
		return nil, EntityError("input bytes are too short")
	}
	l := EntityType(b[0]).Len()
	if len(b) != l {
		return nil, EntityError("wrong length")
	}
	ret := make([]byte, l)
	copy(ret[:], b)
	return EntityID(ret), nil
}

func (u UID) Type() EntityType { return EntityType_User }

func (e EntityID) ToUID() (UID, error) {
	var ret UID
	if len(e) != len(ret) {
		return ret, EntityError("wrong length for UID")
	}
	if e.Type() != ret.Type() {
		return ret, EntityError("wrong leading byte for UID")
	}
	copy(ret[:], e)
	return ret, nil
}

func (t TeamID) Type() EntityType { return EntityType_Team }

func (e EntityID) ToTeamID() (TeamID, error) {
	var ret TeamID
	if len(e) != len(ret) {
		return ret, EntityError("wrong length for team ID")
	}
	if e.Type() != ret.Type() {
		return ret, EntityError("wrong leading byte for team ID")
	}
	copy(ret[:], e)
	return ret, nil
}

func (e EntityID) ToHostID() (HostID, error) {
	var ret HostID
	if len(e) != len(ret) {
		return ret, EntityError("wrong length for host ID")
	}
	if e.Type() != ret.Type() {
		return ret, EntityError("wrong leading byte for host ID")
	}
	copy(ret[:], e)
	return ret, nil
}

func (e EntityID) ToYubiID() (YubiID, error) {
	if e.Type() != EntityType_Yubi {
		return nil, EntityError("wrong type for yubi ID")
	}
	return YubiID(e), nil
}

func (h HostID) Type() EntityType { return EntityType_Host }

func (e EntityID) IsDeviceID() bool {
	return e.Type() == EntityType_Device
}

func (e EntityID) ToX509CertID() (X509CertID, error) {
	if e.Type() != EntityType_X509Cert {
		return nil, EntityError("wrong type for x509 ID")
	}
	if len(e) != e.Type().Len() {
		return nil, EntityError("wrong length for x509 ID")
	}
	return X509CertID(e), nil
}

func (e EntityID) ToDeviceID() (DeviceID, error) {
	if len(e) != EntityType_Device.Len() {
		return nil, EntityError("wrong length for device ID")
	}
	if e.Type() != EntityType_Device {
		return nil, EntityError("wrong leading byte for device ID")
	}
	return DeviceID(e), nil
}

func (h HostMerkleSignerID) Type() EntityType { return EntityType_HostMerkleSigner }

func (e EntityID) ToHostMerkleSignerID() (HostMerkleSignerID, error) {
	var ret HostMerkleSignerID
	if len(e) != ret.Type().Len() {
		return nil, EntityError("wrong length for host merkle ID")
	}
	if e.Type() != ret.Type() {
		return nil, EntityError("wrong leading byte for host merkle ID")
	}
	return HostMerkleSignerID(e), nil
}

func (u UID) EntityID() EntityID {
	return EntityID(u[:])
}

func (l *LinkOuterV1) GetSignatures() []Signature {
	return l.Signatures
}

func (l *LinkOuterV1) SetSignatures(s []Signature) {
	l.Signatures = s
}

func (l *HostchainLinkOuterV1) GetSignatures() []Signature {
	return l.Signatures
}

func (l *HostchainLinkOuterV1) SetSignatures(s []Signature) {
	l.Signatures = s
}

func ExportEd25519Public(k ed25519.PublicKey) Ed25519PublicKey {
	var ret Ed25519PublicKey
	if len(k) != len(ret) {
		panic("bad ed25519 public key")
	}
	copy(ret[:], k[:])
	return ret
}

func (e *Ed25519PublicKey) ImportFromDB(b []byte) error {
	if len(b) != len(e) {
		return DataError("wrong length")
	}
	copy(e[:], b)
	return nil
}

func (e *Ed25519PublicKey) DeviceID() DeviceID {
	var tmp [33]byte
	copy(tmp[1:], e[:])
	tmp[0] = byte(EntityType_Device)
	return DeviceID(tmp[:])
}

func ExportECDSAPublic(k *ecdsa.PublicKey) ECDSACompressedPublicKey {
	pkix := elliptic.MarshalCompressed(k.Curve, k.X, k.Y)
	return ECDSACompressedPublicKey(pkix)
}

func (e ECDSACompressedPublicKey) ImportToECDSAPublic() (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	x, y := elliptic.UnmarshalCompressed(curve, e[:])
	if x == nil {
		return nil, DataError("invalid ECDSA public key")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (o Ed25519PublicKey) Import() ed25519.PublicKey {
	return ed25519.PublicKey(o[:])
}

func (h HostID) Eq(h2 HostID) bool {
	return len(h) > 0 && len(h2) > 0 && hmac.Equal(h[:], h2[:])
}

func (e EntityID) Eq(e2 EntityID) bool {
	return len(e) > 0 && len(e2) > 0 && hmac.Equal(e[:], e2[:])
}

func (r Role) Eq(r2 Role) (bool, error) {
	t1, err1 := r.GetT()
	if err1 != nil {
		return false, err1
	}
	t2, err2 := r2.GetT()
	if err2 != nil {
		return false, err2
	}
	if t1 != t2 {
		return false, nil
	}
	if t1 != RoleType_MEMBER {
		return true, nil
	}
	return r.Member() == r2.Member(), nil
}

func (r RoleType) Cmp(r2 RoleType) int {
	if r == r2 {
		return 0
	}
	if int(r) < int(r2) {
		return -1
	}
	return 1
}

func (r Role) ExportToDB() (int, int, error) {
	t, err := r.GetT()
	if err != nil {
		return 0, 0, err
	}
	var l int
	if t == RoleType_MEMBER {
		l = int(r.Member())
	}
	return int(t), l, nil
}

func ImportRoleFromDB(t int, l int) (*Role, error) {
	var ret Role
	switch RoleType(t) {
	case RoleType_ADMIN, RoleType_OWNER:
		if l != 0 {
			return nil, DataError("invalid level for admin or owner")
		}
		ret = NewRoleDefault(RoleType(t))
	case RoleType_MEMBER:
		if l < 0 || l > 0xffff {
			return nil, DataError("invalid level for member")
		}
		ret = NewRoleWithMember(VizLevel(l))
	default:
		return nil, DataError("invalid role type")
	}
	return &ret, nil
}

func (r *Role) ImportFromDB(t int, l int) error {
	tmp, err := ImportRoleFromDB(t, l)
	if err != nil {
		return err
	}
	*r = *tmp
	return nil
}

// Returns -1 if r < r2; 0 if r == r2; and 1 if r > r2
func (r Role) Cmp(r2 Role) (int, error) {
	t1, err := r.GetT()
	if err != nil {
		return 0, err
	}
	t2, err := r2.GetT()
	if err != nil {
		return 0, err
	}
	res := t1.Cmp(t2)
	if res != 0 {
		return res, nil
	}
	if t1 != RoleType_MEMBER {
		return 0, nil
	}
	l1 := r.Member()
	l2 := r2.Member()
	if l1 < l2 {
		return -1, nil
	}
	if l2 > l1 {
		return 1, nil
	}
	return 0, nil
}

func (r Role) GreaterThan(r2 Role) (bool, error) {
	c, err := r.Cmp(r2)
	return c > 0, err
}
func (r Role) LessThan(r2 Role) (bool, error) {
	c, err := r.Cmp(r2)
	return c < 0, err
}

func (p *Curve25519PublicKey) Eq(p2 *Curve25519PublicKey) bool {
	return p != nil && p2 != nil && hmac.Equal((*p)[:], (*p2)[:])
}

func (e EntityID) ExportToDB() []byte {
	return []byte(e[:])
}

func (u UID) ExportToDB() []byte {
	return []byte(u[:])
}

func (c Commitment) ExportToDB() []byte {
	return []byte(c[:])
}

func (c *Curve25519PublicKey) ExportToDB() []byte {
	if c == nil {
		return nil
	}
	return []byte(c[:])
}

func (c *Curve25519PublicKey) ImportFromDB(b []byte) error {
	if len(b) != len(c) {
		return DataError("wrong length")
	}
	copy(c[:], b)
	return nil
}

func (e Ed25519PublicKey) ExportToDB() []byte {
	return []byte(e[:])
}

func (r RandomCommitmentKey) ExportToDB() []byte {
	return []byte(r[:])
}

func (x X509CertID) ExportToDB() []byte {
	return []byte(x[:])
}

func (d DeviceType) ExportToDB() string {
	switch d {
	case DeviceType_Computer:
		return "computer"
	case DeviceType_Mobile:
		return "mobile"
	case DeviceType_YubiKey:
		return "yubikey"
	case DeviceType_Backup:
		return "backup"
	default:
		return "none"
	}
}

func (t EntityType) IsEd25519() bool {
	switch t {
	case EntityType_User, EntityType_Host, EntityType_Device,
		EntityType_X509Cert, EntityType_LocationVRF, EntityType_Service,
		EntityType_HostMerkleSigner, EntityType_HostMetadataSigner, EntityType_HostTLSCA,
		EntityType_Subkey, EntityType_Team, EntityType_PTKVerify, EntityType_PUKVerify,
		EntityType_BackupKey, EntityType_PassphraseKey:
		return true
	default:
		return false
	}
}

func (e EntityID) EqualEd25519Publickey(k Ed25519PublicKey) bool {
	return len(k)+1 == len(e) && hmac.Equal(e[1:], k[:])
}

func (e EntityID) EqualPublicKey(k crypto.PublicKey) bool {
	if len(e) != e.Type().Len() {
		return false
	}
	switch {
	case e.Type().IsEd25519():
		k2 := ed25519.PublicKey(e[1:])
		return k2.Equal(k)
	case e.Type() == EntityType_Yubi:
		k2, err := YubiID(e).ExportToECDSA()
		if err != nil {
			return false
		}
		return k2.Equal(k)
	default:
		return false
	}
}

func (d EntityID) ExportToPublicKey() (crypto.PublicKey, error) {
	if len(d) != d.Type().Len() {
		return nil, EntityError("wrong key length")
	}
	switch {
	case d.Type().IsEd25519():
		return ed25519.PublicKey(d[1:]), nil
	case d.Type() == EntityType_Yubi:
		return YubiID(d).ExportToPublicKey()
	default:
		return nil, EntityError("cannot export unknown type to public key")
	}
}

func (d DeviceID) ExportToPublicKey() (crypto.PublicKey, error) {
	return EntityID(d).ExportToPublicKey()
}

func (y YubiID) ExportToPublicKey() (crypto.PublicKey, error) {
	return y.ExportToECDSA()
}

func (y YubiID) ExportToECDSA() (*ecdsa.PublicKey, error) {
	if EntityID(y).Type() != EntityType_Yubi {
		return nil, EntityError("wrong key type")
	}
	curve := elliptic.P256()
	xCoord, yCoord := elliptic.UnmarshalCompressed(curve, y[1:])
	if xCoord == nil || yCoord == nil {
		return nil, EntityError("cannot decode compressed public key")
	}
	return &ecdsa.PublicKey{Curve: curve, X: xCoord, Y: yCoord}, nil
}

func (d DeviceID) ExportToDB() []byte {
	return EntityID(d).ExportToDB()
}

func (r Random16) ExportToDB() []byte {
	return r[:]
}

func (u UID) IsZero() bool {
	return EntityID33(u).IsZero()
}

func (h HostID) IsZero() bool {
	return EntityID33(h).IsZero()
}

func hashIsZero(h []byte) bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

func (m MerkleTreeRFOutput) IsZero() bool {
	return hashIsZero(m[:])
}

func (s StdHash) IsZero() bool {
	return hashIsZero(s[:])
}

func (s LinkHash) IsZero() bool {
	return hashIsZero(s[:])
}

func (k Curve25519PublicKey) IsZero() bool {
	return IsZero(k[:])
}

func (m HMACKeyID) ExportToDB() []byte {
	return m[:]
}

func (e EntityID33) IsZero() bool {
	return IsZero(e[:])
}

func IsZero(e []byte) bool {
	for _, b := range e[:] {
		if b != 0 {
			return false
		}
	}
	return true
}

func Now() Time {
	return Time(time.Now().UTC().UnixMilli())
}

func (t Time) Import() time.Time {
	return time.UnixMilli(int64(t)).UTC()
}

func (t TimeMicro) Import() time.Time {
	return time.UnixMicro(int64(t)).UTC()
}

func ExportTime(t time.Time) Time {
	return Time(t.UTC().UnixMilli())
}

func ExportTimeMicro(t time.Time) TimeMicro {
	return TimeMicro(t.UTC().UnixMicro())
}

func (t Time) ToSecondsFloat() float64 {
	return float64(t) / 1000.0
}

func Today() Date {
	n := time.Now()
	return Date{
		Year:  uint64(n.Year()),
		Month: uint64(n.Month()),
		Day:   uint64(n.Day()),
	}
}

func NewTimeFromSecs(s int64) Time {
	return Time(s * 1000)
}

func (h HMAC) Eq(h2 HMAC) bool {
	return hmac.Equal(h[:], h2[:])
}

func (p PassphraseSalt) EncodeToDB() []byte {
	return p[:]
}

func (e EntityID) Type() EntityType {
	return EntityType(e[0])
}

func (u UID) Eq(u2 UID) bool {
	return hmac.Equal(u[:], u2[:])
}

func (u *UID) ExportToDBMaybeNil() *[]byte {
	if u == nil {
		return nil
	}
	tmp := u.ExportToDB()
	return &tmp
}

func (r Role) AssertEq(r2 Role, neqErr error) error {
	eq, err := r.Eq(r2)
	if err != nil {
		return err
	}
	if !eq {
		return neqErr
	}
	return nil
}

func NewRole(rt RoleType, lev VizLevel) *Role {
	switch rt {
	case RoleType_MEMBER:
		ret := NewRoleWithMember(lev)
		return &ret
	case RoleType_ADMIN, RoleType_OWNER:
		ret := NewRoleDefault(rt)
		return &ret
	default:
		return nil
	}
}

func (h StdHash) Eq(h2 StdHash) bool {
	return hmac.Equal(h[:], h2[:])
}

func (h LinkHash) Eq(h2 LinkHash) bool {
	return hmac.Equal(h[:], h2[:])
}

func (e EntityID) EncodeHex() string {
	return hex.EncodeToString(e[:])
}

func (u UID) EncodeHex() string {
	return hex.EncodeToString(u[:])
}

func (s StdHash) ExportToDB() []byte {
	return s[:]
}

func (s LinkHash) ExportToDB() []byte {
	return s[:]
}

func (s LinkHash) ToStdHash() StdHash {
	return StdHash(s)
}

func (d DeviceID) Eq(d2 DeviceID) bool {
	return hmac.Equal(d[:], d2[:])
}

func (l LocationVRFID) ExportToDB() []byte {
	return l[:]
}

func (l TreeLocation) ExportToDB() []byte {
	return l[:]
}

func (p PassphraseSalt) IsZero() bool {
	for _, c := range p[:] {
		if c != 0 {
			return false
		}
	}
	return true
}

func (k MerkleTreeRFOutput) Eq(k2 MerkleTreeRFOutput) bool {
	return hmac.Equal(k[:], k2[:])
}

func (n *MerkleInteriorNode) SetChild(pos bool, hash *MerkleNodeHash) {
	if pos {
		n.Right = *hash
	} else {
		n.Left = *hash
	}
}

func (h *MerkleNodeHash) IsEmpty() bool {
	for _, b := range (*h)[:] {
		if b != byte(0) {
			return false
		}
	}
	return true
}

func (n *MerkleInteriorNode) SetEmpty(hash *MerkleNodeHash) {
	if n.Right.IsEmpty() {
		n.Right = *hash
	} else {
		n.Left = *hash
	}
}

func (m *MerkleTreeRFOutput) ExportToDB() []byte {
	return m[:]
}

func (m *MerkleNodeHash) ExportToDB() []byte {
	return m[:]
}

func (m *MerkleRootHash) ExportToDB() []byte {
	return m[:]
}

func ImportMerkleRootHash(b []byte) (*MerkleRootHash, error) {
	var h MerkleRootHash
	if len(b) != len(h) {
		return nil, EntityError("invalid MerkleRootHash length")
	}
	copy(h[:], b)
	return &h, nil
}

func (h *MerkleNodeHash) Eq(h2 *MerkleNodeHash) bool {
	return hmac.Equal((*h)[:], (*h2)[:])
}

func (h *MerkleBackPointerHash) Eq(h2 *MerkleBackPointerHash) bool {
	return hmac.Equal((*h)[:], (*h2)[:])
}

func (h *MerkleRootHash) Eq(h2 *MerkleRootHash) bool {
	return hmac.Equal((*h)[:], (*h2)[:])
}

func (i KexSessionID) ExportToDB() []byte {
	return i[:]
}

func (s DurationMilli) Duration() time.Duration {
	return time.Duration(s) * time.Millisecond
}

func (s DurationSecs) Duration() time.Duration {
	return time.Duration(s) * time.Second
}

func (d DurationMilli) Import() time.Duration {
	return time.Duration(d) * time.Millisecond
}

func ExportDurationMilli(d time.Duration) DurationMilli {
	return DurationMilli(d / time.Millisecond)
}

func ExportDurationSecs(d time.Duration) DurationSecs {
	return DurationSecs(d / time.Second)
}

func (s *Ed25519SecretKey) ExportToDB() []byte {
	return (*s)[:]
}

func (s *Ed25519SecretKey) Import(data []byte) error {
	if len(data) != len(*s) {
		return DataError("wrong length")
	}
	copy((*s)[:], data)
	return nil
}

func (k *KexSessionID) Eq(k2 *KexSessionID) bool {
	return hmac.Equal((*k)[:], (*k2)[:])
}

func (d Date) ExportToDB() string {
	return fmt.Sprintf("%d-%d-%d", d.Year, d.Month, d.Day)
}

func (e EntityID) Fixed() (FixedEntityID, error) {
	var ret FixedEntityID
	if len(e) > len(ret) {
		return ret, EntityError("entity ID exceeds expected length")
	}
	copy(ret[:], e)
	return ret, nil
}

func (f FQEntity) Fixed() (*FQEntityFixed, error) {
	fid, err := f.Entity.Fixed()
	if err != nil {
		return nil, nil
	}
	ret := &FQEntityFixed{
		Entity: fid,
		Host:   f.Host,
	}
	return ret, nil
}

func (f FixedEntityID) Unfix() EntityID {
	l := EntityType(f[0]).Len()
	return EntityID(f[:l])
}

func (f FixedEntityID) Eq(f2 FixedEntityID) bool {
	return hmac.Equal(f[:], f2[:])
}

func (f1 FQEntity) Eq(f2 FQEntity) bool {
	return f1.Entity.Eq(f2.Entity) && f1.Host.Eq(f2.Host)
}

func (d DeviceID) Type() EntityType { return EntityType_Device }

func (e EntityID) AssertCorrectLength() error {
	if e.Type().Len() != len(e) {
		return EntityError("imported entity has wrong length")
	}
	return nil
}

func (t EntityType) ImportFromPublicKey(k crypto.PublicKey) (EntityID, error) {
	var raw []byte
	switch tk := k.(type) {
	case ed25519.PublicKey:
		raw = tk[:]
	case *ecdsa.PublicKey:
		raw = ExportECDSAPublic(tk)
	default:
		return nil, EntityError("expected Ed25519 or ECDSA key but got something else")
	}
	ret := EntityID(make([]byte, len(raw)+1))
	ret[0] = byte(t)
	copy(ret[1:], raw)
	err := ret.AssertCorrectLength()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (y YubiID) CompressedPublicKey() ECDSACompressedPublicKey {
	return ECDSACompressedPublicKey(y[1:])
}

func (b BoxSetID) ExportToDB() []byte {
	return b[:]
}

func (b *BoxSetID) ImportFromBytes(i []byte) error {
	if len(i) != len(*b) {
		return DataError("wrong length")
	}
	copy((*b)[:], i)
	return nil
}

var LocalHost = []byte{0}

func (h *HostID) ExportToDBIfNotCurrentHost(h2 *HostID) []byte {
	if h == nil {
		return LocalHost
	}
	if h2 == nil {
		return (*h)[:]
	}
	if h.Eq(*h2) {
		return LocalHost
	}
	return (*h)[:]
}

func (f FQEntityInHostScope) WithHost(h HostID) FQEntity {
	ret := FQEntity{
		Entity: f.Entity,
	}
	if f.Host == nil {
		ret.Host = h
	} else {
		ret.Host = *f.Host
	}
	return ret
}

func (f FQEntity) AtHost(h HostID) FQEntityInHostScope {
	ret := FQEntityInHostScope{
		Entity: f.Entity,
	}
	if f.Host.Eq(h) {
		ret.Host = nil
	} else {
		ret.Host = &f.Host
	}
	return ret
}

func (f FQEntityInHostScope) Fixed(h HostID) (*FQEntityFixed, error) {
	fid, err := f.Entity.Fixed()
	if err != nil {
		return nil, err
	}
	ret := &FQEntityFixed{Entity: fid}
	if f.Host == nil {
		ret.Host = h
	} else {
		ret.Host = *f.Host
	}
	return ret, nil
}

func (r Role) IsSet() bool {
	t, err := r.GetT()
	return err == nil && t != RoleType_NONE
}

func (u Name) Normalize() Name {
	return Name(strings.ToLower(string(u)))
}

func NewTCPAddr(h Hostname, p Port) TCPAddr {
	return TCPAddr(fmt.Sprintf("%s:%d", string(h), p))
}
func NewTCPAddrPortOpt(h Hostname, p *Port) TCPAddr {
	if p == nil {
		return TCPAddr(string(h))
	}
	return NewTCPAddr(h, *p)
}

func (b BindAddr) GetPort() (Port, error) {
	return TCPAddr(b).GetPort()
}

// GetPort gets the port from the TCPAddr. If no port is found, it will return
// 0 with no error. If a port is found, it will return the port number and no
// error. If the port is not a valid number, it will return an error. Works
// for hostnames, IPv4 and IPv6 addresses in [::1]:80 style format.
func (a TCPAddr) GetPort() (Port, error) {
	portRxx := regexp.MustCompile(`^[^:]+:(\d+)$`)
	ipv6PortRxx := regexp.MustCompile(`^\[[^]]+\]:(\d+)$`)

	m0 := portRxx.FindStringSubmatch(string(a))
	var portStr string
	if len(m0) > 1 {
		portStr = m0[1]
	} else {
		m1 := ipv6PortRxx.FindStringSubmatch(string(a))
		if len(m1) > 1 {
			portStr = m1[1]
		}
	}
	if portStr == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	return Port(port), nil
}

func (t TCPAddr) MaybeElidePort(defport Port) (TCPAddr, error) {
	port, err := t.GetPort()
	if err != nil {
		return "", err
	}
	if port == defport || port == 0 {
		return NewTCPAddrPortOpt(t.Hostname(), nil), nil
	}
	return t, nil
}

func (a TCPAddr) Portify(def Port) (TCPAddr, error) {
	addr := string(a)
	if strings.IndexByte(addr, ':') >= 0 {
		_, _, err := net.SplitHostPort(addr)
		// "too mamy colons" means an IPV6 address, we think!
		if err != nil {
			return TCPAddr(fmt.Sprintf("[%s]:%d", addr, def)), nil
		}
		return a, nil
	}
	return TCPAddr(fmt.Sprintf("%s:%d", addr, def)), nil
}

func (a TCPAddr) Split() (Hostname, *Port, error) {
	var zed Hostname
	addr := string(a)
	if strings.IndexByte(addr, ':') < 0 {
		return Hostname(addr), nil, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return zed, nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return zed, nil, err
	}
	po := Port(p)
	return Hostname(host), &po, nil
}

func (a TCPAddr) WithHostname(hn Hostname) (TCPAddr, error) {
	_, p, err := a.Split()
	if err != nil {
		return a, err
	}
	return NewTCPAddrPortOpt(hn, p), nil
}

func (a TCPAddr) Hostname() Hostname {
	addr := string(a)
	if strings.IndexByte(addr, ':') < 0 {
		return Hostname(addr)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return Hostname(addr)
	}
	return Hostname(host)
}

func (a TCPAddr) String() string {
	return string(a)
}

func (t ShortIDType) Generate() (*ShortID, error) {
	var ret ShortID
	n, err := rand.Read(ret[1:])
	if err != nil {
		return nil, err
	}
	if n != len(ret)-1 {
		return nil, DataError("short random read")
	}
	ret[0] = byte(t)
	return &ret, nil
}

func GenerateWaitListID() (*WaitListID, error) {
	tmp, err := ShortIDType_WaitList.Generate()
	if err != nil {
		return nil, err
	}
	ret := WaitListID(*tmp)
	return &ret, nil
}

func (i ShortID) ExportToDB() []byte {
	return i[:]
}

func (w WaitListID) ExportToDB() []byte {
	return w[:]
}

func (y YubiID) Check() bool {
	return EntityID(y).Type() == EntityType_Yubi && len(y) == 34
}

func (h HostID) ExportToDB() []byte {
	return h[:]
}

func (l *LinkOuterV1) AssertNormalized() error          { return nil }
func (l *TestLinkOuterV1) AssertNormalized() error      { return nil }
func (t *TempDHKeySigTemplate) AssertNormalized() error { return nil }
func (e *HostchainLinkOuterV1) AssertNormalized() error { return nil }
func (e *MerkleRoot) AssertNormalized() error           { return nil }
func (p *PublicZone) AssertNormalized() error           { return nil }
func (l *LinkInner) AssertNormalized() error            { return nil }

type NormalizationError string

func (n NormalizationError) Error() string {
	return "normalization error: " + string(n)
}

// Usernames must be normalized down to lowercase ASCII
// and 0-9 digits, and underscores. They furthemore must not start or
// end with an underscore, and must not contain two underscores in a row.
var NameNormalizedRxx = regexp.MustCompile(`^[a-z0-9_]+$`)
var NameBadNormalizedRxx = regexp.MustCompile(`^_|_$|__`)

func (u Name) AssertNormalized() error {
	s := string(u)
	if !NameNormalizedRxx.MatchString(s) || NameBadNormalizedRxx.MatchString(s) {
		return NormalizationError("name")
	}
	return nil
}

var DeviceNameNormalizedRxx = regexp.MustCompile(`^[a-z0-9][a-z0-9_ .'+-]+$`)
var DeviceNameBadNormalizedRxx = regexp.MustCompile(`  | $`)
var DeviceNameTokenBadNormalizedRxx = regexp.MustCompile(`[._+'-]{2}|[_'.]$|^[+-]$`)

func (d DeviceNameNormalized) AssertNormalized() error {
	if len(d) > 200 {
		return NormalizationError("device name, length check")
	}
	s := string(d)
	if !DeviceNameNormalizedRxx.MatchString(s) || DeviceNameBadNormalizedRxx.MatchString(s) {
		return NormalizationError("device name, full check")
	}
	v := strings.Split(s, " ")
	for _, x := range v {
		if DeviceNameTokenBadNormalizedRxx.MatchString(x) {
			return NormalizationError("device name, token check")
		}
	}
	return nil
}

func (d *DeviceLabel) AssertNormalized() error { return d.Name.AssertNormalized() }

func (h HostTLSCAID) Eq(e EntityID) bool {
	return len(h) > 0 && len(e) > 0 && hmac.Equal(h[:], e[:])
}

func (h HostID) AssertType() error {
	if EntityType(h[0]) != EntityType_Host {
		return EntityError("bad hostID")
	}
	return nil
}

func (h HostID) Hex() string {
	return hex.EncodeToString(h[:])
}

func ImportLinkHashFromDB(raw []byte) (*LinkHash, error) {
	var ret LinkHash
	if len(raw) != len(ret) {
		return nil, LinkHashError("wrong size")
	}
	copy(ret[:], raw[:])
	return &ret, nil
}

func (b *MerkleBatch) IsEmpty() bool {
	return b.Hostchain == nil && len(b.Leaves) == 0
}

func (l *LinkHash) Hex() string {
	return hex.EncodeToString(l[:])
}

func (e *EntityID33) ImportFromBytes(b []byte) error {
	if len(b) != len(e) {
		return EntityError("bad entity id")
	}
	copy((*e)[:], b[:])
	return nil
}

func (s *StdHash) ImportFromBytes(b []byte) error {
	if len(b) != len(s) {
		return EntityError("bad hash")
	}
	copy((*s)[:], b[:])
	return nil
}

func (m *MerkleTreeRFOutput) ImportFromBytes(b []byte) error {
	if len(b) != len(m) {
		return EntityError("bad merkle tree output")
	}
	copy((*m)[:], b[:])
	return nil
}

func (l *LinkHash) ImportFromBytes(b []byte) error {
	if len(b) != len(l) {
		return EntityError("bad link hash")
	}
	copy((*l)[:], b[:])
	return nil
}

func (h *HostID) ImportFromBytes(b []byte) error {
	if len(b) != len(h) {
		return EntityError("bad host id")
	}
	copy((*h)[:], b[:])
	return nil
}

func (h *HostTLSCAID) ImportFromBytes(b []byte) error {
	if len(b) != len(h) {
		return EntityError("bad host tls ca id")
	}
	copy((*h)[:], b[:])
	return nil
}

var charMap = []byte{
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
	'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
	'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', '-', '_',
}

func Be64Encode(u uint64) []byte {
	b := make([]byte, 0, 8)
	first := true
	for u > 0 || first {
		first = false
		b = append(b, charMap[u&0x3f])
		u >>= 6
	}
	return b
}

func (r *MerkleRootHash) ImportFromBytes(b []byte) error {
	if len(b) != len(r) {
		return EntityError("bad merkle root hash")
	}
	copy((*r)[:], b[:])
	return nil
}

func (k HostMerkleSignerID) Eq(k2 HostMerkleSignerID) bool {
	return hmac.Equal(k[:], k2[:])
}

func (k HostMerkleSignerID) ExportToDB() []byte {
	return k[:]
}

func (t MerklePathTerminal) KeyWasFound() (bool, error) {
	complete, err := t.GetLeaf()
	if err != nil {
		return false, err
	}
	return (complete && t.True().FoundKey == nil), nil
}

func (h HostchainTail) Eq(h2 HostchainTail) bool {
	return h.Hash.Eq(h2.Hash) && h.Seqno == h2.Seqno
}

func (h HostTLSCAID) ExportToDB() []byte {
	return h[:]
}

func (h HostTLSCAID) Hex() string {
	return hex.EncodeToString(h[:])
}
func (m MerkleTreeRFOutput) Hex() string {
	return hex.EncodeToString(m[:])
}

func B62EncodeByte(b byte) (byte, error) {
	switch {
	case b < 10:
		return '0' + b, nil
	case b < 36:
		return 'A' + b - 10, nil
	case b < 62:
		return 'a' + b - 36, nil
	default:
		return 0, DataError("invalid base62 byte")
	}
}

func B62DecodeByte(b byte) (byte, error) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', nil
	case b >= 'A' && b <= 'Z':
		return b - 'A' + 10, nil
	case b >= 'a' && b <= 'z':
		return b - 'a' + 36, nil
	default:
		return 0, DataError(fmt.Sprintf("invalid base62 byte: %c", b))
	}
}

func B62Decode(s string) ([]byte, error) {
	return basex.Base62StdEncodingStrict.DecodeString(s)
}

func B62Encode(b []byte) string {
	return basex.Base62StdEncodingStrict.EncodeToString(b)
}

func (e EntityID) Data() []byte {
	return e[1:]
}
func PrefixedB62EncodeDotOpt(dot bool, prefix byte, b []byte) (string, error) {
	b0, err := B62EncodeByte(prefix)
	if err != nil {
		return "", err
	}
	c0 := string(b0)
	rest := B62Encode(b)
	parts := []string{}
	if dot {
		parts = append(parts, ".")
	}
	parts = append(parts, c0, rest)
	return strings.Join(parts, ""), nil

}

func PrefixedB62Encode(prefix byte, b []byte) (string, error) {
	return PrefixedB62EncodeDotOpt(true, prefix, b)
}

func (e EntityID) StringErr() (string, error) {
	if len(e) == 0 {
		return ".", nil
	}
	return PrefixedB62Encode(byte(e.Type()), e.Data())
}

func (e EntityID) ToEntityIDString() (EntityIDString, error) {
	ret, err := e.StringErr()
	if err != nil {
		return "", err
	}
	return EntityIDString(ret), nil
}

func ImportIDFromString(s string) (EntityID, *ID16, error) {
	if len(s) < 4 {
		return nil, nil, DataError("entity ID too short")
	}
	var hasLeadingDot bool
	if s[0] == '.' {
		hasLeadingDot = true
		s = s[1:]
	}

	b0, err := B62DecodeByte(s[0])
	if err != nil {
		return nil, nil, err
	}
	if b0 < byte(ID16Type_MaxEntityType) {
		if !hasLeadingDot {
			return nil, nil, DataError("entity ID must start with '.'")
		}

		typ := EntityType(b0)
		if !typ.IsValid() {
			return nil, nil, DataError("invalid entity type")
		}
		dat, err := B62Decode(s[1:])
		if err != nil {
			return nil, nil, err
		}
		ret, err := typ.MakeEntityID(dat)
		if err != nil {
			return nil, nil, err
		}
		return ret, nil, nil
	}

	typ := ID16Type(b0)
	if !typ.IsValid() {
		return nil, nil, DataError("invalid ID16 type")
	}
	if typ.HasLeadingDot() && !hasLeadingDot {
		return nil, nil, DataError("ID16 type requires leading dot")
	}
	dat, err := B62Decode(s[1:])
	if err != nil {
		return nil, nil, err
	}
	ret, err := typ.MakeID16(dat)
	if err != nil {
		return nil, nil, err
	}
	return nil, ret, nil
}

func ImportEntityIDFromString(s string) (EntityID, error) {
	ret, id16, err := ImportIDFromString(s)
	if err != nil {
		return nil, err
	}
	if id16 != nil {
		return nil, DataError("got ID16 but wanted EntityID")
	}
	return ret, nil
}

type StringErrer interface {
	StringErr() (string, error)
}

func marsh(s StringErrer) ([]byte, error) {
	x, err := s.StringErr()
	if err != nil {
		return nil, err
	}
	return json.Marshal(x)
}

func unmarshalJson[T any](out *T, data []byte, toFn func(e EntityID) (T, error)) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	var id EntityID
	if s != "." {
		id, err = ImportEntityIDFromString(s)
		if err != nil {
			return err
		}
	}
	ret, err := toFn(id)
	if err != nil {
		return err
	}
	*out = ret
	return nil
}

func (u *UID) UnmarshalJSON(data []byte) error {
	return unmarshalJson(u, data, func(e EntityID) (UID, error) { return e.ToUID() })
}
func (h *HostID) UnmarshalJSON(data []byte) error {
	return unmarshalJson(h, data, func(e EntityID) (HostID, error) { return e.ToHostID() })
}
func (t *TeamID) UnmarshalJSON(data []byte) error {
	return unmarshalJson(t, data, func(e EntityID) (TeamID, error) { return e.ToTeamID() })
}
func (y *YubiID) UnmarshalJSON(data []byte) error {
	return unmarshalJson(y, data, func(e EntityID) (YubiID, error) { return e.ToYubiID() })
}
func (t *HostTLSCAID) UnmarshalJSON(data []byte) error {
	return unmarshalJson(t, data, func(e EntityID) (HostTLSCAID, error) { return e.ToHostTLSCAID() })
}

func (r *Role) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	rs := RoleString(s)
	ret, err := rs.Parse()
	if err != nil {
		return err
	}
	*r = *ret
	return nil
}

func (e *EntityID) UnmarshalJSON(data []byte) error {
	return unmarshalJson(e, data, func(e EntityID) (EntityID, error) { return e, nil })
}

func (c *Curve25519PublicKey) UnmarshalJSON(data []byte) error {
	return UnmarshalJsonFixed((*c)[:], data)
}

func (e *Ed25519PublicKey) UnmarshalJSON(data []byte) error {
	return UnmarshalJsonFixed((*e)[:], data)
}

func UnmarshalJsonFixed(out []byte, in []byte) error {
	var s string
	err := json.Unmarshal(in, &s)
	if err != nil {
		return err
	}
	raw, err := B62Decode(s)
	if err != nil {
		return err
	}
	if len(raw) != len(out) {
		return DataError("decode fixed key, data is wrong size")
	}
	copy(out[:], raw[:])
	return nil
}

func (u UID) StringErr() (string, error)                      { return u.EntityID().StringErr() }
func (h HostID) StringErr() (string, error)                   { return h.EntityID().StringErr() }
func (t TeamID) StringErr() (string, error)                   { return t.EntityID().StringErr() }
func (u UID) MarshalJSON() ([]byte, error)                    { return marsh(u) }
func (h HostID) MarshalJSON() ([]byte, error)                 { return marsh(h) }
func (t TeamID) MarshalJSON() ([]byte, error)                 { return marsh(t) }
func (y YubiID) StringErr() (string, error)                   { return y.EntityID().StringErr() }
func (y YubiID) EntityID() EntityID                           { return EntityID(y[:]) }
func (y YubiID) MarshalJSON() ([]byte, error)                 { return marsh(y) }
func (e EntityID) MarshalJSON() ([]byte, error)               { return marsh(e) }
func (e Ed25519PublicKey) String() string                     { return B62Encode(e[:]) }
func (e Ed25519PublicKey) MarshalJSON() ([]byte, error)       { return json.Marshal(e.String()) }
func (c Curve25519PublicKey) String() string                  { return B62Encode(c[:]) }
func (c Curve25519PublicKey) MarshalJSON() ([]byte, error)    { return json.Marshal(c.String()) }
func (r Role) MarshalJSON() ([]byte, error)                   { return marsh(r) }
func (t HostTLSCAID) StringErr() (string, error)              { return t.EntityID().StringErr() }
func (t HostTLSCAID) MarshalJSON() ([]byte, error)            { return marsh(t) }
func (t StdHash) String() string                              { return B62Encode(t[:]) }
func (t StdHash) MarshalJSON() ([]byte, error)                { return json.Marshal(t.String()) }
func (m MerkleTreeRFOutput) String() string                   { return B62Encode(m[:]) }
func (m MerkleTreeRFOutput) MarshalJSON() ([]byte, error)     { return json.Marshal(m.String()) }
func (t TreeLocationCommitment) String() string               { return B62Encode(t[:]) }
func (t TreeLocationCommitment) MarshalJSON() ([]byte, error) { return json.Marshal(t.String()) }
func (m MerkleRootHash) String() string                       { return B62Encode(m[:]) }
func (m MerkleRootHash) MarshalJSON() ([]byte, error)         { return json.Marshal(m.String()) }
func (l LinkHash) String() string                             { return B62Encode(l[:]) }
func (l LinkHash) MarshalJSON() ([]byte, error)               { return json.Marshal(l.String()) }
func (d DeviceID) StringErr() (string, error)                 { return d.EntityID().StringErr() }
func (d DeviceID) MarshalJSON() ([]byte, error)               { return marsh(d) }
func (p PartyID) StringErr() (string, error)                  { return p.EntityID().StringErr() }
func (p PartyID) MarshalJSON() ([]byte, error)                { return marsh(p) }

func (d *DeviceID) UnmarshalJSON(data []byte) error {
	return unmarshalJson(d, data, func(e EntityID) (DeviceID, error) { return e.ToDeviceID() })
}
func (p *PartyID) UnmarshalJSON(data []byte) error {
	return unmarshalJson(p, data, func(e EntityID) (PartyID, error) { return e.ToPartyID() })
}

func (t *StdHash) UnmarshalJSON(dat []byte) error            { return UnmarshalJsonFixed((*t)[:], dat) }
func (m *MerkleTreeRFOutput) UnmarshalJSON(dat []byte) error { return UnmarshalJsonFixed((*m)[:], dat) }
func (m *MerkleRootHash) UnmarshalJSON(dat []byte) error     { return UnmarshalJsonFixed((*m)[:], dat) }
func (l *LinkHash) UnmarshalJSON(dat []byte) error           { return UnmarshalJsonFixed((*l)[:], dat) }
func (t *TreeLocationCommitment) UnmarshalJSON(dat []byte) error {
	return UnmarshalJsonFixed((*t)[:], dat)
}

func (s StatusCode) MarshalJSON() ([]byte, error) {
	c, ok := StatusCodeRevMap[s]
	if !ok {
		return nil, DataError("invalid status code")
	}
	return json.Marshal(c)
}

func (s *StatusCode) UnmarshalJSON(b []byte) error {
	var c string
	err := json.Unmarshal(b, &c)
	if err != nil {
		return err
	}
	sc, ok := StatusCodeMap[c]
	if !ok {
		return DataError("invalid status code")
	}
	*s = sc
	return nil
}

var RoleSep = string("/")

func (r Role) StringErr() (string, error) {
	t, err := r.GetT()
	if err != nil {
		return "", err
	}
	s := RoleTypeRevMap[t]
	if t == RoleType_MEMBER {
		s += fmt.Sprintf("%s%d", RoleSep, r.Member())
	}
	return s, nil
}

func (r Role) ShortStringErr() (string, error) {
	t, err := r.GetT()
	if err != nil {
		return "", err
	}
	var s string
	switch t {
	case RoleType_MEMBER:
		s = fmt.Sprintf("m%s%d", RoleSep, r.Member())
	case RoleType_OWNER:
		s = "o"
	case RoleType_ADMIN:
		s = "a"
	case RoleType_NONE:
		s = "n"
	}
	return s, nil
}

var VizLevelMin = VizLevel(-32768)
var VizLevelKvMin = VizLevel(-0x4000)
var VizLevelMax = VizLevel(32767)

func NewKexHESP(s string) KexHESP {
	return KexHESP(strings.Fields(s))
}

func (k KexHESP) String() string {
	return strings.Join([]string(k), " ")
}

func (t *TreeLocation) ImportFromBytes(b []byte) error {
	if len(*t) != len(b) {
		return DataError("wrong length for tree location")
	}
	copy((*t)[:], b)
	return nil
}

func (r *RandomCommitmentKey) ImportFromBytes(b []byte) error {
	if len(*r) != len(b) {
		return DataError("wrong length for random commitment key")
	}
	copy((*r)[:], b)
	return nil
}

func (t *MerklePathTerminal) FoundKey() (bool, error) {
	b, err := t.GetLeaf()
	if err != nil {
		return false, err
	}
	return (b && t.True().FoundKey == nil), nil
}

func (s PublicServices) Select(t ServerType) *TCPAddr {
	switch t {
	case ServerType_Reg:
		return &s.Reg
	case ServerType_User:
		return &s.User
	case ServerType_MerkleQuery:
		return &s.MerkleQuery
	case ServerType_KVStore:
		return &s.KvStore
	default:
		return nil
	}
}

func (t ServerType) String() string {
	return ServerTypeRevMap[t]
}

func (t ServerType) NeedsAuth() bool {
	switch t {
	case ServerType_Reg, ServerType_MerkleQuery:
		return false
	case ServerType_User:
		return true
	default:
		return false
	}
}

func (c TreeLocationCommitment) IsZero() bool {
	return IsZero(c[:])
}

func (p MerklePathsCompressed) Select(i int) MerklePathCompressed {
	return MerklePathCompressed{
		Root:     p.Root,
		Path:     p.Paths[i].Path,
		Terminal: p.Paths[i].Terminal,
	}
}

func (l *LinkHash) DebugString() string {
	if l == nil {
		return "<nil>"
	}
	return B62Encode(l[:])
}

var OwnerRole = NewRoleDefault(RoleType_OWNER)
var AdminRole = NewRoleDefault(RoleType_ADMIN)
var DefaultRole = NewRoleWithMember(VizLevel(0))
var MinKVRole = NewRoleWithMember(VizLevelKvMin)
var DefaultMemberLoadFloor = DefaultRole

func (r *Role) WithDefaultMemberLoadFloor() Role {
	if r == nil {
		return DefaultMemberLoadFloor
	}
	return *r
}

func (d DeviceLabel) Eq(d2 DeviceLabel) bool {
	return d.Name == d2.Name && d.Serial == d2.Serial
}

func (h MerkleNodeHash) Hex() string {
	return hex.EncodeToString(h[:])
}

func (t Time) IsNowish() bool {
	now := Now()
	delta := Time(4 * 60 * 60 * 1000)
	if (t > now && t-now > delta) || (now > t && now-t > delta) {
		return false
	}
	return true
}

func (t Time) IsStale(nowGo time.Time) bool {
	now := ExportTime(nowGo)
	return now < t || now-t >= Time(24*60*60*1000)
}

func (y YubiCardInfo) KeyAt(i int) (*YubiKeyInfo, error) {
	if i < 0 || i >= len(y.Keys) {
		return nil, DataError("key index out of range")
	}
	return &YubiKeyInfo{
		Card: y.Id,
		Key:  y.Keys[i],
	}, nil
}

func (y YubiCardInfo) KeyAtSlot(s YubiSlot) (*YubiKeyInfo, error) {
	for _, k := range y.Keys {
		if s == k.Slot {
			return &YubiKeyInfo{
				Card: y.Id,
				Key:  k,
			}, nil
		}
	}
	return nil, DataError("no key found for slot")
}

type NameNormFn func(NameUtf8) (Name, error)

func (s HostString) Parse() (*ParsedHostname, error) {
	tmp := strings.TrimSpace(string(s))
	if len(tmp) == 0 {
		return nil, DataError("cannot parse a len=0 host")
	}

	if tmp[0] == '.' {
		eid, err := ImportEntityIDFromString(tmp)
		if err != nil {
			return nil, err
		}
		hid, err := eid.ToHostID()
		if err != nil {
			return nil, err
		}
		ret := NewParsedHostnameWithFalse(hid)
		return &ret, nil
	}

	addr, err := NormalizeTCPAddr(tmp)
	if err != nil {
		return nil, err
	}
	ret := NewParsedHostnameWithTrue(addr)
	return &ret, nil
}

func (h Hostname) IsIPAddr() bool {
	tmp := net.ParseIP(string(h))
	return tmp != nil
}

func (h Hostname) ToIPAddr() net.IP {
	return net.ParseIP(h.String())
}

func NormalizeTCPAddr(s string) (TCPAddr, error) {
	var zed TCPAddr

	s = strings.ToLower(strings.TrimSpace(s))

	var pp *Port
	var hRet Hostname
	h, p, err := net.SplitHostPort(s)

	if err == nil {
		i, err := strconv.Atoi(p)
		if err != nil {
			return zed, err
		}

		hRet = Hostname(h)
		pRet := Port(i)
		pp = &pRet
	} else {
		h = s
		hRet = Hostname(s)
	}

	ret := NewTCPAddrPortOpt(hRet, pp)

	if h == "localhost" {
		return ret, nil
	}

	if net.ParseIP(h) != nil {
		return ret, nil
	}

	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return zed, NormalizationError("no TLD in hostname")
	}

	if len(parts[len(parts)-1]) < 2 {
		return zed, NormalizationError("invalid TLD in hostname")
	}

	return ret, nil
}

var TeamStringPrefix = string("t:")

func (s TeamString) Parse() (*ParsedTeam, error) {

	tmp := strings.TrimSpace(string(s))
	if len(tmp) == 0 {
		return nil, DataError("cannot parse a len=0 User")
	}

	if tmp[0] == '.' {
		eid, err := ImportEntityIDFromString(tmp)
		if err != nil {
			return nil, err
		}
		tid, err := eid.ToTeamID()
		if err != nil {
			return nil, err
		}
		ret := NewParsedTeamWithFalse(tid)
		return &ret, nil
	}

	// Team prefix is allowed here, though not needed since it's clear from context.
	if len(tmp) > 2 && tmp[0:2] == TeamStringPrefix {
		tmp = tmp[2:]
	}

	tn := NameUtf8(tmp)
	ret := NewParsedTeamWithTrue(tn)
	return &ret, nil
}

func (s UserString) Parse() (*ParsedUser, error) {

	tmp := strings.TrimSpace(string(s))
	if len(tmp) == 0 {
		return nil, DataError("cannot parse a len=0 User")
	}

	if tmp[0] == '.' {
		eid, err := ImportEntityIDFromString(tmp)
		if err != nil {
			return nil, err
		}
		uid, err := eid.ToUID()
		if err != nil {
			return nil, err
		}
		ret := NewParsedUserWithFalse(uid)
		return &ret, nil
	}

	un := NameUtf8(tmp)
	ret := NewParsedUserWithTrue(un)
	return &ret, nil
}

func (s FQTeamString) Parse(f NameNormFn) (*FQTeamParsed, error) {
	tmp := strings.TrimSpace(string(s))
	if len(tmp) == 0 {
		return nil, DataError("empty FQTeam string can't be parsed")
	}
	parts := strings.Split(tmp, "@")
	if len(parts) > 2 {
		return nil, DataError("can have at most one @ in a FQUser string")
	}
	var ret FQTeamParsed
	if len(parts) == 2 {
		h, err := HostString(parts[1]).Parse()
		if err != nil {
			return nil, err
		}
		ret.Host = h
	}
	t, err := TeamString(parts[0]).Parse()
	if err != nil {
		return nil, err
	}
	ret.Team = *t
	return &ret, nil
}

func (s FQPartyString) Parse(f NameNormFn) (*FQPartyParsed, error) {
	tmp := strings.TrimSpace(string(s))
	if len(tmp) == 0 {
		return nil, DataError("empty FQParty string can't be parsed")
	}
	parts := strings.Split(tmp, "@")
	if len(parts) > 2 {
		return nil, DataError("can have at most one @ in a FQParty string")
	}
	var ret FQPartyParsed
	if len(parts) == 2 {
		h, err := HostString(parts[1]).Parse()
		if err != nil {
			return nil, err
		}
		ret.Host = h
	}
	p, err := PartyString(parts[0]).Parse()
	if err != nil {
		return nil, err
	}
	ret.Party = *p
	return &ret, nil

}

const TeamPrefix = "t:"

func (s PartyString) Parse() (*ParsedParty, error) {
	tmp := strings.TrimSpace(string(s))
	if len(tmp) == 0 {
		return nil, DataError("cannot parse a len=0 Party")
	}

	if tmp[0] == '.' {
		eid, err := ImportEntityIDFromString(tmp)
		if err != nil {
			return nil, err
		}
		pid, err := eid.ToPartyID()
		if err != nil {
			return nil, err
		}
		ret := NewParsedPartyWithFalse(pid)
		return &ret, nil
	}

	// Team prefix is allowed here, though not needed since it's clear from context.
	isTeam := false
	if len(tmp) > 2 && tmp[0:2] == TeamPrefix {
		tmp = tmp[2:]
		isTeam = true
	}

	tn := NameUtf8(tmp)
	ret := NewParsedPartyWithTrue(PartyName{
		IsTeam: isTeam,
		Name:   tn,
	})
	return &ret, nil
}

func ParseFQUser(s string) (*FQUser, error) {
	tmp := strings.TrimSpace(string(s))
	if len(tmp) == 0 {
		return nil, DataError("empty FQUser string can't be parsed")
	}
	parts := strings.Split(tmp, "@")
	if len(parts) != 2 {
		return nil, DataError("can have at most one @ in a FQUser string")
	}
	eid, err := ImportEntityIDFromString(parts[0])
	if err != nil {
		return nil, err
	}
	uid, err := eid.ToUID()
	if err != nil {
		return nil, err
	}
	eid, err = ImportEntityIDFromString(parts[1])
	if err != nil {
		return nil, err
	}
	hid, err := eid.ToHostID()
	if err != nil {
		return nil, err
	}
	return &FQUser{
		Uid:    uid,
		HostID: hid,
	}, nil
}

func (s FQUserString) Parse(f NameNormFn) (*FQUserParsed, error) {
	tmp := strings.TrimSpace(string(s))
	if len(tmp) == 0 {
		return nil, DataError("empty FQUser string can't be parsed")
	}
	parts := strings.Split(tmp, "@")
	if len(parts) > 2 {
		return nil, DataError("can have at most one @ in a FQUser string")
	}
	var ret FQUserParsed
	if len(parts) == 2 {
		h, err := HostString(parts[1]).Parse()
		if err != nil {
			return nil, err
		}
		ret.Host = h
	}
	u, err := UserString(parts[0]).Parse()
	if err != nil {
		return nil, err
	}
	ret.User = *u
	return &ret, nil
}

func (s RoleString) Parse() (*Role, error) {

	tmp := strings.TrimSpace(string(s))
	tmp = strings.ToLower(tmp)

	if len(tmp) == 0 {
		return nil, DataError("cannot parse a len=0 role")
	}

	var typ RoleType
	switch tmp {
	case "o", "owner":
		typ = RoleType_OWNER
	case "a", "admin":
		typ = RoleType_ADMIN
	case "n", "none", "∅":
		typ = RoleType_NONE
	default:
		mshort := "m" + RoleSep
		mlong := "member" + RoleSep

		if strings.HasPrefix(tmp, mshort) {
			typ = RoleType_MEMBER
			tmp = tmp[len(mshort):]
		} else if strings.HasPrefix(tmp, mlong) {
			typ = RoleType_MEMBER
			tmp = tmp[len(mlong):]
		} else {
			return nil, DataError("invalid RoleType prefix")
		}
	}
	var ret *Role
	if typ == RoleType_MEMBER {
		if len(tmp) < 1 {
			return nil, DataError("bad vizlevel for member")
		}
		i, err := strconv.Atoi(tmp)
		if err != nil {
			return nil, DataError("invalid vizlevel for member")
		}
		vl := VizLevel(i)
		if vl < VizLevelMin || vl > VizLevelMax {
			return nil, DataError("vizlevel out of range for member")
		}
		tmp := NewRoleWithMember(vl)
		ret = &tmp
	} else {
		tmp := NewRoleDefault(typ)
		ret = &tmp
	}
	return ret, nil
}

func (u Name) Eq(u2 Name) bool {
	return string(u) == string(u2)
}

func (h Hostname) Eq(h2 Hostname) bool {
	return string(h) == string(h2)
}

func (h Hostname) IsZero() bool {
	return len(h) == 0
}

func (u Name) IsZero() bool {
	return len(u) == 0
}

func (h Hostname) NormEq(h2 Hostname) bool {
	return h.Normalize().Eq(h2.Normalize())
}

func (h Hostname) Normalize() Hostname {
	return Hostname(strings.ToLower(string(h)))
}

func (h Hostname) String() string {
	return string(h)
}

func (i UserInfo) Eq(i2 UserInfo) bool {
	return i.Fqu.Eq(i2.Fqu) && i.Key.Eq(i2.Key)
}

func (u NameUtf8) IsZero() bool {
	return len(u) == 0
}

func (u NameBundle) EqUsername(u2 Name) bool {
	return string(u.Name) == string(u2) || string(u.NameUtf8) == string(u2)
}

func (u UserInfo) ToLocalUserIndex() LocalUserIndex {
	return LocalUserIndex{
		Host: u.Fqu.HostID,
		Rest: u.ToLocalUserIndexAtHost(),
	}
}

func (u UserInfo) ToLocalUserIndexAtHost() LocalUserIndexAtHost {
	return LocalUserIndexAtHost{
		Uid:   u.Fqu.Uid,
		Keyid: u.Key,
	}
}

func (d DeviceLabelAndName) NormEq(d2 DeviceLabelAndName) (bool, error) {
	return d.Label.NormEq(d2.Label)
}

func (d DeviceLabel) NormEq(d2 DeviceLabel) (bool, error) {
	err := d.AssertNormalized()
	if err != nil {
		return false, err
	}
	err = d2.AssertNormalized()
	if err != nil {
		return false, err
	}
	return d.Eq(d2), nil
}

func (d DeviceName) ExportToDB() string {
	return string(d)
}

func (n NormalizationVersion) ExportToDB() int {
	return int(n)
}

func (d DeviceNameNormalized) ExportToDB() string {
	return string(d)
}

func (f FQUserAndRole) StringErr() (string, error) {

	u, err := f.Fqu.Uid.StringErr()
	if err != nil {
		return "", err
	}
	h, err := f.Fqu.HostID.StringErr()
	if err != nil {
		return "", err
	}
	r, err := f.Role.ShortStringErr()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s%s@%s", u, RoleSep, r, h), nil
}

func (f FQUser) StringErr() (string, error) {
	u, err := f.Uid.StringErr()
	if err != nil {
		return "", err
	}
	h, err := f.HostID.StringErr()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s@%s", u, h), nil

}

func (s FQUserAndRoleString) Parse() (*FQUserAndRole, error) {
	tmp := strings.TrimSpace(string(s))
	p := strings.Split(tmp, "@")
	if len(p) != 2 {
		return nil, DataError("FQUserAndRole: need 2 parts delimited by '@'")
	}
	uParts := strings.Split(p[0], RoleSep)
	if !(len(uParts) == 2 || len(uParts) == 3) {
		return nil, DataError("FQUserAndRole: need 1 or 2 parts before '@'")
	}
	uEid, err := ImportEntityIDFromString(uParts[0])
	if err != nil {
		return nil, err
	}
	uid, err := uEid.ToUID()
	if err != nil {
		return nil, err
	}
	hEid, err := ImportEntityIDFromString(p[1])
	if err != nil {
		return nil, err
	}
	hid, err := hEid.ToHostID()
	if err != nil {
		return nil, err
	}
	rs := RoleString(strings.Join(uParts[1:], RoleSep))
	role, err := rs.Parse()
	if err != nil {
		return nil, err
	}
	return &FQUserAndRole{
		Fqu: FQUser{
			Uid:    uid,
			HostID: hid,
		},
		Role: *role,
	}, nil
}

func (f FQUserAndRole) Eq(f2 FQUserAndRole) (bool, error) {
	eq, err := f.Role.Eq(f2.Role)
	if err != nil {
		return false, err
	}
	if !eq {
		return false, nil
	}
	return f.Fqu.Eq(f2.Fqu), nil
}

func (p Passphrase) IsZero() bool {
	return len(p) == 0
}

func (t ChainType) IsSubchain() bool {
	switch t {
	case ChainType_UserSettings, ChainType_TeamMembership:
		return true
	default:
		return false
	}
}

func (t ChainType) Uint16() uint16 {
	return uint16(t)
}

func (u UID) IsGuest() bool {
	if u[0] != byte(EntityType_User) {
		return false
	}
	for _, c := range u[1:] {
		if c != 0xff {
			return false
		}
	}
	return true
}

func NewGestUID() UID {
	var ret UID
	ret[0] = byte(EntityType_User)
	for i := 1; i < len(ret); i++ {
		ret[i] = 0xff
	}
	return ret
}

func (k SharedKey) ToTeamMemberKeys(tir *RationalRange) TeamMemberKeys {
	return TeamMemberKeys{
		VerifyKey: k.VerifyKey,
		HepkFp:    k.HepkFp,
		Gen:       k.Gen,
		Tir:       tir,
	}
}

func (k TeamMemberKeys) ToSharedKey(r Role) SharedKey {
	return SharedKey{
		VerifyKey: k.VerifyKey,
		HepkFp:    k.HepkFp,
		Gen:       k.Gen,
		Role:      r,
	}
}

func (e FQEntityFixed) Eq(e2 FQEntityFixed) bool {
	return hmac.Equal(e.Entity[:], e2.Entity[:]) && e.Host.Eq(e2.Host)
}

func (e FQEntityFixed) Cmp(g FQEntityFixed) int {
	x := bytes.Compare(e.Host[:], g.Host[:])
	if x != 0 {
		return x
	}
	return bytes.Compare(e.Entity[:], g.Entity[:])
}

func (t EntityType) RollingType() EntityType {
	switch t {
	case EntityType_User:
		return EntityType_PUKVerify
	case EntityType_Team:
		return EntityType_PTKVerify
	default:
		return t
	}
}

// Will match a UID against a PUK, a PUK against a PUK, or a UID against a UID.
// And similarly for Teams versus PTKs. We might revisit this.
func (e EntityID) RollingEq(e2 EntityID) bool {
	return len(e) == len(e2) && len(e) > 2 &&
		e.Type().RollingType() == e2.Type().RollingType() &&
		hmac.Equal(e[1:], e2[1:])
}

func (e EntityID) ToRollingEntityID() (EntityID, error) {
	if len(e) < 2 {
		return nil, DataError("entity ID too short")
	}
	if e.Type().RollingType() == e.Type() {
		return e, nil
	}
	return e.Type().RollingType().MakeEntityID(e.Data())
}

func (t EntityType) PersistentType() EntityType {
	switch t {
	case EntityType_PUKVerify:
		return EntityType_User
	case EntityType_PTKVerify:
		return EntityType_Team
	default:
		return t
	}
}

func (e EntityID) Persistent() (EntityID, error) {
	if len(e) < 2 {
		return nil, DataError("entity ID too short")
	}
	return e.Type().PersistentType().MakeEntityID(e.Data())
}

func (f FQEntityFixed) Unfix() FQEntity {
	return FQEntity{
		Entity: f.Entity.Unfix(),
		Host:   f.Host,
	}
}

func (t TeamID) ExportToDB() []byte {
	return t[:]
}

func (r RoleType) IsAdminOrAbove() bool {
	return r.Cmp(RoleType_ADMIN) >= 0
}

func (r Role) IsAdminOrAbove() (bool, error) {
	typ, err := r.GetT()
	if err != nil {
		return false, err
	}
	return typ.IsAdminOrAbove(), nil
}

func (r Role) IsNone() (bool, error) {
	typ, err := r.GetT()
	if err != nil {
		return false, err
	}
	return typ == RoleType_NONE, nil
}

func (r Role) IsAtOrAbove(r2 Role) (bool, error) {
	typ, err := r.GetT()
	if err != nil {
		return false, err
	}
	typ2, err := r2.GetT()
	if err != nil {
		return false, err
	}
	tmp := typ.Cmp(typ2)
	switch {
	case tmp < 0:
		return false, nil
	case tmp > 0:
		return true, nil
	case tmp == 0 && typ == RoleType_MEMBER:
		return r.Member() >= r2.Member(), nil
	case tmp == 0 && typ != RoleType_MEMBER:
		return true, nil
	default:
		return false, nil
	}
}

func (r Role) AssertAdminOrAbove(e error) error {
	typ, err := r.GetT()
	if err != nil {
		return err
	}
	if !typ.IsAdminOrAbove() {
		return e
	}
	return nil
}

func (r Role) AssertBelowAdmin(e error) error {
	typ, err := r.GetT()
	if err != nil {
		return err
	}
	if typ.IsAdminOrAbove() {
		return e
	}
	return nil
}

func (h HostID) FastEq(h2 HostID) bool {
	return len(h) == len(h2) && len(h) > 2 && bytes.Equal(h[:], h2[:])
}

func (p PartyID) EntityID() EntityID      { return EntityID(p) }
func (p PartyID) TeamID() (TeamID, error) { return p.EntityID().ToTeamID() }
func (p PartyID) UID() (UID, error)       { return p.EntityID().ToUID() }
func (p PartyID) Check() error {
	if len(p) != 33 {
		return DataError("bad principal id")
	}
	switch p.EntityID().Type() {
	case EntityType_User:
		return nil
	case EntityType_Team:
		return nil
	default:
		return DataError("bad principal id")
	}
}

func (p PartyID) IsUser() bool { return len(p) > 2 && p.EntityID().Type() == EntityType_User }
func (p PartyID) IsTeam() bool { return len(p) > 2 && p.EntityID().Type() == EntityType_Team }

func (p PartyID) Select() (*UID, *TeamID, error) {
	if len(p) != 33 {
		return nil, nil, DataError("bad principal id")
	}
	switch p.EntityID().Type() {
	case EntityType_User:
		uid, err := p.UID()
		if err != nil {
			return nil, nil, err
		}
		return &uid, nil, nil
	case EntityType_Team:
		tid, err := p.TeamID()
		if err != nil {
			return nil, nil, err
		}
		return nil, &tid, nil
	default:
		return nil, nil, DataError("bad principal id")
	}
}

func (p PartyID) ExportToDB() []byte { return p[:] }

func (u UID) ToPartyID() PartyID { return PartyID(u[:]) }

func (f FQUser) FQParty() FQParty {
	return FQParty{
		Party: f.Uid.ToPartyID(),
		Host:  f.HostID,
	}
}

func (t *TeamID) ImportFromDB(d []byte) error {
	eid, err := ImportEntityIDFromBytes(d)
	if err != nil {
		return err
	}
	tid, err := eid.ToTeamID()
	if err != nil {
		return err
	}
	*t = tid
	return nil
}

func (t PTKVerifyID) EntityID() EntityID { return EntityID(t[:]) }

func (h TeamCertHash) ExportToDB() []byte { return h[:] }

func (t FQTeam) FQParty() FQParty {
	return FQParty{
		Party: t.Team.ToPartyID(),
		Host:  t.Host,
	}
}

func (t TeamID) ToPartyID() PartyID {
	return PartyID(t[:])
}

func (p FQParty) FQUser() *FQUser {
	uid, _, _ := p.Party.Select()
	if uid != nil {
		return &FQUser{
			Uid:    *uid,
			HostID: p.Host,
		}
	}
	return nil
}

func (p FQParty) FQTeam() *FQTeam {
	_, tid, _ := p.Party.Select()
	if tid != nil {
		return &FQTeam{
			Team: *tid,
			Host: p.Host,
		}
	}
	return nil
}

func (t TeamID) Eq(t2 TeamID) bool {
	return len(t) == len(t2) && len(t) > 2 && hmac.Equal(t[:], t2[:])
}

func (t TCPAddr) IsZero() bool {
	return t == ""
}

func (h *HMACKeyID) ImportFromDB(b []byte) error {
	if len(b) != len(*h) {
		return DataError("bad hmac key id")
	}
	copy((*h)[:], b)
	return nil
}

func (h *HMACKey) ImportFromDB(b []byte) error {
	if len(b) != len(*h) {
		return DataError("bad hmac key")
	}
	copy((*h)[:], b)
	return nil
}

func (e EntityID) ToPartyID() (PartyID, error) {
	if len(e) < 2 {
		return nil, DataError("zero party")
	}
	switch e.Type() {
	case EntityType_User, EntityType_Team:
		return PartyID(e), nil
	default:
		return nil, DataError("bad party")
	}
}

func (p *PartyID) ImportFromDB(b []byte) error {
	eid, err := ImportEntityIDFromBytes(b)
	if err != nil {
		return err
	}
	pid, err := eid.ToPartyID()
	if err != nil {
		return err
	}
	*p = pid
	return nil
}

func (p PartyID) Eq(p2 PartyID) bool {
	return len(p) > 0 && len(p2) > 0 && len(p) == len(p2) && hmac.Equal(p[:], p2[:])
}

func (p FQParty) Eq(p2 FQParty) bool {
	return p.Party.Eq(p2.Party) && p.Host.Eq(p2.Host)
}

func (t FQTeam) Eq(t2 FQTeam) bool {
	return t.Team.Eq(t2.Team) && t.Host.Eq(t2.Host)
}

func (t FQTeam) DbKey() (DbKey, error) {
	ret := []byte{}
	ret = append(ret, t.Team[:]...)
	ret = append(ret, t.Host[:]...)
	return ret, nil
}

func (t ChainType) IsPartyType() bool {
	switch t {
	case ChainType_User, ChainType_Team:
		return true
	default:
		return false
	}
}

func (p FQParty) FQEntity() FQEntity {
	return FQEntity{
		Entity: p.Party.EntityID(),
		Host:   p.Host,
	}
}

func (t SharedKeyBoxTarget) InHostScope(h HostID) SharedKeyBoxTarget {
	if t.Host == nil {
		t.Host = &h
	}
	return t
}

func (t SharedKeyBoxTarget) Fixed(h HostID) (*FQEntityFixed, error) {
	return (FQEntityInHostScope{Entity: t.Eid, Host: t.Host}).Fixed(h)
}

func (r Role) SimpleEq(r2 Role) bool {
	if r.T != r2.T {
		return false
	}
	if r.T == RoleType_MEMBER && r.Member() != r2.Member() {
		return false
	}
	return true
}

func (r Role) SimpleCmp(r2 Role) int {
	if r.T != r2.T {
		return int(r.T) - int(r2.T)
	}
	if r.T == RoleType_MEMBER {
		return int(r.Member()) - int(r2.Member())
	}
	return 0
}

func (u UID) ToOwnerKeyOwner() KeyOwner {
	return KeyOwner{
		Party:   u.ToPartyID(),
		SrcRole: OwnerRole,
	}
}

func (e EntityID) Cmp(e2 EntityID) int {
	return bytes.Compare(e[:], e2[:])
}

func (f FQTeam) Cmp(f2 FQTeam) int {
	x := bytes.Compare(f.Host[:], f2.Host[:])
	if x != 0 {
		return x
	}
	return bytes.Compare(f.Team[:], f2.Team[:])
}

func (k KeyCommitment) ExportToDB() []byte {
	return k[:]
}

func (e FQEntity) FQParty() (*FQParty, error) {
	party, err := e.Entity.ToPartyID()
	if err != nil {
		return nil, err
	}
	return &FQParty{Party: party, Host: e.Host}, nil

}

func (t FQTeam) ToFQTeamIDOrName() FQTeamIDOrName {
	return FQTeamIDOrName{
		Host:     t.Host,
		IdOrName: NewTeamIDOrNameWithTrue(t.Team),
	}
}

func (t TeamID) IsZero() bool {
	return IsZero(t[:])
}

func (c KeyCommitment) Eq(c2 KeyCommitment) bool {
	return hmac.Equal(c[:], c2[:])
}

func (t FQTeamIDOrName) Eq(t2 FQTeamIDOrName) (bool, error) {
	if !t.Host.Eq(t2.Host) {
		return false, nil
	}
	return t.IdOrName.Eq(t2.IdOrName)
}

func (t TeamIDOrName) Eq(t2 TeamIDOrName) (bool, error) {
	i1, err := t.GetId()
	if err != nil {
		return false, err
	}
	i2, err := t2.GetId()
	if err != nil {
		return false, err
	}
	if i1 != i2 {
		return false, nil
	}
	if i1 {
		return t.True().Eq(t2.True()), nil
	}
	return t.False().Eq(t2.False()), nil
}

func shortString(b []byte) string      { return hex.EncodeToString(b[:3]) }
func (h HostID) ShortString() string   { return shortString(h[:]) }
func (e EntityID) ShortString() string { return shortString(e[:]) }
func (t TeamID) ShortString() string   { return shortString(t[:]) }
func shortStringAt(a, b []byte) string {
	return fmt.Sprintf("{%s}@{%s}", shortString(a), shortString(b))
}

func (e FQEntity) ShortString() string { return shortStringAt(e.Entity[:], e.Host[:]) }
func (f FQTeam) ShortString() string   { return shortStringAt(f.Team[:], f.Host[:]) }

func (d DbKey) ExportToDB() []byte {
	return d[:]
}

func (t ParsedTeam) StringErr() (string, error) {
	isName, err := t.GetS()
	if err != nil {
		return "", err
	}
	if isName {
		return string(t.True()), nil
	}
	return t.False().StringErr()
}

func (t ParsedHostname) StringErr() (string, error) {
	isName, err := t.GetS()
	if err != nil {
		return "", err
	}
	if isName {
		return string(t.True()), nil
	}
	return t.False().StringErr()
}

func (u FQUser) ToFQParty() FQParty {
	return FQParty{
		Party: u.FQParty().Party,
		Host:  u.HostID,
	}
}

func (e1 ECDSACompressedPublicKey) Eq(e2 ECDSACompressedPublicKey) bool {
	return hmac.Equal(e1[:], e2[:])
}

func (d1 DHPublicKey) Eq(d2 DHPublicKey) (bool, error) {
	t1, err := d1.GetT()
	if err != nil {
		return false, err
	}
	t2, err := d2.GetT()
	if err != nil {
		return false, err
	}
	if t1 != t2 {
		return false, nil
	}
	switch t1 {
	case DHType_Curve25519:
		c1 := d1.Curve25519()
		c2 := d2.Curve25519()
		return c1.Eq(&c2), nil
	case DHType_P256:
		p1 := d1.P256()
		p2 := d2.P256()
		return p1.Eq(p2), nil
	default:
		return false, DataError("bad dh public key type")
	}
}

func (m *Member) AddRemovalKeyCommitment(k *KeyCommitment) error {
	typ, err := m.Keys.GetT()
	if err != nil {
		return err
	}
	if typ != MemberKeysType_Team {
		return DataError("not a team member key set")
	}
	tmk := m.Keys.Team()
	tmk.Trkc = k
	m.Keys = NewMemberKeysWithTeam(tmk)
	return nil
}

func (d *DirID) ExportToDB() []byte {
	return d[:]
}

func (v KVVersion) IsZero() bool {
	return v == 0
}

func (v KVVersion) IsFirst() bool {
	return int(v) == 1
}

func (d *DirentID) ExportToDB() []byte {
	return d[:]
}

func (n *NaclNonce) ImportFromDB(b []byte) error {
	if len(b) != len(*n) {
		return DataError("bad nacl nonce")
	}
	copy((*n)[:], b)
	return nil
}

func (n *KVNodeID) ImportFromDB(b []byte) error {
	if len(b) == 1 && b[0] == byte(KVNodeType_None) {
		// "Tombstoned" file for a deleted file, which we abbreviate
		// with "0x00" rather than "0x00"x17
		var ret KVNodeID
		// This is a noop, but if we ever change _None to be != 0,
		// it will do something interesting
		ret[0] = byte(KVNodeType_None)
		*n = ret
		return nil
	}
	if len(b) != len(*n) {
		return DataError("bad kv node id")
	}
	copy((*n)[:], b)
	return nil
}

func (h *HMAC) ImportFromDB(b []byte) error {
	if len(b) != len(*h) {
		return DataError("bad hmac")
	}
	copy((*h)[:], b)
	return nil
}

func (n *NaclCiphertext) ImportFromDB(b []byte) error {
	if len(b) < 8 {
		return DataError("bad nacl ciphertext")
	}
	*n = b
	return nil
}

func (d1 DirID) FastEq(d2 DirID) bool {
	return bytes.Equal(d1[:], d2[:])
}

func (i *KVNodeID) ExportToDB() []byte {
	if i.IsNone() {
		return []byte{byte(KVNodeType_None)}
	}
	return i[:]
}

func (n *NaclNonce) ExportToDB() []byte {
	return n[:]
}

func (m *HMAC) ExportToDB() []byte {
	return m[:]
}

func (d *DirID) ImportFromDB(b []byte) error {
	if len(b) != len(*d) {
		return DataError("bad dir id")
	}
	copy((*d)[:], b)
	return nil
}

func (n *KVNodeID) IsFileOrSmallFile() bool {
	typ, err := n.Type()
	if err != nil {
		return false
	}
	switch typ {
	case KVNodeType_File, KVNodeType_SmallFile:
		return true
	default:
		return false
	}
}

func (n *KVNodeID) IsDir() bool {
	typ, err := n.Type()
	if err != nil {
		return false
	}
	return typ == KVNodeType_Dir
}

func (n *KVNodeID) Type() (KVNodeType, error) {
	typ := KVNodeType((*n)[0])
	switch typ {
	case KVNodeType_Dir, KVNodeType_File, KVNodeType_SmallFile, KVNodeType_Symlink:
		return typ, nil
	case KVNodeType_None:
		// Tombstone
		return KVNodeType_None, nil
	default:
		return KVNodeType_None, DataError("bad kv node id")
	}
}

func (n *KVNodeID) IsNone() bool {
	return len(*n) > 0 && (*n)[0] == byte(KVNodeType_None)
}

func (n *KVNodeID) ToDirID() (*DirID, error) {
	typ, err := n.Type()
	if err != nil {
		return nil, err
	}
	if typ != KVNodeType_Dir {
		return nil, DataError("not a dir")
	}
	var ret DirID
	copy(ret[:], (*n)[1:])
	return &ret, nil
}

func (f *KVNodeID) ToFileID() (*FileID, error) {
	typ, err := f.Type()
	if err != nil {
		return nil, err
	}
	if typ != KVNodeType_File {
		return nil, DataError("not a file")
	}
	var ret FileID
	copy(ret[:], (*f)[1:])
	return &ret, nil
}

func (n *KVNodeID) Sel() (*DirID, *FileID, *SmallFileID, error) {
	typ := KVNodeType((*n)[0])
	switch typ {
	case KVNodeType_Dir:
		var ret DirID
		copy(ret[:], (*n)[1:])
		return &ret, nil, nil, nil
	case KVNodeType_File:
		var ret FileID
		copy(ret[:], (*n)[1:])
		return nil, &ret, nil, nil
	case KVNodeType_SmallFile:
		var ret SmallFileID
		copy(ret[:], (*n)[1:])
		return nil, nil, &ret, nil
	default:
		return nil, nil, nil, DataError("bad kv node id")
	}
}

func (f *FileID) ExportToDB() []byte {
	return f[:]
}
func (s *SmallFileID) ExportToDB() []byte {
	return s[:]
}

func (b *NaclSecretBox) ImportFromDB(nonce []byte, box []byte) error {
	if len(nonce) != len(b.Nonce) {
		return DataError("bad nacl nonce")
	}
	if len(box) < 8 {
		return DataError("bad nacl ciphertext")
	}
	copy(b.Nonce[:], nonce)
	b.Ciphertext = box
	return nil
}

func (n *KVNameNonce) ExportToDB() []byte {
	return n[:]
}

func (i *DirentID) ImportFromDB(b []byte) error {
	if len(b) != len(*i) {
		return DataError("bad dirent id")
	}
	copy((*i)[:], b)
	return nil
}

func (u *KVUploadID) ExportToDB() []byte {
	return u[:]
}

func (f *FileID) ImportFromDB(b []byte) error {
	if len(b) != len(*f) {
		return DataError("bad file id")
	}
	copy((*f)[:], b)
	return nil
}

type KVDirStatusString string

const (
	KVDirStatusStringActive     KVDirStatusString = "active"
	KVDirStatusStringDead       KVDirStatusString = "dead"
	KVDirStatusStringEncrypting KVDirStatusString = "encrypting"
)

func (k *KVDirStatus) ImportFromDB(s string) error {
	switch KVDirStatusString(s) {
	case KVDirStatusStringActive:
		*k = KVDirStatus_Active
	case KVDirStatusStringDead:
		*k = KVDirStatus_Dead
	case KVDirStatusStringEncrypting:
		*k = KVDirStatus_Encrypting
	default:
		return DataError("bad kv dir status")
	}
	return nil
}

func (d *DirID) KVNodeID() *KVNodeID {
	var ret KVNodeID
	ret[0] = byte(KVNodeType_Dir)
	copy(ret[1:], d[:])
	return &ret
}

func (d *DirID) ToNonce() *NaclNonce {
	return (*NaclNonce)(d)
}

func (d *KVDirent) Type() (KVNodeType, error) {
	return d.Value.Type()
}

func (d *DirKeySeed) ToSecretSeed32() *SecretSeed32 {
	return (*SecretSeed32)(d)
}

func (d *KVDirent) ToBindingPayload() *KVDirentBindingPayload {
	return &KVDirentBindingPayload{
		ParentDir:  d.ParentDir,
		Id:         d.Id,
		Value:      d.Value,
		Version:    d.Version,
		DirVersion: d.DirVersion,
		WriteRole:  d.WriteRole,
		NameMac:    d.NameMac,
		NameBox:    d.NameBox,
	}
}

func (m *HMAC) IsZero() bool {
	return IsZero(m[:])
}

func (r *KVRoot) ToBindingPayload(p FQParty) *KVRootBindingPayload {
	return &KVRootBindingPayload{
		Party: p,
		Root:  r.Root,
		Vers:  r.Vers,
		Rg:    r.Rg,
	}
}

func (r RolePairOpt) FillDefaults(isUser bool) RolePair {
	defRole := DefaultRole
	if isUser {
		defRole = OwnerRole
	}
	var ret RolePair

	switch {
	case r.Read == nil && r.Write == nil:
		ret = RolePair{
			Read:  defRole,
			Write: defRole,
		}
	case r.Read != nil && r.Write == nil:
		ret = RolePair{
			Read:  *r.Read,
			Write: *r.Read,
		}
	case r.Read == nil && r.Write != nil:
		ret = RolePair{
			Read:  *r.Write,
			Write: *r.Write,
		}
	default:
		ret = RolePair{
			Read:  *r.Read,
			Write: *r.Write,
		}
	}
	return ret
}

func (p ShortPartyID) ExportToDB() []byte {
	return p[:]
}

func (p PartyID) Shorten() ShortPartyID {
	var ret ShortPartyID
	copy(ret[:], p[:])
	return ret
}

func (n *KVNodeID) NaclNonce() *NaclNonce {
	return (*NaclNonce)(n[1:])
}

func (s *SymlinkID) NaclNonce() *NaclNonce {
	return (*NaclNonce)(s)
}

func (s *SmallFileID) NaclNonce() *NaclNonce {
	return (*NaclNonce)(s)
}

func (n *KVNodeID) ToSymlinkID() (*SymlinkID, error) {
	typ, err := n.Type()
	if err != nil {
		return nil, err
	}
	if typ != KVNodeType_Symlink {
		return nil, DataError("not a symlink")
	}
	var ret SymlinkID
	copy(ret[:], (*n)[1:])
	return &ret, nil
}

func (n *KVNodeID) MaybeSmallFileID() (*SmallFileID, error) {
	typ, err := n.Type()
	if err != nil {
		return nil, err
	}
	if typ != KVNodeType_SmallFile {
		return nil, nil
	}
	var ret SmallFileID
	copy(ret[:], (*n)[1:])
	return &ret, nil

}

func (n *KVNodeID) ToSmallFileID() (*SmallFileID, error) {
	ret, err := n.MaybeSmallFileID()
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return nil, DataError("not a small file")
	}
	return ret, nil
}

func (c NaclCiphertext) ExportToDB() []byte {
	return c
}

func (c Chunk) ExportToDB() []byte {
	return c
}

func (s *SmallFileID) KVNodeID() KVNodeID {
	var ret KVNodeID
	ret[0] = byte(KVNodeType_SmallFile)
	copy(ret[1:], s[:])
	return ret
}

func (f FileID) Eq(f2 FileID) bool {
	return bytes.Equal(f[:], f2[:])
}

func (f *FileID) KVNodeID() KVNodeID {
	var ret KVNodeID
	ret[0] = byte(KVNodeType_File)
	copy(ret[1:], f[:])
	return ret
}

func (k KVNodeID) StringErr() (string, error) {
	if len(k) < 2 {
		return "", DataError("bad kv node id")
	}
	b, err := B62EncodeByte(k[0])
	if err != nil {
		return "", err
	}
	s := B62Encode(k[1:])
	return (string(b) + s), nil
}

func (k KVNodeID) IsTombstone() bool {
	return len(k) < 1 || k[0] == byte(KVNodeType_None)
}

func (k KVRoot) GetVersion() KVVersion {
	return k.Vers
}

func (k KVDirPair) GetVersion() KVVersion {
	if k.Encrypting != nil {
		return k.Encrypting.Version
	}
	return k.Active.Version
}

func (k KVDirent) GetVersion() KVVersion {
	return k.Version
}

func (s SmallFileBox) GetVersion() KVVersion {
	return 0
}

func (m LargeFileMetadata) GetVersion() KVVersion {
	return m.Vers
}

func (r GitRefBoxedSet) GetVersion() KVVersion {
	return 0
}

func (t EntityType) IsECDSA() bool {
	switch t {
	case EntityType_Yubi:
		return true
	default:
		return false
	}
}

func (i EntityID) ECDSACompressedPublicKey() (ECDSACompressedPublicKey, error) {
	switch i.Type() {
	case EntityType_Yubi:
		return YubiID(i).CompressedPublicKey(), nil
	default:
		return nil, DataError("not an ecdsa entity")
	}
}

func (f *HEPKFingerprint) ImportFromDB(b []byte) error {
	if len(b) != len(*f) {
		return DataError("bad HEPK fingerprint; wrong length")
	}
	copy((*f)[:], b)
	return nil
}

func (f *HEPKFingerprint) Eq(f2 *HEPKFingerprint) bool {
	return hmac.Equal(f[:], f2[:])
}

func (f *HEPKFingerprint) ExportToDB() []byte {
	return f[:]
}

func (h HEPK) ToSet() HEPKSet {
	return HEPKSet{V: []HEPK{h}}
}

func (s *HEPKSet) Push(h HEPK) {
	s.V = append(s.V, h)
}

func (s *SecretBoxKey) ToDHSharedKey() DHSharedKey {
	return DHSharedKey(s[:])
}

func (p *YubiPQKeyID) Eq(p2 *YubiPQKeyID) bool {
	return hmac.Equal(p[:], p2[:])
}

func (p *YubiPQKeyID) ExportToDB() []byte {
	return p[:]
}

func (p *YubiPQKeyID) IsZero() bool {
	return IsZero(p[:])
}

func (y *YubiCardInfo) SelectSlot(yi YubiIndex) (YubiSlot, error) {
	var res YubiSlot
	typ, err := yi.GetT()
	if err != nil {
		return res, err
	}
	switch typ {
	case YubiIndexType_Reuse:
		i := yi.Reuse()
		if int(i) >= len(y.Keys) {
			return res, DataError("slot reuse Index out of range")
		}
		selected := y.Keys[i]
		res = selected.Slot
		y.Selected = append(y.Selected, selected)
		y.Keys = append(y.Keys[:i], y.Keys[i+1:]...)
	case YubiIndexType_Empty:
		i := yi.Empty()
		if int(i) >= len(y.EmptySlots) {
			return res, DataError("slot empty Index out of range")
		}
		selected := y.EmptySlots[i]
		res = selected
		y.Selected = append(y.Selected, YubiSlotAndKeyID{Slot: selected})
		y.EmptySlots = append(y.EmptySlots[:i], y.EmptySlots[i+1:]...)
	default:
		// no select -> noop
	}
	return res, nil
}

func (p *YubiPQKeyID) ImportFromDB(b []byte) error {
	if len(b) != len(*p) {
		return DataError("bad YubiPQKey; wrong length")
	}
	copy((*p)[:], b)
	return nil
}

func (p HEPKFingerprint) String() string                  { return B62Encode(p[:]) }
func (p HEPKFingerprint) MarshalJSON() ([]byte, error)    { return json.Marshal(p.String()) }
func (p YubiPQKeyID) String() string                      { return B62Encode(p[:]) }
func (p YubiPQKeyID) MarshalJSON() ([]byte, error)        { return json.Marshal(p.String()) }
func (p *HEPKFingerprint) UnmarshalJSON(dat []byte) error { return UnmarshalJsonFixed((*p)[:], dat) }
func (p *YubiPQKeyID) UnmarshalJSON(dat []byte) error     { return UnmarshalJsonFixed((*p)[:], dat) }

func (e EntityType) KeyGenus() (KeyGenus, error) {
	var kg KeyGenus
	switch e {
	case EntityType_Device:
		kg = KeyGenus_Device
	case EntityType_Yubi:
		kg = KeyGenus_Yubi
	case EntityType_BackupKey:
		kg = KeyGenus_Backup
	default:
		return kg, DataError("bad entity type")
	}
	return kg, nil

}

func (u UserContext) ToUserInfoAndStatus() UserInfoAndStatus {
	return UserInfoAndStatus{
		Info:          u.Info,
		LockStatus:    u.LockStatus,
		NetworkStatus: u.NetworkStatus,
	}
}

func (d DeviceID) EntityID() EntityID {
	return EntityID(d[:])
}

func (t HostTLSCA) PemEncode() (string, error) {
	ret := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: t.Cert,
	})
	if ret == nil {
		return "", DataError("PEM encoding failed")
	}
	return string(ret), nil
}

func (r Rational) Validate() error {
	isZero := len(r.Base) == 0 && r.Exp == 0
	if r.Infinity && !isZero {
		return DataError("bad rational")
	}
	return nil
}

func (t FQTeam) StringErr() (string, error) {
	hostStr, err := t.Host.StringErr()
	if err != nil {
		return "", err
	}
	teamStr, err := t.Team.StringErr()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s@%s", teamStr, hostStr), nil
}

const GitProtoPrefix = "foks://"

// Parse a git url string into components. The general form is:
// foks://host/party/repo
// But note that repo can contain slashes. Also, party can be either
// a team or a user, either via name or via id.
func (g GitURLString) Parse() (*GitURL, error) {

	if len(g) == 0 {
		return nil, DataError("empty git url")
	}

	ok := strings.HasPrefix(string(g), GitProtoPrefix)
	if !ok {
		return nil, DataError("bad git url; doesn't start with foks://")
	}
	rest := string(g[len(GitProtoPrefix):])
	parts := strings.Split(rest, "/")
	if len(parts) < 3 {
		return nil, DataError("bad git url; not enough parts")
	}

	hostStr := HostString(parts[0])
	host, err := hostStr.Parse()
	if err != nil {
		return nil, err
	}
	parts = parts[1:]
	partyStr := PartyString(parts[0])
	party, err := partyStr.Parse()
	if err != nil {
		return nil, err
	}

	parts = parts[1:]
	stripEmpties := func(p []string) []string {
		ret := []string{}
		for _, s := range p {
			if len(s) > 0 {
				ret = append(ret, s)
			}
		}
		return ret
	}
	parts = stripEmpties(parts)
	repoName := strings.ToLower(strings.Join(parts, "/"))
	repoName, _ = strings.CutSuffix(repoName, ".git")
	repo := GitRepo(repoName)
	return &GitURL{
		Proto: GitProtoType_Foks,
		Fqp: FQPartyParsed{
			Party: *party,
			Host:  host,
		},
		Repo: repo,
	}, nil
}

func (d KVDirent) IDPair() KVDirentIDPair {
	return KVDirentIDPair{
		ParentDirID: d.ParentDir,
		DirentID:    d.Id,
	}
}

func (t FQTeam) ToFQTeamParsed() FQTeamParsed {
	host := NewParsedHostnameWithFalse(t.Host)
	return FQTeamParsed{
		Team: NewParsedTeamWithFalse(t.Team),
		Host: &host,
	}
}

func (p GitRepo) Module(s string) GitRepo {
	return GitRepo(path.Join(string(p), "modules", s))
}

func (p ParsedParty) IsTeam() (bool, error) {
	isName, err := p.GetS()
	if err != nil {
		return false, err
	}
	if isName {
		return p.True().IsTeam, nil
	}
	return p.False().IsTeam(), nil
}

func (p ParsedParty) IsUser() (bool, error) {
	isTeam, err := p.IsTeam()
	if err != nil {
		return false, err
	}
	return !isTeam, nil
}

func (p FQPartyParsed) ToUser() (*FQUserParsed, error) {
	ret, _, err := p.Select()
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return nil, DataError("not a user")
	}
	return ret, err
}

func (p FQPartyParsed) ToTeam() (*FQTeamParsed, error) {
	_, ret, err := p.Select()
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return nil, DataError("not a team")
	}
	return ret, err
}

func (p FQPartyParsed) Select() (*FQUserParsed, *FQTeamParsed, error) {
	isName, err := p.Party.GetS()
	if err != nil {
		return nil, nil, err
	}

	if isName {
		nm := p.Party.True()
		if nm.IsTeam {
			return nil, &FQTeamParsed{
				Team: NewParsedTeamWithTrue(nm.Name),
				Host: p.Host,
			}, nil
		} else {
			return &FQUserParsed{
				User: NewParsedUserWithTrue(nm.Name),
				Host: p.Host,
			}, nil, nil

		}
	}

	uid, tid, err := p.Party.False().Select()
	if err != nil {
		return nil, nil, err
	}

	switch {
	case uid != nil:
		return &FQUserParsed{
			User: NewParsedUserWithFalse(*uid),
			Host: p.Host,
		}, nil, nil

	case tid != nil:
		return nil, &FQTeamParsed{
			Team: NewParsedTeamWithFalse(*tid),
			Host: p.Host,
		}, nil
	default:
		return nil, nil, DataError("bad party")
	}
}

func (i UserInfo) EqFQUserParsed(p FQUserParsed, fn NameNormFn) (bool, error) {
	isName, err := p.User.GetS()
	if err != nil {
		return false, err
	}

	if isName {
		nun, err := fn(p.User.True())
		if err != nil {
			return false, err
		}
		eq := i.Username.Name.Eq(nun)
		if !eq {
			return false, nil
		}
	} else {
		eq := i.Fqu.Uid.Eq(p.User.False())
		if !eq {
			return false, nil
		}
	}

	if p.Host == nil {
		return true, nil
	}

	isName, err = p.Host.GetS()
	if err != nil {
		return false, err
	}
	if isName {
		return i.HostAddr.NormEqIgnorePort(p.Host.True()), nil
	}
	return i.Fqu.HostID.Eq(p.Host.False()), nil
}

func KVPathAbs(p ...string) KVPath {
	ret := KVPathJoin(p...)
	if ret == "" {
		return ret
	}
	if !strings.HasPrefix(ret.String(), KVPathSeparator) {
		ret = KVPath(KVPathSeparator) + ret
	}
	return ret
}

// KVPathSeparator is the separator used in KVPath. It's crucial that it
// doesn't change to "\" on Windows, so we can't use filepath.Separator.
// Ditto for filepath.Join.
const KVPathSeparator = string("/")

func KVPathJoin(p ...string) KVPath {
	return KVPath(path.Join(p...))
}

func PathComponentJoin(p []KVPathComponent) KVPath {
	v := make([]string, len(p))
	for i, c := range p {
		v[i] = string(c)
	}
	return KVPathJoin(v...)
}

func PathJoin(p []KVPath) KVPath {
	v := make([]string, len(p))
	for i, c := range p {
		v[i] = string(c)
	}
	return KVPathJoin(v...)
}

func (k KVPath) String() string {
	return string(k)
}

func (s SenderPair) ToTeamMemberKeys() TeamMemberKeys {
	return TeamMemberKeys{
		VerifyKey: s.VerifyKey,
		HepkFp:    s.HepkFp,
	}
}

func (t TeamMemberKeys) ToSenderPair() SenderPair {
	return SenderPair{
		VerifyKey: t.VerifyKey,
		HepkFp:    t.HepkFp,
	}
}

func (l LocalFSPath) String() string { return string(l) }

func (t TCPAddr) NormEqIgnorePort(t2 TCPAddr) bool {
	return t.Hostname().NormEq(t2.Hostname())

}

func (t KVNodeType) IsFile() bool {
	switch t {
	case KVNodeType_File, KVNodeType_SmallFile:
		return true
	default:
		return false
	}
}

func (y YubiID) Eq(y2 YubiID) bool {
	return hmac.Equal(y[:], y2[:])
}

func (k KVPath) Append(p ...KVPathComponent) KVPath {
	sv := make([]string, 0, len(p))
	for _, c := range p {
		sv = append(sv, string(c))
	}
	return KVPathJoin(
		string(k),
		string(KVPathJoin(sv...)),
	)
}

func (k KVPathComponent) ToPath() KVPath {
	return KVPath(string(k))
}

func (n NameUtf8) String() string {
	return string(n)
}

func (p ParsedParty) StringErr() (PartyString, error) {
	isName, err := p.GetS()
	if err != nil {
		return "", err
	}
	if isName {
		// This routine with prefix teams with the 't:' prefix so they can be
		// distinguished from user names.
		return p.True().PartyString(), nil
	}
	s, err := p.False().EntityID().StringErr()
	if err != nil {
		return "", err
	}
	return PartyString(s), nil
}

func (g GitURL) StringErr() (GitURLString, error) {
	host, err := g.Fqp.Host.StringErr()
	if err != nil {
		return "", err
	}
	party, err := g.Fqp.Party.StringErr()
	if err != nil {
		return "", err
	}
	var proto string
	switch g.Proto {
	case GitProtoType_Foks:
		proto = GitProtoPrefix
	default:
		return "", DataError("bad git proto")
	}
	return GitURLString(fmt.Sprintf("%s%s/%s/%s", proto, host, party, g.Repo)), nil
}

func (u UID) EncodeToHex() string {
	return hex.EncodeToString(u[:])
}

// Map of size suffixes to their corresponding multiplier in bytes
var sizeMultipliers = map[string]int64{
	"B":  1,
	"KB": 1024,
	"MB": 1024 * 1024,
	"GB": 1024 * 1024 * 1024,
	"TB": 1024 * 1024 * 1024 * 1024,
}

func (s *Size) Parse(s2 string) error {
	// Remove any leading or trailing whitespace
	sizeStr := strings.TrimSpace(s2)

	// Find the first non-digit character (this will be the start of the unit)
	var i int
	for i = 0; i < len(sizeStr); i++ {
		if sizeStr[i] < '0' || sizeStr[i] > '9' {
			break
		}
	}

	// Separate the numeric part from the unit part
	numberPart := sizeStr[:i]
	unitPart := strings.ToUpper(strings.TrimSpace(sizeStr[i:]))

	// Convert the numeric part to an integer
	number, err := strconv.ParseInt(numberPart, 10, 64)
	if err != nil {
		return DataError("invalid number format")
	}
	var multiplier int64 = 1
	if len(numberPart) > 0 {
		// Lookup the multiplier for the unit
		var ok bool
		multiplier, ok = sizeMultipliers[unitPart]
		if !ok {
			return DataError("unknown size unit")
		}
	}

	// Calculate the size in bytes
	*s = Size(number * multiplier)
	return nil
}

func (s Size) HumanReadable() string {
	bytes := s
	const unit = Size(1024)
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := Size(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	val := float64(bytes) / float64(div)
	var floatFmt string
	switch {
	case val < 100:
		floatFmt = "%.2f"
	case val < 1000:
		floatFmt = "%.1f"
	default:
		floatFmt = "%.0f"
	}
	return fmt.Sprintf(floatFmt+"%cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func (p PartyID) Fixed() (FixedPartyID, error) {
	var ret FixedPartyID
	if len(p) != len(ret) {
		return ret, DataError("bad partyID; wrong length")
	}
	copy(ret[:], p[:])
	return ret, nil
}

func (f FixedPartyID) Unfix() PartyID {
	return PartyID(f[:])
}

func (e EntityIDString) CSSId() string {
	return string(e[1:11])
}

func (t Time) IsZero() bool {
	return t == 0
}

func (u URLString) StringP() *string {
	ret := string(u)
	return &ret
}

func (u URLString) String() string {
	return string(u)
}

func (e Email) String() string {
	return string(e)
}

func (u URLString) PathJoin(p URLString) URLString {
	left := strings.TrimRight(u.String(), "/")
	right := strings.TrimLeft(p.String(), "/")
	return URLString(left + "/" + right)
}

func (h Hostname) Parent() Hostname {
	parts := strings.Split(string(h), ".")
	if len(parts) < 2 {
		return ""
	}
	return Hostname(strings.Join(parts[1:], "."))
}

func (h Hostname) Reverse() Hostname {
	parts := strings.Split(string(h), ".")
	if len(parts) < 2 {
		return h
	}
	ret := make([]string, len(parts))
	for i, x := range parts {
		ret[len(parts)-1-i] = x
	}
	return Hostname(strings.Join(ret, "."))
}

func (v HostBuildStage) String() string {
	switch v {
	case HostBuildStage_None:
		return "none"
	case HostBuildStage_Stage1:
		return "stage1"
	case HostBuildStage_Stage2a:
		return "stage2a"
	case HostBuildStage_Stage2b:
		return "stage2b"
	case HostBuildStage_Complete:
		return "complete"
	case HostBuildStage_Aborted:
		return "aborted"
	default:
		return "none"
	}
}

func (v *HostBuildStage) ImportFromString(s string) error {
	switch s {
	case "none":
		*v = HostBuildStage_None
	case "stage1":
		*v = HostBuildStage_Stage1
	case "stage2a":
		*v = HostBuildStage_Stage2a
	case "stage2b":
		*v = HostBuildStage_Stage2b
	case "complete":
		*v = HostBuildStage_Complete
	case "aborted":
		*v = HostBuildStage_Aborted
	default:
		return DataError("bad vanity host build stage")
	}
	return nil
}

func (a Hostname) Cmp(b Hostname) int {
	x1 := strings.ToLower(a.String())
	x2 := strings.ToLower(b.String())
	return strings.Compare(x1, x2)
}

func (s HostBuildStage) IsBuilding() bool {
	switch s {
	case HostBuildStage_Stage1,
		HostBuildStage_Stage2a,
		HostBuildStage_Stage2b:
		return true
	default:
		return false
	}
}

func (s HostBuildStage) Gt(t HostBuildStage) bool {
	return int(s) > int(t)
}

func (s HostBuildStage) Gte(t HostBuildStage) bool {
	return int(s) >= int(t)
}

func (s HostBuildStage) Lt(t HostBuildStage) bool {
	return int(s) < int(t)
}
func (s HostBuildStage) Lte(t HostBuildStage) bool {
	return int(s) <= int(t)
}

var HostBuildStagesInProgress = []HostBuildStage{
	HostBuildStage_Stage1,
	HostBuildStage_Stage2a,
	HostBuildStage_Stage2b,
}

func (h HostID) String() string {
	ret, err := h.StringErr()
	if err != nil {
		return "error"
	}
	return ret
}

func (h Hostname) Join(g Hostname) Hostname {
	return Hostname(string(h) + "." + string(g))
}

func (h Hostname) Wildcard() Hostname {
	return Hostname("*." + string(h))
}

func (h Hostname) Split() []Hostname {
	parts := strings.Split(string(h), ".")
	ret := make([]Hostname, len(parts))
	for i, x := range parts {
		ret[i] = Hostname(x)
	}
	return ret
}

func (h Hostname) RevSplit() []Hostname {
	parts := strings.Split(string(h), ".")
	ret := make([]Hostname, len(parts))
	for i, x := range parts {
		ret[len(parts)-1-i] = Hostname(x)
	}
	return ret
}

func (h Hostname) IsSubdomainOf(g Hostname) bool {
	gl := g.Normalize().RevSplit()
	hl := h.Normalize().RevSplit()
	if len(hl) < len(gl) {
		return false
	}
	for i, x := range gl {
		if x != hl[i] {
			return false
		}
	}
	return true
}

func (z ZoneID) IsZero() bool {
	return z == ""
}

func (z ZoneID) String() string {
	return string(z)
}

func (h Hostname) AllSuperdomains() []Hostname {
	parts := strings.Split(string(h), ".")

	// Strip off any trailing empty string, which we'll get if we're dealing with a
	// domain ending in ".", as we sometimes see in the context of DNS.
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	var ret []Hostname
	for i := 1; i < len(parts)-1; i++ {
		domain := strings.Join(parts[i:], ".")
		ret = append(ret, Hostname(domain))
	}
	return ret
}

func HostnameJoin(h []Hostname) Hostname {
	parts := make([]string, len(h))
	for i, x := range h {
		parts[i] = string(x)
	}
	return Hostname(strings.Join(parts, "."))
}

func (h Hostname) WithTrailingDot() Hostname {
	if strings.HasSuffix(string(h), ".") {
		return h
	}
	return Hostname(string(h) + ".")
}

func (v ViewershipMode) String() string {
	switch v {
	case ViewershipMode_Closed:
		return "closed"
	case ViewershipMode_OpenToAdmin:
		return "open_to_admin"
	case ViewershipMode_OpenToAll:
		return "open_to_all"
	default:
		return "error"
	}
}

func (v *ViewershipMode) ImportFromDB(s string) error {
	switch s {
	case "closed":
		*v = ViewershipMode_Closed
	case "open_to_admin":
		*v = ViewershipMode_OpenToAdmin
	case "open_to_all":
		*v = ViewershipMode_OpenToAll
	default:
		return DataError("bad viewership mode")
	}
	return nil
}

func (n Name) String() string {
	return string(n)
}

func (p PassphraseSalt) String() string                  { return B62Encode(p[:]) }
func (p PassphraseSalt) MarshalJSON() ([]byte, error)    { return json.Marshal(p.String()) }
func (p *PassphraseSalt) UnmarshalJSON(dat []byte) error { return UnmarshalJsonFixed((*p)[:], dat) }

const DefProbePort = Port(4430)

func (t TCPAddr) ProbeHostStringErr() (string, error) {
	tmp, err := t.MaybeElidePort(DefProbePort)
	if err != nil {
		return "", err
	}
	return tmp.String(), nil
}

func (t TCPAddr) ProbeHostString() string {
	ret, err := t.ProbeHostStringErr()
	if err != nil {
		return "error"
	}
	return ret
}

func (q KVPathComponent) Escape() KVPathComponent {
	return KVPathComponent(url.QueryEscape(string(q)))
}

func (q KVPathComponent) Unescape() (KVPath, error) {
	ret, err := url.QueryUnescape(string(q))
	if err != nil {
		return "", err
	}
	return KVPath(ret), nil
}

func (p KVPath) Escape() KVPathComponent {
	return KVPathComponent(url.QueryEscape(string(p)))
}

func (p KVPath) Join(p2 KVPath) KVPath {
	return KVPathJoin(string(p), string(p2))
}

func (s AutocertState) String() string {
	switch s {
	case AutocertState_OK:
		return "ok"
	case AutocertState_Failing:
		return "failing"
	case AutocertState_Failed:
		return "failed"
	default:
		return "none"
	}
}

func (a *AutocertState) ImportFromDB(s string) error {
	switch s {
	case "ok":
		*a = AutocertState_OK
	case "failing":
		*a = AutocertState_Failing
	case "failed":
		*a = AutocertState_Failed
	case "none":
		*a = AutocertState_None
	default:
		return DataError("bad Autocert state")
	}
	return nil
}

func (p PartyName) PartyString() PartyString {
	var ret string
	if p.IsTeam {
		ret = TeamStringPrefix
	}
	return PartyString(ret + string(p.Name))
}

func (s SSOClientID) String() string {
	return string(s)
}

func (u URLString) IsZero() bool {
	return u == ""
}

func (u URLString) Normalize() URLString {
	return URLString(strings.ToLower(string(u)))
}

func (n OAuth2Nonce) String() string {
	return string(n)
}

func (p OAuth2PKCEChallengeCode) String() string {
	return string(p)
}

func (p OAuth2PKCEVerifier) String() string {
	return string(p)
}

func (c OAuth2Code) String() string {
	return string(c)
}

func (n1 OAuth2Nonce) Eq(n2 OAuth2Nonce) bool {
	return n1 == n2
}

func (o OAuth2ClientID) String() string {
	return string(o)
}

func (o OAuth2ClientSecret) IsZero() bool {
	return o == ""
}

func (o OAuth2ClientSecret) String() string {
	return string(o)
}

func (t SSOProtocolType) String() string {
	switch t {
	case SSOProtocolType_Oauth2:
		return "oauth2"
	case SSOProtocolType_SAML:
		return "saml"
	default:
		return "none"
	}
}

func (t *SSOProtocolType) ImportFromDB(s string) error {
	switch s {
	case "oauth2":
		*t = SSOProtocolType_Oauth2
	case "saml":
		*t = SSOProtocolType_SAML
	case "none":
		*t = SSOProtocolType_None
	default:
		return DataError("bad SSO protocol type")
	}
	return nil
}

func (s *SSOConfig) HasOAuth2() bool {
	return s != nil && s.Active == SSOProtocolType_Oauth2 && s.Oauth2 != nil
}

func (o OAuth2RefreshToken) String() string { return string(o) }
func (o OAuth2AccessToken) String() string  { return string(o) }
func (o OAuth2IDToken) String() string      { return string(o) }

func (o OAuth2AccessToken) IsZero() bool  { return len(o) == 0 }
func (o OAuth2RefreshToken) IsZero() bool { return len(o) == 0 }
func (o OAuth2IDToken) IsZero() bool      { return len(o) == 0 }

func (e Email) IsZero() bool {
	return len(e) == 0
}

func (o *OAuth2IDTokenBindingPayload) AssertNormalized() error {
	return nil
}

func (h Hostname) AssertNoPort() error {
	_, port, err := net.SplitHostPort(string(h))
	if err != nil {
		return nil
	}
	if port != "" {
		return DataError("hostname contains port")
	}
	return nil
}

func (o OAuth2Subject) String() string {
	return string(o)
}

func (n OAuth2Nonce) IsZero() bool {
	return len(n) == 0
}

const HostchainEldestSeqno = Seqno(1)
const ChainEldestSeqno = Seqno(1)
const FirstGeneration = Generation(1)
const FirstPassphraseGeneration = PassphraseGeneration(1)
const FirstNameSeqno = NameSeqno(1)
const FirstDeviceSerial = DeviceSerial(1)

func (s Seqno) IsEldest() bool       { return s == ChainEldestSeqno }
func (s Seqno) IsValid() bool        { return s >= ChainEldestSeqno }
func (g Generation) IsFirst() bool   { return g == FirstGeneration }
func (g Generation) IsVoid() bool    { return g == 0 }
func (g Generation) IsValid() bool   { return g >= FirstGeneration }
func (g Generation) ToIndex() int    { return int(g - FirstGeneration) }
func (n NameSeqno) IsFirst() bool    { return n == FirstNameSeqno }
func (n NameSeqno) IsValid() bool    { return n >= FirstNameSeqno }
func (n NameSeqno) ToIndex() int     { return int(n - FirstNameSeqno) }
func (s DeviceSerial) IsValid() bool { return s >= FirstDeviceSerial }
func (s DeviceSerial) ToIndex() int  { return int(s - FirstDeviceSerial) }
func (s DeviceSerial) IsFirst() bool { return s == FirstDeviceSerial }

func GenerationFromIndex(idx int) Generation {
	if idx < 0 {
		return Generation(0)
	}
	return Generation(idx) + FirstGeneration
}

func PassphraseGenerationFromIndex(idx int) PassphraseGeneration {
	if idx < 0 {
		return PassphraseGeneration(0)
	}
	return PassphraseGeneration(idx) + FirstPassphraseGeneration
}

func (p PassphraseGeneration) IsFirst() bool { return p == FirstPassphraseGeneration }
func (p PassphraseGeneration) IsValid() bool { return p >= FirstPassphraseGeneration }
func (p PassphraseGeneration) ToIndex() int  { return int(p - FirstPassphraseGeneration) }

func (t CKSAssetType) String() string {
	switch t {
	case CKSAssetType_None:
		return "none"
	case CKSAssetType_InternalClientCA:
		return "internal_client_ca"
	case CKSAssetType_ExternalClientCA:
		return "external_client_ca"
	case CKSAssetType_HostchainFrontendCA:
		return "hostchain_frontend_ca"
	case CKSAssetType_BackendCA:
		return "backend_ca"
	case CKSAssetType_RootPKIFrontendX509Cert:
		return "root_pki_frontend_x509_cert"
	case CKSAssetType_HostchainFrontendX509Cert:
		return "hostchain_frontend_x509_cert"
	case CKSAssetType_BackendX509Cert:
		return "backend_x509_cert"
	case CKSAssetType_RootPKIBeaconX509Cert:
		return "root_pki_beacon_x509_cert"
	default:
		return "error"
	}
}

func (t *CKSAssetType) ImportFromDB(s string) error {
	switch s {
	case "none":
		*t = CKSAssetType_None
	case "internal_client_ca", "internal-client-ca":
		*t = CKSAssetType_InternalClientCA
	case "external_client_ca", "external-client-ca":
		*t = CKSAssetType_ExternalClientCA
	case "hostchain_frontend_ca", "hostchain-frontend-ca":
		*t = CKSAssetType_HostchainFrontendCA
	case "backend_ca", "backend-ca":
		*t = CKSAssetType_BackendCA
	case "root_pki_frontend_x509_cert", "root-pki-frontend-x509-cert":
		*t = CKSAssetType_RootPKIFrontendX509Cert
	case "hostchain_frontend_x509_cert", "hostchain-frontend-x509-cert":
		*t = CKSAssetType_HostchainFrontendX509Cert
	case "backend_x509_cert", "backend-x509-cert":
		*t = CKSAssetType_BackendX509Cert
	case "root_pki_beacon_x509_cert", "root-pki-beacon-x509-cert":
		*t = CKSAssetType_RootPKIBeaconX509Cert
	default:
		return DataError("bad CKS asset type")
	}
	return nil
}

func NewCKSEncKey() (CKSEncKey, error) {
	var ret CKSEncKey
	_, err := rand.Read(ret[:])
	return ret, err
}

func (k CKSEncKey) KeyString() CKSEncKeyString { return CKSEncKeyString(B62Encode(k[:])) }
func (k CKSEncKey) String() string             { return k.KeyString().String() }
func (k CKSEncKeyString) String() string       { return string(k) }

func (k CKSEncKeyString) Parse() (*CKSEncKey, error) {
	raw, err := B62Decode(string(k))
	if err != nil {
		return nil, err
	}
	var ret CKSEncKey
	if len(raw) != len(ret) {
		return nil, DataError("bad CKSEncKey, wrong length")
	}
	copy(ret[:], raw)
	return &ret, nil
}

func (t ServerType) ClientCAType() CKSAssetType {
	switch t {
	case ServerType_Queue, ServerType_Quota, ServerType_MerkleBatcher,
		ServerType_MerkleBuilder, ServerType_MerkleSigner, ServerType_Autocert:
		return CKSAssetType_InternalClientCA
	case ServerType_User, ServerType_KVStore:
		return CKSAssetType_ExternalClientCA
	default:
		return CKSAssetType_None
	}
}

func (t ServerType) ServerCertType() CKSAssetType {
	switch t {
	case ServerType_Queue, ServerType_Quota, ServerType_MerkleBatcher,
		ServerType_MerkleBuilder, ServerType_MerkleSigner, ServerType_Autocert,
		ServerType_InternalCA:
		return CKSAssetType_BackendX509Cert
	case ServerType_User, ServerType_KVStore, ServerType_Reg, ServerType_MerkleQuery:
		return CKSAssetType_HostchainFrontendX509Cert
	case ServerType_Probe, ServerType_Web:
		return CKSAssetType_RootPKIFrontendX509Cert
	case ServerType_Beacon:
		return CKSAssetType_RootPKIBeaconX509Cert
	default:
		return CKSAssetType_None
	}
}

func (k PKIXCertID) EntityID() EntityID { return EntityID(k) }

func (c CKSCertChain) ToRaw() [][]byte {
	return [][]byte(c.Certs)
}

func NewCKSCertChainFromSingle(cert []byte) CKSCertChain {
	return CKSCertChain{
		Certs: [][]byte{cert},
	}
}

func (c *CKSCertChain) Leaf() []byte {
	if len(c.Certs) == 0 {
		return nil
	}
	return c.Certs[0]
}

func (t CKSAssetType) CAType() CKSAssetType {
	switch t {
	case CKSAssetType_BackendX509Cert:
		return CKSAssetType_BackendCA
	case CKSAssetType_HostchainFrontendX509Cert:
		return CKSAssetType_HostchainFrontendCA
	default:
		return CKSAssetType_None
	}
}

func (t CKSAssetType) IsFrontendCA() bool {
	switch t {
	case CKSAssetType_ExternalClientCA,
		CKSAssetType_HostchainFrontendCA:
		return true
	default:
		return false
	}
}

func (t HostType) String() string {
	switch t {
	case HostType_None:
		return "none"
	case HostType_BigTop:
		return "big_top"
	case HostType_VHostManagement:
		return "vhost_management"
	case HostType_VHost:
		return "vhost"
	default:
		return "error"
	}
}

func (t *HostType) ImportFromString(s string) error {
	switch s {
	case "none":
		*t = HostType_None
	case "big_top":
		*t = HostType_BigTop
	case "vhost_management":
		*t = HostType_VHostManagement
	case "vhost":
		*t = HostType_VHost
	default:
		return DataError("bad host type")
	}
	return nil
}

func (t Time) DateString() string {
	return t.Import().Format("02 Jan 2006")
}

func (t Time) String() string {
	return fmt.Sprintf("%d", int64(t))
}

func (t Time) UnixSeconds() int64 {
	return int64(t / 1000)
}

func (h HostType) SupportKVStore() bool {
	switch h {
	case HostType_BigTop, HostType_VHost:
		return true
	default:
		return false
	}
}

func (h HostType) SupportBilling() bool {
	switch h {
	case HostType_BigTop, HostType_VHostManagement:
		return true
	default:
		return false
	}
}

func (s UISessionID) IsZero() bool {
	return s.Type == 0
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (p YubiPIN) IsValid() bool {
	return len(p) >= 6 && len(p) <= 8 && isAllDigits(string(p))
}

func (p YubiPIN) IsZero() bool {
	return len(p) == 0
}

func (p Passphrase) ToYubiPIN() (YubiPIN, error) {
	ret := YubiPIN(p)
	if !ret.IsValid() {
		var zed YubiPIN
		return zed, DataError("bad YubiKey PIN; must be 6-8 characters")
	}
	return ret, nil
}

func (p Passphrase) ToYubiPINOrZero() (YubiPIN, error) {
	if len(p) == 0 {
		var zed YubiPIN
		return zed, nil
	}
	return p.ToYubiPIN()
}

func (p YubiPIN) String() string {
	return string(p)
}

func (p YubiPIN) Eq(q YubiPIN) bool {
	return p == q
}

func (p YubiPUK) IsValid() bool {
	return len(p) == 8 && isAllDigits(string(p))
}

func (p Passphrase) ToYubiPUK() (YubiPUK, error) {
	ret := YubiPUK(p)
	if !ret.IsValid() {
		var zed YubiPUK
		return zed, DataError("bad YubiKey PUK; must be 8 characters")
	}
	return ret, nil
}

func (p Passphrase) ToYubiPUKOrZero() (YubiPUK, error) {
	if len(p) == 0 {
		var zed YubiPUK
		return zed, nil
	}
	return p.ToYubiPUK()
}

func (p YubiPUK) Eq(q YubiPUK) bool {
	return p == q
}

func (p YubiPUK) String() string {
	return string(p)
}

func (p YubiPUK) IsZero() bool {
	return len(p) == 0
}

func (k YubiManagementKey) String() string {
	raw := B62Encode(k[:])
	var parts []string
	splitAt := 5
	for len(raw) > splitAt {
		parts = append(parts, raw[:splitAt])
		raw = raw[splitAt:]
	}
	parts = append(parts, raw)
	return strings.Join(parts, " ")
}

func (m YubiManagementKey) IsZero() bool {
	return IsZero(m[:])
}

func (k YubiManagementKey) Eq(i YubiManagementKey) bool {
	return hmac.Equal(k[:], i[:])
}

func (i YubiCardID) Eq(i2 YubiCardID) bool {
	return i.Name == i2.Name && i.Serial == i2.Serial
}

const MerkleEpnoFirst = MerkleEpno(1)

func (e MerkleEpno) IsFirst() bool {
	return e == MerkleEpnoFirst
}

func (e MerkleEpno) IsValid() bool {
	return e >= MerkleEpnoFirst
}

func (t FQTeam) ToFQEntity() FQEntity {
	return FQEntity{
		Entity: t.Team.EntityID(),
		Host:   t.Host,
	}
}

func (s SemVer) Cmp(s2 SemVer) int {
	if s.Major < s2.Major {
		return -1
	}
	if s.Major > s2.Major {
		return 1
	}
	if s.Minor < s2.Minor {
		return -1
	}
	if s.Minor > s2.Minor {
		return 1
	}
	if s.Patch < s2.Patch {
		return -1
	}
	if s.Patch > s2.Patch {
		return 1
	}
	return 0
}

func (s SemVer) String() string {
	return fmt.Sprintf("%d.%d.%d", s.Major, s.Minor, s.Patch)
}

func (i TeamRemoteMemberViewTokenInner) GetPTKRole() (*Role, error) {
	ret := i.PtkRole
	typ, err := ret.GetT()
	if err != nil {
		return nil, err
	}
	if typ == RoleType_NONE {
		ret := AdminRole
		return &ret, nil
	}
	return &ret, nil
}
