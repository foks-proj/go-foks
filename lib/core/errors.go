// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	infra "github.com/foks-proj/go-foks/proto/infra"
	lcl "github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	remhelp "github.com/foks-proj/go-git-remhelp"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type InternalError string

func (i InternalError) Error() string {
	return "internal error: " + string(i)
}

type DeviceAlreadyProvisionedError struct{}

func (d DeviceAlreadyProvisionedError) Error() string {
	return "device already provisioned"
}

type AuthError struct{}

func (a AuthError) Error() string {
	return "authentication error"
}

type VersionNotSupportedError string

func (v VersionNotSupportedError) Error() string {
	return string(v)
}

type UpgradeNeededError string

func (u UpgradeNeededError) Error() string {
	return "upgrade needed: " + string(u)
}

type DecryptionError struct{}

func (d DecryptionError) Error() string {
	return "decryption failed"
}

type UserNotFoundError struct{}

func (u UserNotFoundError) Error() string {
	return "user not found"
}

type ConfigError string

func (c ConfigError) Error() string {
	return "config error: " + string(c)
}

type TLSError string

func (t TLSError) Error() string {
	return "TLS error: " + string(t)
}

type DbError string

func (d DbError) Error() string {
	return "DB error: " + string(d)
}

type DuplicateError string

func (e DuplicateError) Error() string {
	return "duplicate error: " + string(e)
}

func (e DuplicateError) Thing() string {
	return string(e)
}

type VerifyError string

func (v VerifyError) Error() string {
	return "signature verify error: " + string(v)
}

type CanonicalEncodingError struct {
	Path StructPath
	Err  error
}

func (c CanonicalEncodingError) Error() string {
	return fmt.Sprintf("canonical encoding error @%s: %s", c.Path, c.Err.Error())
}

type SigningKeyNotFullyProvisionedError struct{}

func (s SigningKeyNotFullyProvisionedError) Error() string {
	return "signing key not fully provisioned"
}

type SignatureError string

func (s SignatureError) Error() string {
	return "signature error: " + string(s)
}

type LinkError string

func (l LinkError) Error() string {
	return "link error: " + string(l)
}

type PublicKeyError string

func (p PublicKeyError) Error() string {
	return "public key error: " + string(p)
}

type ReservationError string

func (u ReservationError) Error() string {
	return "username reservation error: " + string(u)
}

type NameError string

func (n NameError) Error() string {
	return string(n)
}

type ValidationError string

func (v ValidationError) Error() string {
	return "validation error: " + string(v)
}

type X509Error string

func (x X509Error) Error() string {
	return "x509 error: " + string(x)
}

type InsertError string

func (i InsertError) Error() string {
	return "insert error: " + string(i)
}

type UpdateError string

func (u UpdateError) Error() string {
	return "update error: " + string(u)
}

type TimeoutError struct{}

func (t TimeoutError) Error() string {
	return "timeout error"
}

type ReplayError struct{}

func (r ReplayError) Error() string {
	return "replay error"
}

type BadPassphraseError struct{}

func (b BadPassphraseError) Error() string {
	return "bad passphrase"
}

type PassphraseNotFoundError struct{}

func (p PassphraseNotFoundError) Error() string {
	return "no passphrase for user"
}

type RateLimitError struct{}

func (r RateLimitError) Error() string {
	return "rate limit error"
}

type PermissionError string

func (p PermissionError) Error() string {
	return "permission error: " + string(p)
}

type TxRetryError struct{}

func (t TxRetryError) Error() string {
	return "transaction failed since retry attempts exceeeded"
}

type PrevError string

func (l PrevError) Error() string {
	return "prev error: " + string(l)
}

type BoxError string

func (b BoxError) Error() string {
	return "box error: " + string(b)
}

type RevokeError string

func (r RevokeError) Error() string {
	return "revoke error: " + string(r)
}

type CommitmentError string

func (c CommitmentError) Error() string {
	return "commitment error: " + string(c)
}

type BitPrefixMatchError int

func (b BitPrefixMatchError) Error() string {
	return fmt.Sprintf("bit prefix match failed at bit=%d", b)
}

type MerkleNodeNotFoundError struct {
	Msg         string
	BitPosition int
}

type MerkleNoRootError struct{}

func (m MerkleNoRootError) Error() string {
	return "no merkle root"
}

func (m MerkleNodeNotFoundError) Error() string {
	return fmt.Sprintf("merkle node not found at bit position %d: %s", m.BitPosition, m.Msg)
}

type MerkleLeafNotFoundError struct{}

func (m MerkleLeafNotFoundError) Error() string {
	return "merkle leaf not found"
}

type MerkleInitError string

func (m MerkleInitError) Error() string {
	return "merkle init error: " + string(m)
}

type MerkleTreeError string

func (m MerkleTreeError) Error() string {
	return fmt.Sprintf("merkle tree integrity error: %s", string(m))
}

type KeyImportError string

func (k KeyImportError) Error() string {
	return "key import error: " + string(k)
}

type MerkleVerifyError string

func (m MerkleVerifyError) Error() string {
	return "merkle verify error: " + string(m)
}

type MerkleRollbackError struct {
	Have proto.MerkleEpno
	Saw  proto.MerkleEpno
}

func (m MerkleRollbackError) Error() string {
	return fmt.Sprintf("merkle rollback error: %d < %d", m.Saw, m.Have)
}

type MerkleBackPointerVerifyError struct {
	Epno proto.MerkleEpno
	Msg  string
}

func (m MerkleBackPointerVerifyError) Error() string {
	return fmt.Sprintf("error verifying backpointers at epno=%d: %s", m.Epno, m.Msg)
}

type WrongUserError struct{}

func (w WrongUserError) Error() string {
	return "credentials for wrong user"
}

type UserSwitchError string

func (a UserSwitchError) Error() string {
	return "user switch error: " + string(a)
}

type KexBadSecretError struct{}

func (k KexBadSecretError) Error() string {
	return "KEX: bad secret input; typo?"
}

type KexWrongMessageError struct {
	Expected lcl.KexMsgType
	Received lcl.KexMsgType
}

func (k KexWrongMessageError) Error() string {
	return fmt.Sprintf("KEX wrong message type; wanted %s but got %s",
		lcl.KexMsgTypeRevMap[k.Expected],
		lcl.KexMsgTypeRevMap[k.Received],
	)
}

type KexVerifyError string

func (k KexVerifyError) Error() string {
	return fmt.Sprintf("key verify error: %s", string(k))
}

type KexWrapperError struct {
	Err error
}

func (k KexWrapperError) Error() string {
	return "kex wrapper error: " + k.Err.Error()
}

func (k KexWrapperError) Unwrap() error {
	return k.Err
}

type EncodingError string

func (b EncodingError) Error() string {
	return "encoding error: " + string(b)
}

type MacOSKeychainError string

func (m MacOSKeychainError) Error() string {
	return "macOS keychain error: " + string(m)
}

type PlatformError struct{}

func (p PlatformError) Error() string {
	return "feature not available on this platform"
}

type KeyNotFoundError struct {
	Which string
}

func (n KeyNotFoundError) Error() string {
	ret := "key not found"
	if n.Which != "" {
		ret += ": " + n.Which
	}
	return ret
}

type NotFoundError string

func (n NotFoundError) Error() string {
	return "not found: " + string(n)
}

type RowNotFoundError struct{}

func (r RowNotFoundError) Error() string {
	return "row not found"
}

type YubiError string

func (y YubiError) Error() string {
	return "yubikey error: " + string(y)
}

type HostMismatchError struct {
	Which string
}

func (h HostMismatchError) Error() string {
	ret := "hostname mismatch"
	if h.Which != "" {
		ret += ": " + h.Which
	}
	return ret
}

type MissingHostError struct{}

func (h MissingHostError) Error() string {
	return "wanted a host but it was missing"
}

type BadInviteCodeError struct{}

func (b BadInviteCodeError) Error() string {
	return "bad invite code"
}

type NotImplementedError struct{}

func (n NotImplementedError) Error() string {
	return "not implemented"
}

type ExpandError string

func (e ExpandError) Error() string {
	return "expansion error: " + string(e)
}

type SessionNotFoundError proto.UISessionID

func (s SessionNotFoundError) Error() string {
	return fmt.Sprintf("session not found: %d/%d", uint(s.Type), uint(s.Ctr))
}

type TooManyTriesError struct{}

func (t TooManyTriesError) Error() string {
	return "too many tries"
}

type CanceledInputError struct{}

func (c CanceledInputError) Error() string {
	return "input canceled"
}

type CancelSignupStage int

type MerkleLeafExistsError struct{}

func (m MerkleLeafExistsError) Error() string {
	return "merkle leaf already exists"
}

type HESPError string

func (k HESPError) Error() string {
	return "high entropy secret phrase error: " + string(k)
}

type CannotRotateError struct{}

func (c CannotRotateError) Error() string {
	return "cannot rotate; active key is too low"
}

type ConnectError struct {
	Err  error
	Desc string
}

func NewConnectError(desc string, err error) ConnectError {
	return ConnectError{Err: err, Desc: desc}
}

func (c ConnectError) Error() string {
	return "connect error: " + c.Desc + " (" + c.Err.Error() + ")"
}

func IsConnectError(e error) bool {
	if e == nil {
		return false
	}
	_, ok := e.(ConnectError)
	return ok
}

type DNSError struct {
	Stage string
	Err   error
}

func (d DNSError) Error() string {
	return fmt.Sprintf("DNS error at stage %s: %s", d.Stage, d.Err.Error())
}

const (
	CancelSignupStageWaitList CancelSignupStage = 1
	CancelSignupPickYubi      CancelSignupStage = 2
	CancelSignupPickHost      CancelSignupStage = 3
	CancelSignupLoginInstead  CancelSignupStage = 4
	CancelSignupPickYubiSlot  CancelSignupStage = 5
)

type CancelSignupError struct {
	Stage CancelSignupStage
}

func (c CancelSignupError) Error() string {
	return "signup canceled"
}

type InvalidEmailError proto.Email

func (i InvalidEmailError) Error() string {
	return "invalid email: " + string(i)
}

type NameInUseError struct{}

func (u NameInUseError) Error() string {
	return "username in use"
}

type HostInUseError struct {
	Host proto.Hostname
}

func (u HostInUseError) Error() string {
	return "host in use: " + string(u.Host)
}

type NoDefaultHostError struct{}

func (n NoDefaultHostError) Error() string {
	return "no default host"
}

type KeyInUseError struct{}

func (k KeyInUseError) Error() string {
	return "key is already in use by another user"
}

type HostKeyError string

func (h HostKeyError) Error() string {
	return "host key error: " + string(h)
}

type HostchainError string

func (h HostchainError) Error() string {
	return "hostchain error: " + string(h)
}

type LockedError struct {
	Id  []byte
	Pid int
	Age time.Duration
}

func (l LockedError) Error() string {
	return "runlock already held"
}

type HostIDNotFoundError struct{}

func (h HostIDNotFoundError) Error() string {
	return "host ID wasn't spcecified and refusing to guess"
}

type GrantError string

func (g GrantError) Error() string {
	return "grant error: " + string(g)
}

type NoChangeError string

func (n NoChangeError) Error() string {
	return "change expected but not realized: " + string(n)
}

type BadArgsError string

func (b BadArgsError) Error() string {
	return "bad arguments: " + string(b)
}

type PUKChainError string

func (p PUKChainError) Error() string {
	return "PUK chain error: " + string(p)
}

type YubiBusError struct {
	Err error
}

func (y YubiBusError) Error() string {
	return "yubikey bus error: " + y.Err.Error()
}

type YubiLockedError struct {
	Info proto.YubiKeyInfoHybrid
}

func (y YubiLockedError) Error() string {
	return "credentials are locked by Yubikey and unlocked credentials are required"
}

type BadPasswordError struct{}

func (b BadPasswordError) Error() string {
	return "bad password"
}

type SecretKeyExistsError struct{}

func (s SecretKeyExistsError) Error() string {
	return "secret key already exists"
}

type SecretKeyStorageTypeError struct {
	Actual proto.SecretKeyStorageType
}

func (s SecretKeyStorageTypeError) Error() string {
	return fmt.Sprintf("secret key storage type error: got %s",
		proto.SecretKeyStorageTypeRevMap[s.Actual],
	)
}

type BadServerDataError string

func (b BadServerDataError) Error() string {
	return "bad server data: " + string(b)
}

type NeedLoginError struct{}

func (n NeedLoginError) Error() string {
	return "need login"
}

type PassphraseError string

func (p PassphraseError) Error() string {
	return "passphrase error: " + string(p)
}

type PassphraseLockedError struct{}

func (b PassphraseLockedError) Error() string {
	return "secret key material is passphrase locked"
}

type SSOIdPLockedError struct{}

func (s SSOIdPLockedError) Error() string {
	return "account is logged out of SSO IdP"
}

type HomeError string

func (h HomeError) Error() string {
	return "home directory error: " + string(h)
}

type HostPinError proto.HostPinError

func (h HostPinError) Error() string {
	s0, _ := h.Old.StringErr()
	s1, _ := h.New.StringErr()
	return fmt.Sprintf("host pin error: %s changed from %s to %s", h.Host, s0, s1)
}

type NoActiveUserError struct{}

func (n NoActiveUserError) Error() string {
	return "no active user"
}

type AmbiguousError string

func (a AmbiguousError) Error() string {
	return string(a)
}

type RoleError string

func (r RoleError) Error() string {
	return "role error: " + string(r)
}

type TestingOnlyError struct{}

func (t TestingOnlyError) Error() string {
	return "feature only works in testing (too dangerous for prod)"
}

type RevokeRaceError struct {
	Which string
}

func (r RevokeRaceError) IsRace() bool { return true }

func (r RevokeRaceError) Error() string {
	return "race in revocation: " + string(r.Which)
}

type NonRetriableError struct{ Err error }

func (n NonRetriableError) Error() string { return n.Err.Error() }
func (n NonRetriableError) IsRace() bool  { return false }

type RPCEOFError struct{}

func (e RPCEOFError) Error() string {
	return "RPC EOF or permission denied"
}

type KeyMismatchError struct{}

func (k KeyMismatchError) Error() string {
	return "key mismatch"
}

type NetworkConditionerError struct{}

func (n NetworkConditionerError) Error() string {
	return "network conditioner error"
}

type TeamError string

func (t TeamError) Error() string {
	return "team error: " + string(t)
}

type TeamRaceError string

func (t TeamRaceError) Error() string {
	return "race in team operation: " + string(t)
}

type TeamBearerTokenStaleError struct {
	Which string
}

func (t TeamBearerTokenStaleError) Error() string {
	return "team bearer token is stale: " + t.Which
}

type TeamNotFoundError struct{}

func (t TeamNotFoundError) Error() string {
	return "team not found"
}

type TeamCertError string

func (t TeamCertError) Error() string {
	return "team cert error: " + string(t)
}

type TeamRosterError string

func (t TeamRosterError) Error() string {
	return "team roster error: " + string(t)
}

type TeamKeyError string

func (t TeamKeyError) Error() string {
	return "team key/box error: " + string(t)
}

type TeamNoSrcRoleError struct{}

func (t TeamNoSrcRoleError) Error() string {
	return "expected a src role but got NONE"
}

type TeamRemovalKeyError string

func (t TeamRemovalKeyError) Error() string {
	return "team removal key error: " + string(t)
}

type TeamInviteAlreadyAcceptedError struct{}

func (t TeamInviteAlreadyAcceptedError) Error() string {
	return "team invite already accepted"
}

type CycleError struct{}

func (c CycleError) Error() string {
	return "cycle found"
}

type TeamCycleError struct {
	proto.TeamCycleError
}

func (t TeamCycleError) Error() string {
	a := NewRationalRange(t.Joiner).StringParen()
	b := NewRationalRange(t.Joinee).StringParen()
	return fmt.Sprintf("team cycle avoidance error; cannot add team at index %s to team at index %s", a, b)
}

func NewTeamCycleError(joiner RationalRange, joinee RationalRange) TeamCycleError {
	return TeamCycleError{proto.TeamCycleError{
		Joiner: joiner.Export(),
		Joinee: joinee.Export(),
	}}
}

type TeamIndexRangeError string

func (t TeamIndexRangeError) Error() string {
	return "team index error: " + string(t)
}

type PTKNotFound struct {
	Gen  proto.Generation
	Role proto.Role
}

func (t PTKNotFound) Error() string {
	role, err := t.Role.StringErr()
	if err != nil {
		role = "n/a"
	}
	return fmt.Sprintf("PTK not found for gen=%d role=%s", t.Gen, role)
}

type TeamExploreError string

func (t TeamExploreError) Error() string {
	return "error in team explore: " + string(t)
}

func IsPermissionError(e error) bool {
	if e == nil {
		return false
	}
	_, ok := e.(PermissionError)
	return ok
}

func IsKVNoentError(e error) bool {
	if e == nil {
		return false
	}
	_, ok := e.(KVNoentError)
	return ok
}

type TooBigError struct {
	Limit  int
	Actual int
	Desc   string
}

func (t TooBigError) Error() string {
	parts := []string{"file too big"}
	if (t.Actual > 0 && t.Limit > 0) || t.Desc != "" {
		parts = append(parts, " (")
		var inner []string
		if t.Desc != "" {
			inner = append(inner, t.Desc)
		}
		if t.Actual > 0 && t.Limit > 0 {
			inner = append(inner, fmt.Sprintf("%d > %d", t.Actual, t.Limit))
		}
		parts = append(parts, strings.Join(inner, ": "))
		parts = append(parts, ")")
	}
	return strings.Join(parts, "")
}

type UploadError string

func (u UploadError) Error() string {
	return "upload failed: " + string(u)
}

type KVRaceError string

func (k KVRaceError) Error() string {
	return "KV store race: " + string(k)
}

type KVPathError string

func (k KVPathError) Error() string {
	return "path error: " + string(k)
}

type KVMkdirError string

func (k KVMkdirError) Error() string {
	return "mkdir error: " + string(k)
}

type KVExistsError struct{}

func (k KVExistsError) Error() string {
	return "node already exists"
}

type KVTypeError string

func (k KVTypeError) Error() string {
	return "KV store type error: " + string(k)
}

type KVNeedFileError struct{}
type KVNeedDirError struct{}

func (k KVNeedFileError) Error() string {
	return "needed file, got something else"
}

func (k KVNeedDirError) Error() string {
	return "needed directory, got something else"
}

type KVPermssionError struct {
	proto.KVPermError
}

func (k KVPermssionError) Error() string {
	return fmt.Sprintf("permission denied (op=%s, resource=%s)",
		proto.KVOpRevMap[k.Op],
		proto.KVNodeTypeRevMap[k.Resource],
	)
}

type KVStaleCacheError struct {
	proto.PathVersionVector
}

func (k KVStaleCacheError) Error() string {
	return "cached values were stale"
}

type KVPathTooDeepError struct{}

func (k KVPathTooDeepError) Error() string {
	return "path too deep"
}

type KVLockAlreadyHeldError struct{}

func (k KVLockAlreadyHeldError) Error() string {
	return "lock already held"
}

type KVLockTimeoutError struct{}

func (k KVLockTimeoutError) Error() string {
	return "lock timeout"
}

type KVNoentError struct {
	Path proto.KVPath
}

func (e KVNoentError) Error() string {
	var rest string
	if len(e.Path) > 0 {
		rest = ": " + string(e.Path)
	}
	return fmt.Sprintf("no such file or directory%s", rest)
}

type KVUploadInProgressError struct{}

func (k KVUploadInProgressError) Error() string {
	return "upload in progress"
}

type KVRmdirNeedRecursiveError struct{}

func (k KVRmdirNeedRecursiveError) Error() string {
	return "rmdir needs recursive flag set"
}

type KVNotAvailableError struct{}

func (k KVNotAvailableError) Error() string {
	return "KV store not available on this host"
}

type HEPKFingerprintError struct{}

func (h HEPKFingerprintError) Error() string {
	return "HEPK fingerprint mismatch"
}

type BadFormatError string

func (b BadFormatError) Error() string {
	return "bad format: " + string(b)
}

type BadRangeError struct{}

func (b BadRangeError) Error() string {
	return "invalid range (required that low <= high)"
}

type GitGenericError string

func (g GitGenericError) Error() string {
	return "git error: " + string(g)
}

type WebSessionNotFoundError struct{}

func (w WebSessionNotFoundError) Error() string {
	return "web session not found"
}

type NoActivePlanError struct{}

func (n NoActivePlanError) Error() string {
	return "no active plan for user"
}

type PlanExistsError struct{}

func (a PlanExistsError) Error() string {
	return "plan exists"
}

type OverQuotaError struct{}

func (o OverQuotaError) Error() string {
	return "over quota; plan upgrade required"
}

type OAuth2IdPError struct {
	proto.OAuth2IdPError
}

func (h OAuth2IdPError) Error() string {
	ret := fmt.Sprintf("OAuth2 IdP Error HTTP %d", h.Code)
	if h.Desc != "" {
		ret = ret + ": " + h.Desc
	}
	if h.Err != "" {
		ret = ret + " (" + h.Err + ")"
	}
	return ret
}

type HttpError struct {
	Code uint
	Err  error
	Desc string
}

func (h HttpError) Error() string {
	ret := fmt.Sprintf("HTTP %d", h.Code)
	if h.Desc != "" {
		ret = ret + ": " + h.Desc
	}
	if h.Err != nil {
		ret = ret + "; " + h.Err.Error()
	}
	return ret
}

func IsHttpError(e error) bool {
	if e == nil {
		return false
	}
	_, ok := e.(HttpError)
	return ok
}

func NewHttp422Error(e error, d string) HttpError {
	return HttpError{
		Code: 422,
		Err:  e,
		Desc: d,
	}
}

func NewHttp401Error(e error, d string) HttpError {
	return HttpError{
		Code: 401,
		Err:  e,
		Desc: d,
	}
}

func NewOAuth2IdPError(e string, d string) OAuth2IdPError {
	return OAuth2IdPError{
		proto.OAuth2IdPError{
			Code: 400,
			Err:  e,
			Desc: d,
		},
	}
}

type ExpiredError struct{}

func (e ExpiredError) Error() string {
	return "expired"
}

type StripeWrapperError struct {
	Err error
}

func (s StripeWrapperError) Error() string {
	return "stripe error: " + s.Err.Error()
}

type StripeSessionExistsError struct {
	Id infra.StripeSessionID
}

func (e StripeSessionExistsError) Error() string {
	return "stripe session exists"
}

type AutocertFailedError struct {
	Err error
}

func (e AutocertFailedError) Error() string {
	ret := "autocert failed"
	if e.Err != nil {
		ret = ret + ": " + e.Err.Error()
	}
	return ret
}

type OAuth2Error string

func (o OAuth2Error) Error() string {
	return "OAuth2 error: " + string(o)
}

type SocketError struct {
	Path Path
	Msg  string
}

func (s SocketError) Error() string {
	return "socket error: " + string(s.Msg) + " (" + string(s.Path) + ")"
}

type OAuth2TokenError struct {
	Err   error
	Which string
}

func (o OAuth2TokenError) Error() string {
	return fmt.Sprintf("error in Oauth2 %s token: %s", o.Which, o.Err.Error())
}

type OAuth2AuthError struct {
	Err error
}

func (o OAuth2AuthError) Error() string {
	return "OAuth2 auth error: " + o.Err.Error()
}

func IsSSOAuthError(err error) bool {
	if err == nil {
		return false
	}
	helper := func(e error) bool {
		if e == nil {
			return false
		}
		oerr, ok := e.(OAuth2AuthError)
		if !ok {
			return false
		}
		return errors.Is(oerr.Err, AuthError{})
	}

	if helper(err) {
		return true
	}
	cle, ok := err.(ChainLoaderError)
	if ok && helper(cle.Err) {
		return true
	}
	return false
}

func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, AuthError{}) || errors.Is(err, OAuth2AuthError{Err: AuthError{}})
}

type KeychainError string

func (k KeychainError) Error() string {
	return "keychain error: " + string(k)
}

type YubiAuthError struct {
	Retries int
}

func (y YubiAuthError) Error() string {
	return fmt.Sprintf("YubiKey authentication failed (%d retries left)", y.Retries)
}

type YubiDefaultManagementKeyError struct{}

func (y YubiDefaultManagementKeyError) Error() string {
	return "YubiKey management key is set to default value"
}

type YubiDefaultPINError struct{}

func (y YubiDefaultPINError) Error() string {
	return "YubiKey default PIN not allowed"
}

type YubiBadPINFormatError struct{}

func (y YubiBadPINFormatError) Error() string {
	return "invalid YubiKey PIN: must be 6-8 digits"
}

type YubiPINRequredError struct{}

func (y YubiPINRequredError) Error() string {
	return "YubiKey PIN is required for private key operation"
}

type AgentConnectError struct {
	Path Path
}

func (a AgentConnectError) Error() string {
	return fmt.Sprintf("failed to connect to agent at path %s", a.Path.String())
}

func ErrorToStatus(e error) proto.Status {

	switch {
	case e == nil:
		return proto.NewStatusWithOk()
	case e == context.Canceled:
		return proto.NewStatusWithContextCanceledError()
	}

	switch te := e.(type) {
	case rpc.ProtocolV2NotFoundError:
		return proto.NewStatusWithProtoNotFoundError(uint64(te.U))
	case rpc.MethodV2NotFoundError:
		return proto.NewStatusWithMethodNotFoundError(
			proto.MethodV2{
				Proto:  uint64(te.ProtID),
				Name:   te.ProtName,
				Method: uint64(te.Method),
			},
		)
	case TLSError:
		return proto.NewStatusWithTlsError(string(te))
	case ConnectError:
		return proto.NewStatusWithConnectError(proto.ConnectError{
			Desc: te.Desc,
			Err:  ErrorToStatus(te.Err),
		})
	case HttpError:
		return proto.NewStatusWithHttpError(proto.HttpError{
			Code: uint64(te.Code),
			Desc: te.Desc,
			Err:  ErrorToStatus(te.Err),
		})
	case OAuth2IdPError:
		return proto.NewStatusWithOauth2IdpError(te.OAuth2IdPError)
	case SocketError:
		return proto.NewStatusWithSocketError(proto.SocketError{
			Path: te.Path.String(),
			Msg:  te.Msg,
		})
	case OAuth2TokenError:
		return proto.NewStatusWithOauth2TokenError(proto.OAuth2TokenError{
			Which: te.Which,
			Err:   ErrorToStatus(te.Err),
		})
	case OAuth2AuthError:
		return proto.NewStatusWithOauth2AuthError(ErrorToStatus(te.Err))
	case NetworkConditionerError:
		return proto.NewStatusWithNetworkConditionerError()
	case VersionNotSupportedError:
		return proto.NewStatusWithVersionNotSupportedError(string(te))
	case ConfigError:
		return proto.NewStatusWithConfigError(string(te))
	case DuplicateError:
		return proto.NewStatusWithDuplicateError(string(te))
	case ReservationError:
		return proto.NewStatusWithReservationError(string(te))
	case LinkError:
		return proto.NewStatusWithLinkError(string(te))
	case ValidationError:
		return proto.NewStatusWithValidationError(string(te))
	case VerifyError:
		return proto.NewStatusWithVerifyError(string(te))
	case AuthError:
		return proto.NewStatusWithAuthError()
	case DeviceAlreadyProvisionedError:
		return proto.NewStatusWithDeviceAlreadyProvisionedError()
	case X509Error:
		return proto.NewStatusWithX509Error(string(te))
	case InsertError:
		return proto.NewStatusWithInsertError(string(te))
	case TimeoutError:
		return proto.NewStatusWithTimeoutError()
	case ReplayError:
		return proto.NewStatusWithReplayError()
	case BadPassphraseError:
		return proto.NewStatusWithBadPassphraseError()
	case PassphraseNotFoundError:
		return proto.NewStatusWithPassphraseNotFoundError()
	case RateLimitError:
		return proto.NewStatusWithRateLimitError()
	case PermissionError:
		return proto.NewStatusWithPermissionError(string(te))
	case TxRetryError:
		return proto.NewStatusWithTxRetryError()
	case PrevError:
		return proto.NewStatusWithPrevError(string(te))
	case BoxError:
		return proto.NewStatusWithBoxError(string(te))
	case UpdateError:
		return proto.NewStatusWithUpdateError(string(te))
	case RevokeError:
		return proto.NewStatusWithRevokeError(string(te))
	case CommitmentError:
		return proto.NewStatusWithCommitmentError(string(te))
	case WrongUserError:
		return proto.NewStatusWithWrongUserError()
	case KexWrapperError:
		return proto.NewStatusWithKexWrapperError(ErrorToStatus(te.Err))
	case AutocertFailedError:
		return proto.NewStatusWithAutocertFailedError(ErrorToStatus(te.Err))
	case OAuth2Error:
		return proto.NewStatusWithOauth2Error(string(te))
	case BadInviteCodeError:
		return proto.NewStatusWithBadInviteCodeError()
	case NotImplementedError:
		return proto.NewStatusWithNotImplemented()
	case SessionNotFoundError:
		return proto.NewStatusWithSessionNotFoundError(proto.UISessionID(te))
	case YubiError:
		return proto.NewStatusWithYubiError(string(te))
	case KeychainError:
		return proto.NewStatusWithKeychainError(string(te))
	case YubiBusError:
		return proto.NewStatusWithYubiBusError(string(te.Err.Error()))
	case YubiAuthError:
		return proto.NewStatusWithYubiAuthError(int64(te.Retries))
	case YubiDefaultManagementKeyError:
		return proto.NewStatusWithYubiDefaultManagementKeyError()
	case YubiDefaultPINError:
		return proto.NewStatusWithYubiDefaultPinError()
	case YubiBadPINFormatError:
		return proto.NewStatusWithYubiBadPinFormatError()
	case YubiPINRequredError:
		return proto.NewStatusWithYubiPinRequiredError()
	case NameInUseError:
		return proto.NewStatusWithUsernameInUseError()
	case HostInUseError:
		return proto.NewStatusWithHostInUseError(te.Host.String())
	case MerkleNoRootError:
		return proto.NewStatusWithMerkleNoRootError()
	case MerkleLeafNotFoundError:
		return proto.NewStatusWithMerkleLeafNotFoundError()
	case NoDefaultHostError:
		return proto.NewStatusWithNoDefaultHostError()
	case KeyNotFoundError:
		return proto.NewStatusWithKeyNotFoundError(te.Which)
	case KeyInUseError:
		return proto.NewStatusWithKeyInUseError()
	case HostchainError:
		return proto.NewStatusWithHostchainError(string(te))
	case UserNotFoundError:
		return proto.NewStatusWithUserNotFoundError()
	case RowNotFoundError:
		return proto.NewStatusWithRowNotFoundError()
	case KexBadSecretError:
		return proto.NewStatusWithKexBadSecret()
	case GrantError:
		return proto.NewStatusWithGrantError(string(te))
	case NoChangeError:
		return proto.NewStatusWithNoChangeError(string(te))
	case BadArgsError:
		return proto.NewStatusWithBadArgsError(string(te))
	case YubiLockedError:
		return proto.NewStatusWithYubiLockedError(te.Info)
	case PassphraseLockedError:
		return proto.NewStatusWithPassphraseLockedError()
	case SSOIdPLockedError:
		return proto.NewStatusWithSsoIdpLockedError()
	case proto.DataError:
		return proto.NewStatusWithProtoDataError(string(te))
	case HostMismatchError:
		return proto.NewStatusWithHostMismatchError(string(te.Which))
	case HostPinError:
		return proto.NewStatusWithHostPinError(proto.HostPinError(te))
	case NoActiveUserError:
		return proto.NewStatusWithNoActiveUserError()
	case AmbiguousError:
		return proto.NewStatusWithAmbiguousError(string(te))
	case RoleError:
		return proto.NewStatusWithRoleError(string(te))
	case CanceledInputError:
		return proto.NewStatusWithCanceledInputError()
	case BadFormatError:
		return proto.NewStatusWithBadFormatError(string(te))
	case BadRangeError:
		return proto.NewStatusWithBadRangeError()
	case DNSError:
		return proto.NewStatusWithDnsError(proto.DNSError{
			Stage: te.Stage,
			Err:   ErrorToStatus(te.Err),
		})
	case TestingOnlyError:
		return proto.NewStatusWithTestingOnlyError()
	case RevokeRaceError:
		return proto.NewStatusWithRevokeRaceError(string(te.Which))
	case MerkleVerifyError:
		return proto.NewStatusWithMerkleVerifyError(string(te))
	case SecretKeyStorageTypeError:
		return proto.NewStatusWithSecretKeyStorageTypeError(te.Actual)
	case SigningKeyNotFullyProvisionedError:
		return proto.NewStatusWithSigningKeyNotFullyProvisionedError()
	case AgentConnectError:
		return proto.NewStatusWithAgentConnectError(te.Path.String())
	case RPCEOFError:
		return proto.NewStatusWithRpcEof()
	case OverQuotaError:
		return proto.NewStatusWithOverQuotaError()
	case NoActivePlanError:
		return proto.NewStatusWithNoActivePlanError()
	case ExpiredError:
		return proto.NewStatusWithExpiredError()
	case PlanExistsError:
		return proto.NewStatusWithPlanExistsError()
	case TeamError:
		return proto.NewStatusWithTeamError(string(te))
	case TeamRaceError:
		return proto.NewStatusWithTeamRaceError(string(te))
	case TeamBearerTokenStaleError:
		return proto.NewStatusWithTeamBearerTokenStaleError(te.Which)
	case TeamNotFoundError:
		return proto.NewStatusWithTeamNotFoundError()
	case TeamCertError:
		return proto.NewStatusWithTeamCertError(string(te))
	case TeamRosterError:
		return proto.NewStatusWithTeamRosterError(string(te))
	case TeamKeyError:
		return proto.NewStatusWithTeamKeyError(string(te))
	case TeamNoSrcRoleError:
		return proto.NewStatusWithTeamNoSrcRoleError()
	case TeamRemovalKeyError:
		return proto.NewStatusWithTeamRemovalKeyError(string(te))
	case TeamInviteAlreadyAcceptedError:
		return proto.NewStatusWithTeamInviteAlreadyAcceptedError()
	case TeamExploreError:
		return proto.NewStatusWithTeamExploreError(string(te))
	case TeamCycleError:
		return proto.NewStatusWithTeamCycleError(te.TeamCycleError)
	case TeamIndexRangeError:
		return proto.NewStatusWithTeamIndexRangeError(string(te))
	case NeedLoginError:
		return proto.NewStatusWithNeedLoginError()
	case HostIDNotFoundError:
		return proto.NewStatusWithHostidNotFoundError()
	case NotFoundError:
		return proto.NewStatusWithGenericNotFoundError(string(te))
	case WebSessionNotFoundError:
		return proto.NewStatusWithWebSessionNotFoundError()
	case TooBigError:
		return proto.NewStatusWithKvTooBigError(
			proto.TooBigError{
				Limit:  uint64(te.Limit),
				Actual: uint64(te.Actual),
				Desc:   te.Desc,
			},
		)
	case UploadError:
		return proto.NewStatusWithKvUploadError(string(te))
	case KVRaceError:
		return proto.NewStatusWithKvRaceError(string(te))
	case KVPathError:
		return proto.NewStatusWithKvPathError(string(te))
	case KVMkdirError:
		return proto.NewStatusWithKvMkdirError(string(te))
	case KVExistsError:
		return proto.NewStatusWithKvExistsError()
	case KVTypeError:
		return proto.NewStatusWithKvTypeError(string(te))
	case KVNeedFileError:
		return proto.NewStatusWithKvNeedFileError()
	case KVNeedDirError:
		return proto.NewStatusWithKvNeedDirError()
	case KVPermssionError:
		return proto.NewStatusWithKvPermError(te.KVPermError)
	case KVStaleCacheError:
		return proto.NewStatusWithKvStaleCacheError(te.PathVersionVector)
	case KVPathTooDeepError:
		return proto.NewStatusWithKvPathTooDeepError()
	case KVLockAlreadyHeldError:
		return proto.NewStatusWithKvLockAlreadyHeldError()
	case KVLockTimeoutError:
		return proto.NewStatusWithKvLockTimeoutError()
	case KVNoentError:
		return proto.NewStatusWithKvNoentError(string(te.Path))
	case KVUploadInProgressError:
		return proto.NewStatusWithKvUploadInProgressError()
	case KVRmdirNeedRecursiveError:
		return proto.NewStatusWithKvRmdirNeedRecursiveError()
	case KVNotAvailableError:
		return proto.NewStatusWithKvNotAvailableError()
	case StripeSessionExistsError:
		return proto.NewStatusWithStripeSessionExistsError()
	case NonRetriableError:
		return ErrorToStatus(te.Err)
	case GitGenericError:
		return proto.NewStatusWithGitGenericError(string(te))
	case remhelp.BadGitPathError:
		return proto.NewStatusWithGitBadPathError(string(te.Path))
	case PTKNotFound:
		return proto.NewStatusWithTeamPtkNotFoundError(
			proto.SharedKeyNotFound{
				Gen:  te.Gen,
				Role: te.Role,
			},
		)
	case ChainLoaderError:
		return proto.NewStatusWithChainLoaderError(proto.ChainLoaderError{
			Err:  ErrorToStatus(te.Err),
			Race: te.Race,
		})

	default:
		return proto.NewStatusDefault(proto.StatusCode_GENERIC_ERROR, te.Error())
	}
}

func StatusToError(s proto.Status) error {
	sc, err := s.GetSc()
	if err != nil {
		return err
	}
	switch sc {
	case proto.StatusCode_OK:
		return nil
	case proto.StatusCode_CONFIG_ERROR:
		return errors.New(s.ConfigError())
	case proto.StatusCode_TLS_ERROR:
		return errors.New(s.TlsError())
	case proto.StatusCode_DUPLICATE_ERROR:
		return DuplicateError(s.DuplicateError())
	case proto.StatusCode_CONNECT_ERROR:
		return ConnectError{
			Desc: s.ConnectError().Desc,
			Err:  StatusToError(s.ConnectError().Err),
		}
	case proto.StatusCode_HTTP_ERROR:
		return HttpError{
			Desc: s.HttpError().Desc,
			Err:  StatusToError(s.HttpError().Err),
			Code: uint(s.HttpError().Code),
		}
	case proto.StatusCode_OAUTH2_IDP_ERROR:
		return OAuth2IdPError{
			OAuth2IdPError: s.Oauth2IdpError(),
		}
	case proto.StatusCode_NETWORK_CONDITIONER_ERROR:
		return NetworkConditionerError{}
	case proto.StatusCode_SOCKET_ERROR:
		return SocketError{
			Path: Path(s.SocketError().Path),
			Msg:  s.SocketError().Msg,
		}
	case proto.StatusCode_OAUTH2_TOKEN_ERROR:
		return OAuth2TokenError{
			Which: s.Oauth2TokenError().Which,
			Err:   StatusToError(s.Oauth2TokenError().Err),
		}
	case proto.StatusCode_OAUTH2_AUTH_ERROR:
		return OAuth2AuthError{Err: StatusToError(s.Oauth2AuthError())}
	case proto.StatusCode_PROTO_NOT_FOUND_ERROR:
		return rpc.NewProtocolV2NotFoundError(rpc.ProtocolUniqueID(s.ProtoNotFoundError()))
	case proto.StatusCode_RESERVATION_ERROR:
		return ReservationError(s.ReservationError())
	case proto.StatusCode_LINK_ERROR:
		return LinkError(s.LinkError())
	case proto.StatusCode_VALIDATION_ERROR:
		return ValidationError(s.ValidationError())
	case proto.StatusCode_VERIFY_ERROR:
		return VerifyError(s.VerifyError())
	case proto.StatusCode_AUTH_ERROR:
		return AuthError{}
	case proto.StatusCode_DEVICE_ALREADY_PROVISIONED_ERROR:
		return DeviceAlreadyProvisionedError{}
	case proto.StatusCode_X509_ERROR:
		return X509Error(s.X509Error())
	case proto.StatusCode_METHOD_NOT_FOUND_ERROR:
		tmp := s.MethodNotFoundError()
		return rpc.NewMethodV2NotFoundError(
			rpc.ProtocolUniqueID(tmp.Proto),
			rpc.Position(tmp.Method),
			tmp.Name,
		)
	case proto.StatusCode_INSERT_ERROR:
		return InsertError(s.InsertError())
	case proto.StatusCode_TIMEOUT_ERROR:
		return TimeoutError{}
	case proto.StatusCode_REPLAY_ERROR:
		return ReplayError{}
	case proto.StatusCode_KEYCHAIN_ERROR:
		return KeychainError(s.KeychainError())
	case proto.StatusCode_YUBI_AUTH_ERROR:
		return YubiAuthError{Retries: int(s.YubiAuthError())}
	case proto.StatusCode_YUBI_DEFAULT_MANAGEMENT_KEY_ERROR:
		return YubiDefaultManagementKeyError{}
	case proto.StatusCode_YUBI_DEFAULT_PIN_ERROR:
		return YubiDefaultPINError{}
	case proto.StatusCode_YUBI_BAD_PIN_FORMAT_ERROR:
		return YubiBadPINFormatError{}
	case proto.StatusCode_YUBI_PIN_REQUIRED_ERROR:
		return YubiPINRequredError{}
	case proto.StatusCode_BAD_PASSPHRASE_ERROR:
		return BadPassphraseError{}
	case proto.StatusCode_SSO_IDP_LOCKED_ERROR:
		return SSOIdPLockedError{}
	case proto.StatusCode_PASSPHRASE_NOT_FOUND_ERROR:
		return PassphraseNotFoundError{}
	case proto.StatusCode_RATE_LIMIT_ERROR:
		return RateLimitError{}
	case proto.StatusCode_PERMISSION_ERROR:
		return PermissionError(s.PermissionError())
	case proto.StatusCode_TX_RETRY_ERROR:
		return TxRetryError{}
	case proto.StatusCode_PREV_ERROR:
		return PrevError(s.PrevError())
	case proto.StatusCode_BOX_ERROR:
		return BoxError(s.BoxError())
	case proto.StatusCode_UPDATE_ERROR:
		return UpdateError(s.UpdateError())
	case proto.StatusCode_REVOKE_ERROR:
		return RevokeError(s.RevokeError())
	case proto.StatusCode_COMMITMENT_ERROR:
		return CommitmentError(s.CommitmentError())
	case proto.StatusCode_WRONG_USER_ERROR:
		return WrongUserError{}
	case proto.StatusCode_BAD_INVITE_CODE_ERROR:
		return BadInviteCodeError{}
	case proto.StatusCode_KEX_WRAPPER_ERROR:
		status := s.KexWrapperError()
		return KexWrapperError{Err: StatusToError(status)}
	case proto.StatusCode_AUTOCERT_FAILED_ERROR:
		status := s.AutocertFailedError()
		return AutocertFailedError{Err: StatusToError(status)}
	case proto.StatusCode_OAUTH2_ERROR:
		return OAuth2Error(s.Oauth2Error())
	case proto.StatusCode_NOT_IMPLEMENTED:
		return NotImplementedError{}
	case proto.StatusCode_SESSION_NOT_FOUND_ERROR:
		return SessionNotFoundError(s.SessionNotFoundError())
	case proto.StatusCode_YUBI_ERROR:
		return YubiError(s.YubiError())
	case proto.StatusCode_YUBI_BUS_ERROR:
		return YubiBusError{Err: errors.New(s.YubiBusError())}
	case proto.StatusCode_USERNAME_IN_USE_ERROR:
		return NameInUseError{}
	case proto.StatusCode_HOST_IN_USE_ERROR:
		return HostInUseError{Host: proto.Hostname(s.HostInUseError())}
	case proto.StatusCode_MERKLE_NO_ROOT_ERROR:
		return MerkleNoRootError{}
	case proto.StatusCode_MERKLE_LEAF_NOT_FOUND_ERROR:
		return MerkleLeafNotFoundError{}
	case proto.StatusCode_NO_DEFAULT_HOST_ERROR:
		return NoDefaultHostError{}
	case proto.StatusCode_KEY_NOT_FOUND_ERROR:
		return KeyNotFoundError{Which: s.KeyNotFoundError()}
	case proto.StatusCode_KEY_IN_USE_ERROR:
		return KeyInUseError{}
	case proto.StatusCode_HOSTCHAIN_ERROR:
		return HostchainError(s.HostchainError())
	case proto.StatusCode_USER_NOT_FOUND_ERROR:
		return UserNotFoundError{}
	case proto.StatusCode_ROW_NOT_FOUND_ERROR:
		return RowNotFoundError{}
	case proto.StatusCode_KEX_BAD_SECRET:
		return KexBadSecretError{}
	case proto.StatusCode_GRANT_ERROR:
		return GrantError(s.GrantError())
	case proto.StatusCode_NO_CHANGE_ERROR:
		return NoChangeError(s.NoChangeError())
	case proto.StatusCode_BAD_ARGS_ERROR:
		return BadArgsError(s.BadArgsError())
	case proto.StatusCode_PASSPHRASE_LOCKED_ERROR:
		return PassphraseLockedError{}
	case proto.StatusCode_YUBI_LOCKED_ERROR:
		return YubiLockedError{Info: s.YubiLockedError()}
	case proto.StatusCode_PROTO_DATA_ERROR:
		return proto.DataError(s.ProtoDataError())
	case proto.StatusCode_HOST_MISMATCH_ERROR:
		return HostMismatchError{Which: s.HostMismatchError()}
	case proto.StatusCode_HOST_PIN_ERROR:
		return HostPinError(s.HostPinError())
	case proto.StatusCode_NO_ACTIVE_USER_ERROR:
		return NoActiveUserError{}
	case proto.StatusCode_AMBIGUOUS_ERROR:
		return AmbiguousError(s.AmbiguousError())
	case proto.StatusCode_ROLE_ERROR:
		return RoleError(s.RoleError())
	case proto.StatusCode_CANCELED_INPUT_ERROR:
		return CanceledInputError{}
	case proto.StatusCode_DNS_ERROR:
		{
			dnse := s.DnsError()
			return DNSError{Stage: dnse.Stage, Err: StatusToError(dnse.Err)}
		}
	case proto.StatusCode_CONTEXT_CANCELED_ERROR:
		return context.Canceled
	case proto.StatusCode_BAD_FORMAT_ERROR:
		return BadFormatError(s.BadFormatError())
	case proto.StatusCode_BAD_RANGE_ERROR:
		return BadRangeError{}
	case proto.StatusCode_TESTING_ONLY_ERROR:
		return TestingOnlyError{}
	case proto.StatusCode_REVOKE_RACE_ERROR:
		return RevokeRaceError{Which: s.RevokeRaceError()}
	case proto.StatusCode_MERKLE_VERIFY_ERROR:
		return MerkleVerifyError(s.MerkleVerifyError())
	case proto.StatusCode_SECRET_KEY_STORAGE_TYPE_ERROR:
		return SecretKeyStorageTypeError{Actual: s.SecretKeyStorageTypeError()}
	case proto.StatusCode_RPC_EOF:
		return RPCEOFError{}
	case proto.StatusCode_SIGNING_KEY_NOT_FULLY_PROVISIONED_ERROR:
		return SigningKeyNotFullyProvisionedError{}
	case proto.StatusCode_AGENT_CONNECT_ERROR:
		return AgentConnectError{Path: Path(s.AgentConnectError())}
	case proto.StatusCode_NO_ACTIVE_PLAN_ERROR:
		return NoActivePlanError{}
	case proto.StatusCode_EXPIRED_ERROR:
		return ExpiredError{}
	case proto.StatusCode_PLAN_EXISTS_ERROR:
		return PlanExistsError{}
	case proto.StatusCode_OVER_QUOTA_ERROR:
		return OverQuotaError{}
	case proto.StatusCode_TEAM_ERROR:
		return TeamError(s.TeamError())
	case proto.StatusCode_TEAM_RACE_ERROR:
		return TeamRaceError(s.TeamRaceError())
	case proto.StatusCode_TEAM_BEARER_TOKEN_STALE_ERROR:
		return TeamBearerTokenStaleError{Which: s.TeamBearerTokenStaleError()}
	case proto.StatusCode_TEAM_NOT_FOUND_ERROR:
		return TeamNotFoundError{}
	case proto.StatusCode_TEAM_CERT_ERROR:
		return TeamCertError(s.TeamCertError())
	case proto.StatusCode_TEAM_ROSTER_ERROR:
		return TeamRosterError(s.TeamRosterError())
	case proto.StatusCode_TEAM_KEY_ERROR:
		return TeamKeyError(s.TeamKeyError())
	case proto.StatusCode_TEAM_NO_SRC_ROLE_ERROR:
		return TeamNoSrcRoleError{}
	case proto.StatusCode_TEAM_REMOVAL_KEY_ERROR:
		return TeamRemovalKeyError(s.TeamRemovalKeyError())
	case proto.StatusCode_TEAM_INVITE_ALREADY_ACCEPTED_ERROR:
		return TeamInviteAlreadyAcceptedError{}
	case proto.StatusCode_TEAM_EXPLORE_ERROR:
		return TeamExploreError(s.TeamExploreError())
	case proto.StatusCode_TEAM_CYCLE_ERROR:
		return TeamCycleError{TeamCycleError: s.TeamCycleError()}
	case proto.StatusCode_TEAM_INDEX_RANGE_ERROR:
		return TeamIndexRangeError(s.TeamIndexRangeError())
	case proto.StatusCode_NEED_LOGIN_ERROR:
		return NeedLoginError{}
	case proto.StatusCode_HOSTID_NOT_FOUND_ERROR:
		return HostIDNotFoundError{}
	case proto.StatusCode_GENERIC_NOT_FOUND_ERROR:
		return NotFoundError(s.GenericNotFoundError())
	case proto.StatusCode_WEB_SESSION_NOT_FOUND_ERROR:
		return WebSessionNotFoundError{}
	case proto.StatusCode_TEAM_PTK_NOT_FOUND_ERROR:
		return PTKNotFound{
			Gen:  s.TeamPtkNotFoundError().Gen,
			Role: s.TeamPtkNotFoundError().Role,
		}
	case proto.StatusCode_KV_TOO_BIG_ERROR:
		tbe := s.KvTooBigError()
		return TooBigError{
			Limit:  int(tbe.Limit),
			Actual: int(tbe.Actual),
			Desc:   tbe.Desc,
		}
	case proto.StatusCode_KV_UPLOAD_ERROR:
		return UploadError(s.KvUploadError())
	case proto.StatusCode_KV_RACE_ERROR:
		return KVRaceError(s.KvRaceError())
	case proto.StatusCode_KV_PATH_ERROR:
		return errors.New(s.KvPathError())
	case proto.StatusCode_KV_MKDIR_ERROR:
		return KVMkdirError(s.KvMkdirError())
	case proto.StatusCode_KV_EXISTS_ERROR:
		return KVExistsError{}
	case proto.StatusCode_KV_TYPE_ERROR:
		return KVTypeError(s.KvTypeError())
	case proto.StatusCode_KV_NEED_FILE_ERROR:
		return KVNeedFileError{}
	case proto.StatusCode_KV_NEED_DIR_ERROR:
		return KVNeedDirError{}
	case proto.StatusCode_KV_PERM_ERROR:
		return KVPermssionError{KVPermError: s.KvPermError()}
	case proto.StatusCode_KV_STALE_CACHE_ERROR:
		return KVStaleCacheError{s.KvStaleCacheError()}
	case proto.StatusCode_KV_PATH_TOO_DEEP_ERROR:
		return KVPathTooDeepError{}
	case proto.StatusCode_KV_LOCK_ALREADY_HELD_ERROR:
		return KVLockAlreadyHeldError{}
	case proto.StatusCode_KV_LOCK_TIMEOUT_ERROR:
		return KVLockTimeoutError{}
	case proto.StatusCode_KV_NOENT_ERROR:
		return KVNoentError{Path: proto.KVPath(s.KvNoentError())}
	case proto.StatusCode_KV_UPLOAD_IN_PROGRESS_ERROR:
		return KVUploadInProgressError{}
	case proto.StatusCode_KV_RMDIR_NEED_RECURSIVE_ERROR:
		return KVRmdirNeedRecursiveError{}
	case proto.StatusCode_KV_NOT_AVAILABLE_ERROR:
		return KVNotAvailableError{}
	case proto.StatusCode_STRIPE_SESSION_EXISTS_ERROR:
		return StripeSessionExistsError{}
	case proto.StatusCode_CHAIN_LOADER_ERROR:
		cle := s.ChainLoaderError()
		return ChainLoaderError{
			Err:  StatusToError(cle.Err),
			Race: cle.Race,
		}
	case proto.StatusCode_GIT_GENERIC_ERROR:
		return GitGenericError(s.GitGenericError())
	case proto.StatusCode_GIT_BAD_PATH_ERROR:
		return remhelp.BadGitPathError{
			Path: remhelp.LocalPath(s.GitBadPathError()),
		}
	case proto.StatusCode_VERSION_NOT_SUPPORTED_ERROR:
		return VersionNotSupportedError(s.VersionNotSupportedError())
	default:
		return errors.New(s.Default())
	}
}
