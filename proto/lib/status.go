// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/status.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type StatusCode int

const (
	StatusCode_OK                                      StatusCode = 0
	StatusCode_GENERIC_ERROR                           StatusCode = 100
	StatusCode_CONFIG_ERROR                            StatusCode = 101
	StatusCode_TLS_ERROR                               StatusCode = 200
	StatusCode_PROTO_NOT_FOUND_ERROR                   StatusCode = 210
	StatusCode_METHOD_NOT_FOUND_ERROR                  StatusCode = 211
	StatusCode_DUPLICATE_ERROR                         StatusCode = 1001
	StatusCode_RESERVATION_ERROR                       StatusCode = 1002
	StatusCode_LINK_ERROR                              StatusCode = 1003
	StatusCode_VALIDATION_ERROR                        StatusCode = 1004
	StatusCode_VERIFY_ERROR                            StatusCode = 1005
	StatusCode_AUTH_ERROR                              StatusCode = 1006
	StatusCode_X509_ERROR                              StatusCode = 1007
	StatusCode_BOX_ERROR                               StatusCode = 1008
	StatusCode_TIMEOUT_ERROR                           StatusCode = 1009
	StatusCode_REPLAY_ERROR                            StatusCode = 1010
	StatusCode_BAD_PASSPHRASE_ERROR                    StatusCode = 1011
	StatusCode_RATE_LIMIT_ERROR                        StatusCode = 1012
	StatusCode_PERMISSION_ERROR                        StatusCode = 1013
	StatusCode_TX_RETRY_ERROR                          StatusCode = 1014
	StatusCode_PREV_ERROR                              StatusCode = 1015
	StatusCode_REVOKE_ERROR                            StatusCode = 1016
	StatusCode_COMMITMENT_ERROR                        StatusCode = 1017
	StatusCode_WRONG_USER_ERROR                        StatusCode = 1018
	StatusCode_BAD_INVITE_CODE_ERROR                   StatusCode = 1019
	StatusCode_NOT_IMPLEMENTED                         StatusCode = 1020
	StatusCode_SESSION_NOT_FOUND_ERROR                 StatusCode = 1021
	StatusCode_YUBI_ERROR                              StatusCode = 1022
	StatusCode_USERNAME_IN_USE_ERROR                   StatusCode = 1023
	StatusCode_NO_DEFAULT_HOST_ERROR                   StatusCode = 1024
	StatusCode_KEY_NOT_FOUND_ERROR                     StatusCode = 1025
	StatusCode_KEY_IN_USE_ERROR                        StatusCode = 1026
	StatusCode_USER_NOT_FOUND_ERROR                    StatusCode = 1027
	StatusCode_GRANT_ERROR                             StatusCode = 1028
	StatusCode_NO_CHANGE_ERROR                         StatusCode = 1029
	StatusCode_BAD_ARGS_ERROR                          StatusCode = 1030
	StatusCode_ROW_NOT_FOUND_ERROR                     StatusCode = 1031
	StatusCode_KEX_BAD_SECRET                          StatusCode = 1032
	StatusCode_YUBI_LOCKED_ERROR                       StatusCode = 1033
	StatusCode_PASSPHRASE_LOCKED_ERROR                 StatusCode = 1034
	StatusCode_PROTO_DATA_ERROR                        StatusCode = 1035
	StatusCode_HOST_MISMATCH_ERROR                     StatusCode = 1036
	StatusCode_HOST_PIN_ERROR                          StatusCode = 1037
	StatusCode_NO_ACTIVE_USER_ERROR                    StatusCode = 1038
	StatusCode_AMBIGUOUS_ERROR                         StatusCode = 1039
	StatusCode_ROLE_ERROR                              StatusCode = 1040
	StatusCode_CANCELED_INPUT_ERROR                    StatusCode = 1041
	StatusCode_TESTING_ONLY_ERROR                      StatusCode = 1042
	StatusCode_PASSPHRASE_NOT_FOUND_ERROR              StatusCode = 1043
	StatusCode_REVOKE_RACE_ERROR                       StatusCode = 1044
	StatusCode_SECRET_KEY_STORAGE_TYPE_ERROR           StatusCode = 1045
	StatusCode_RPC_EOF                                 StatusCode = 1046
	StatusCode_NEED_LOGIN_ERROR                        StatusCode = 1047
	StatusCode_HOSTID_NOT_FOUND_ERROR                  StatusCode = 1048
	StatusCode_GENERIC_NOT_FOUND_ERROR                 StatusCode = 1049
	StatusCode_BAD_FORMAT_ERROR                        StatusCode = 1050
	StatusCode_BAD_RANGE_ERROR                         StatusCode = 1051
	StatusCode_SIGNING_KEY_NOT_FULLY_PROVISIONED_ERROR StatusCode = 1052
	StatusCode_UPGRADE_NEEDED_ERROR                    StatusCode = 1053
	StatusCode_VERSION_NOT_SUPPORTED_ERROR             StatusCode = 1054
	StatusCode_CONTEXT_CANCELED_ERROR                  StatusCode = 1055
	StatusCode_CONNECT_ERROR                           StatusCode = 1056
	StatusCode_NETWORK_CONDITIONER_ERROR               StatusCode = 1057
	StatusCode_WEB_SESSION_NOT_FOUND_ERROR             StatusCode = 1058
	StatusCode_NO_ACTIVE_PLAN_ERROR                    StatusCode = 1059
	StatusCode_OVER_QUOTA_ERROR                        StatusCode = 1060
	StatusCode_PLAN_EXISTS_ERROR                       StatusCode = 1061
	StatusCode_EXPIRED_ERROR                           StatusCode = 1062
	StatusCode_HOST_IN_USE_ERROR                       StatusCode = 1063
	StatusCode_DNS_ERROR                               StatusCode = 1064
	StatusCode_AUTOCERT_FAILED_ERROR                   StatusCode = 1065
	StatusCode_SOCKET_ERROR                            StatusCode = 1066
	StatusCode_OAUTH2_ERROR                            StatusCode = 1067
	StatusCode_OAUTH2_TOKEN_ERROR                      StatusCode = 1068
	StatusCode_OAUTH2_AUTH_ERROR                       StatusCode = 1069
	StatusCode_OAUTH2_IDP_ERROR                        StatusCode = 1070
	StatusCode_SSO_IDP_LOCKED_ERROR                    StatusCode = 1071
	StatusCode_DEVICE_ALREADY_PROVISIONED_ERROR        StatusCode = 1072
	StatusCode_YUBI_BUS_ERROR                          StatusCode = 1073
	StatusCode_KEYCHAIN_ERROR                          StatusCode = 1074
	StatusCode_YUBI_AUTH_ERROR                         StatusCode = 1075
	StatusCode_YUBI_DEFAULT_MANAGEMENT_KEY_ERROR       StatusCode = 1076
	StatusCode_YUBI_BAD_PIN_FORMAT_ERROR               StatusCode = 1077
	StatusCode_YUBI_PIN_REQUIRED_ERROR                 StatusCode = 1078
	StatusCode_YUBI_DEFAULT_PIN_ERROR                  StatusCode = 1079
	StatusCode_AGENT_CONNECT_ERROR                     StatusCode = 1080
	StatusCode_INSERT_ERROR                            StatusCode = 2001
	StatusCode_UPDATE_ERROR                            StatusCode = 2002
	StatusCode_KEX_WRAPPER_ERROR                       StatusCode = 3001
	StatusCode_MERKLE_NO_ROOT_ERROR                    StatusCode = 4001
	StatusCode_MERKLE_LEAF_NOT_FOUND_ERROR             StatusCode = 4002
	StatusCode_MERKLE_VERIFY_ERROR                     StatusCode = 4003
	StatusCode_HOSTCHAIN_ERROR                         StatusCode = 5001
	StatusCode_CHAIN_LOADER_ERROR                      StatusCode = 6001
	StatusCode_TEAM_ERROR                              StatusCode = 7001
	StatusCode_TEAM_RACE_ERROR                         StatusCode = 7002
	StatusCode_TEAM_BEARER_TOKEN_STALE_ERROR           StatusCode = 7003
	StatusCode_TEAM_NOT_FOUND_ERROR                    StatusCode = 7004
	StatusCode_TEAM_CERT_ERROR                         StatusCode = 7005
	StatusCode_TEAM_ROSTER_ERROR                       StatusCode = 7006
	StatusCode_TEAM_KEY_ERROR                          StatusCode = 7007
	StatusCode_TEAM_NO_SRC_ROLE_ERROR                  StatusCode = 7008
	StatusCode_TEAM_REMOVAL_KEY_ERROR                  StatusCode = 7009
	StatusCode_TEAM_EXPLORE_ERROR                      StatusCode = 7010
	StatusCode_TEAM_PTK_NOT_FOUND_ERROR                StatusCode = 7011
	StatusCode_TEAM_CYCLE_ERROR                        StatusCode = 7012
	StatusCode_TEAM_INDEX_RANGE_ERROR                  StatusCode = 7013
	StatusCode_TEAM_BAD_INBOX_ROW_ERROR                StatusCode = 7014
	StatusCode_TEAM_INVITE_ALREADY_ACCEPTED_ERROR      StatusCode = 7015
	StatusCode_KV_TOO_BIG_ERROR                        StatusCode = 8001
	StatusCode_KV_UPLOAD_ERROR                         StatusCode = 8002
	StatusCode_KV_RACE_ERROR                           StatusCode = 8003
	StatusCode_KV_PATH_ERROR                           StatusCode = 8005
	StatusCode_KV_MKDIR_ERROR                          StatusCode = 8006
	StatusCode_KV_EXISTS_ERROR                         StatusCode = 8007
	StatusCode_KV_TYPE_ERROR                           StatusCode = 8008
	StatusCode_KV_NEED_FILE_ERROR                      StatusCode = 8009
	StatusCode_KV_NEED_DIR_ERROR                       StatusCode = 8010
	StatusCode_KV_PERM_ERROR                           StatusCode = 8011
	StatusCode_KV_STALE_CACHE_ERROR                    StatusCode = 8012
	StatusCode_KV_PATH_TOO_DEEP_ERROR                  StatusCode = 8013
	StatusCode_KV_LOCK_ALREADY_HELD_ERROR              StatusCode = 8014
	StatusCode_KV_LOCK_TIMEOUT_ERROR                   StatusCode = 8015
	StatusCode_KV_NOENT_ERROR                          StatusCode = 8016
	StatusCode_KV_UPLOAD_IN_PROGRESS_ERROR             StatusCode = 8017
	StatusCode_KV_RMDIR_NEED_RECURSIVE_ERROR           StatusCode = 8018
	StatusCode_KV_NOT_AVAILABLE_ERROR                  StatusCode = 8019
	StatusCode_KV_ABS_PATH_ERROR                       StatusCode = 8020
	StatusCode_GIT_GENERIC_ERROR                       StatusCode = 9001
	StatusCode_GIT_BAD_PATH_ERROR                      StatusCode = 9002
	StatusCode_HTTP_ERROR                              StatusCode = 10001
	StatusCode_STRIPE_SESSION_EXISTS_ERROR             StatusCode = 11001
)

var StatusCodeMap = map[string]StatusCode{
	"OK":                                      0,
	"GENERIC_ERROR":                           100,
	"CONFIG_ERROR":                            101,
	"TLS_ERROR":                               200,
	"PROTO_NOT_FOUND_ERROR":                   210,
	"METHOD_NOT_FOUND_ERROR":                  211,
	"DUPLICATE_ERROR":                         1001,
	"RESERVATION_ERROR":                       1002,
	"LINK_ERROR":                              1003,
	"VALIDATION_ERROR":                        1004,
	"VERIFY_ERROR":                            1005,
	"AUTH_ERROR":                              1006,
	"X509_ERROR":                              1007,
	"BOX_ERROR":                               1008,
	"TIMEOUT_ERROR":                           1009,
	"REPLAY_ERROR":                            1010,
	"BAD_PASSPHRASE_ERROR":                    1011,
	"RATE_LIMIT_ERROR":                        1012,
	"PERMISSION_ERROR":                        1013,
	"TX_RETRY_ERROR":                          1014,
	"PREV_ERROR":                              1015,
	"REVOKE_ERROR":                            1016,
	"COMMITMENT_ERROR":                        1017,
	"WRONG_USER_ERROR":                        1018,
	"BAD_INVITE_CODE_ERROR":                   1019,
	"NOT_IMPLEMENTED":                         1020,
	"SESSION_NOT_FOUND_ERROR":                 1021,
	"YUBI_ERROR":                              1022,
	"USERNAME_IN_USE_ERROR":                   1023,
	"NO_DEFAULT_HOST_ERROR":                   1024,
	"KEY_NOT_FOUND_ERROR":                     1025,
	"KEY_IN_USE_ERROR":                        1026,
	"USER_NOT_FOUND_ERROR":                    1027,
	"GRANT_ERROR":                             1028,
	"NO_CHANGE_ERROR":                         1029,
	"BAD_ARGS_ERROR":                          1030,
	"ROW_NOT_FOUND_ERROR":                     1031,
	"KEX_BAD_SECRET":                          1032,
	"YUBI_LOCKED_ERROR":                       1033,
	"PASSPHRASE_LOCKED_ERROR":                 1034,
	"PROTO_DATA_ERROR":                        1035,
	"HOST_MISMATCH_ERROR":                     1036,
	"HOST_PIN_ERROR":                          1037,
	"NO_ACTIVE_USER_ERROR":                    1038,
	"AMBIGUOUS_ERROR":                         1039,
	"ROLE_ERROR":                              1040,
	"CANCELED_INPUT_ERROR":                    1041,
	"TESTING_ONLY_ERROR":                      1042,
	"PASSPHRASE_NOT_FOUND_ERROR":              1043,
	"REVOKE_RACE_ERROR":                       1044,
	"SECRET_KEY_STORAGE_TYPE_ERROR":           1045,
	"RPC_EOF":                                 1046,
	"NEED_LOGIN_ERROR":                        1047,
	"HOSTID_NOT_FOUND_ERROR":                  1048,
	"GENERIC_NOT_FOUND_ERROR":                 1049,
	"BAD_FORMAT_ERROR":                        1050,
	"BAD_RANGE_ERROR":                         1051,
	"SIGNING_KEY_NOT_FULLY_PROVISIONED_ERROR": 1052,
	"UPGRADE_NEEDED_ERROR":                    1053,
	"VERSION_NOT_SUPPORTED_ERROR":             1054,
	"CONTEXT_CANCELED_ERROR":                  1055,
	"CONNECT_ERROR":                           1056,
	"NETWORK_CONDITIONER_ERROR":               1057,
	"WEB_SESSION_NOT_FOUND_ERROR":             1058,
	"NO_ACTIVE_PLAN_ERROR":                    1059,
	"OVER_QUOTA_ERROR":                        1060,
	"PLAN_EXISTS_ERROR":                       1061,
	"EXPIRED_ERROR":                           1062,
	"HOST_IN_USE_ERROR":                       1063,
	"DNS_ERROR":                               1064,
	"AUTOCERT_FAILED_ERROR":                   1065,
	"SOCKET_ERROR":                            1066,
	"OAUTH2_ERROR":                            1067,
	"OAUTH2_TOKEN_ERROR":                      1068,
	"OAUTH2_AUTH_ERROR":                       1069,
	"OAUTH2_IDP_ERROR":                        1070,
	"SSO_IDP_LOCKED_ERROR":                    1071,
	"DEVICE_ALREADY_PROVISIONED_ERROR":        1072,
	"YUBI_BUS_ERROR":                          1073,
	"KEYCHAIN_ERROR":                          1074,
	"YUBI_AUTH_ERROR":                         1075,
	"YUBI_DEFAULT_MANAGEMENT_KEY_ERROR":       1076,
	"YUBI_BAD_PIN_FORMAT_ERROR":               1077,
	"YUBI_PIN_REQUIRED_ERROR":                 1078,
	"YUBI_DEFAULT_PIN_ERROR":                  1079,
	"AGENT_CONNECT_ERROR":                     1080,
	"INSERT_ERROR":                            2001,
	"UPDATE_ERROR":                            2002,
	"KEX_WRAPPER_ERROR":                       3001,
	"MERKLE_NO_ROOT_ERROR":                    4001,
	"MERKLE_LEAF_NOT_FOUND_ERROR":             4002,
	"MERKLE_VERIFY_ERROR":                     4003,
	"HOSTCHAIN_ERROR":                         5001,
	"CHAIN_LOADER_ERROR":                      6001,
	"TEAM_ERROR":                              7001,
	"TEAM_RACE_ERROR":                         7002,
	"TEAM_BEARER_TOKEN_STALE_ERROR":           7003,
	"TEAM_NOT_FOUND_ERROR":                    7004,
	"TEAM_CERT_ERROR":                         7005,
	"TEAM_ROSTER_ERROR":                       7006,
	"TEAM_KEY_ERROR":                          7007,
	"TEAM_NO_SRC_ROLE_ERROR":                  7008,
	"TEAM_REMOVAL_KEY_ERROR":                  7009,
	"TEAM_EXPLORE_ERROR":                      7010,
	"TEAM_PTK_NOT_FOUND_ERROR":                7011,
	"TEAM_CYCLE_ERROR":                        7012,
	"TEAM_INDEX_RANGE_ERROR":                  7013,
	"TEAM_BAD_INBOX_ROW_ERROR":                7014,
	"TEAM_INVITE_ALREADY_ACCEPTED_ERROR":      7015,
	"KV_TOO_BIG_ERROR":                        8001,
	"KV_UPLOAD_ERROR":                         8002,
	"KV_RACE_ERROR":                           8003,
	"KV_PATH_ERROR":                           8005,
	"KV_MKDIR_ERROR":                          8006,
	"KV_EXISTS_ERROR":                         8007,
	"KV_TYPE_ERROR":                           8008,
	"KV_NEED_FILE_ERROR":                      8009,
	"KV_NEED_DIR_ERROR":                       8010,
	"KV_PERM_ERROR":                           8011,
	"KV_STALE_CACHE_ERROR":                    8012,
	"KV_PATH_TOO_DEEP_ERROR":                  8013,
	"KV_LOCK_ALREADY_HELD_ERROR":              8014,
	"KV_LOCK_TIMEOUT_ERROR":                   8015,
	"KV_NOENT_ERROR":                          8016,
	"KV_UPLOAD_IN_PROGRESS_ERROR":             8017,
	"KV_RMDIR_NEED_RECURSIVE_ERROR":           8018,
	"KV_NOT_AVAILABLE_ERROR":                  8019,
	"KV_ABS_PATH_ERROR":                       8020,
	"GIT_GENERIC_ERROR":                       9001,
	"GIT_BAD_PATH_ERROR":                      9002,
	"HTTP_ERROR":                              10001,
	"STRIPE_SESSION_EXISTS_ERROR":             11001,
}
var StatusCodeRevMap = map[StatusCode]string{
	0:     "OK",
	100:   "GENERIC_ERROR",
	101:   "CONFIG_ERROR",
	200:   "TLS_ERROR",
	210:   "PROTO_NOT_FOUND_ERROR",
	211:   "METHOD_NOT_FOUND_ERROR",
	1001:  "DUPLICATE_ERROR",
	1002:  "RESERVATION_ERROR",
	1003:  "LINK_ERROR",
	1004:  "VALIDATION_ERROR",
	1005:  "VERIFY_ERROR",
	1006:  "AUTH_ERROR",
	1007:  "X509_ERROR",
	1008:  "BOX_ERROR",
	1009:  "TIMEOUT_ERROR",
	1010:  "REPLAY_ERROR",
	1011:  "BAD_PASSPHRASE_ERROR",
	1012:  "RATE_LIMIT_ERROR",
	1013:  "PERMISSION_ERROR",
	1014:  "TX_RETRY_ERROR",
	1015:  "PREV_ERROR",
	1016:  "REVOKE_ERROR",
	1017:  "COMMITMENT_ERROR",
	1018:  "WRONG_USER_ERROR",
	1019:  "BAD_INVITE_CODE_ERROR",
	1020:  "NOT_IMPLEMENTED",
	1021:  "SESSION_NOT_FOUND_ERROR",
	1022:  "YUBI_ERROR",
	1023:  "USERNAME_IN_USE_ERROR",
	1024:  "NO_DEFAULT_HOST_ERROR",
	1025:  "KEY_NOT_FOUND_ERROR",
	1026:  "KEY_IN_USE_ERROR",
	1027:  "USER_NOT_FOUND_ERROR",
	1028:  "GRANT_ERROR",
	1029:  "NO_CHANGE_ERROR",
	1030:  "BAD_ARGS_ERROR",
	1031:  "ROW_NOT_FOUND_ERROR",
	1032:  "KEX_BAD_SECRET",
	1033:  "YUBI_LOCKED_ERROR",
	1034:  "PASSPHRASE_LOCKED_ERROR",
	1035:  "PROTO_DATA_ERROR",
	1036:  "HOST_MISMATCH_ERROR",
	1037:  "HOST_PIN_ERROR",
	1038:  "NO_ACTIVE_USER_ERROR",
	1039:  "AMBIGUOUS_ERROR",
	1040:  "ROLE_ERROR",
	1041:  "CANCELED_INPUT_ERROR",
	1042:  "TESTING_ONLY_ERROR",
	1043:  "PASSPHRASE_NOT_FOUND_ERROR",
	1044:  "REVOKE_RACE_ERROR",
	1045:  "SECRET_KEY_STORAGE_TYPE_ERROR",
	1046:  "RPC_EOF",
	1047:  "NEED_LOGIN_ERROR",
	1048:  "HOSTID_NOT_FOUND_ERROR",
	1049:  "GENERIC_NOT_FOUND_ERROR",
	1050:  "BAD_FORMAT_ERROR",
	1051:  "BAD_RANGE_ERROR",
	1052:  "SIGNING_KEY_NOT_FULLY_PROVISIONED_ERROR",
	1053:  "UPGRADE_NEEDED_ERROR",
	1054:  "VERSION_NOT_SUPPORTED_ERROR",
	1055:  "CONTEXT_CANCELED_ERROR",
	1056:  "CONNECT_ERROR",
	1057:  "NETWORK_CONDITIONER_ERROR",
	1058:  "WEB_SESSION_NOT_FOUND_ERROR",
	1059:  "NO_ACTIVE_PLAN_ERROR",
	1060:  "OVER_QUOTA_ERROR",
	1061:  "PLAN_EXISTS_ERROR",
	1062:  "EXPIRED_ERROR",
	1063:  "HOST_IN_USE_ERROR",
	1064:  "DNS_ERROR",
	1065:  "AUTOCERT_FAILED_ERROR",
	1066:  "SOCKET_ERROR",
	1067:  "OAUTH2_ERROR",
	1068:  "OAUTH2_TOKEN_ERROR",
	1069:  "OAUTH2_AUTH_ERROR",
	1070:  "OAUTH2_IDP_ERROR",
	1071:  "SSO_IDP_LOCKED_ERROR",
	1072:  "DEVICE_ALREADY_PROVISIONED_ERROR",
	1073:  "YUBI_BUS_ERROR",
	1074:  "KEYCHAIN_ERROR",
	1075:  "YUBI_AUTH_ERROR",
	1076:  "YUBI_DEFAULT_MANAGEMENT_KEY_ERROR",
	1077:  "YUBI_BAD_PIN_FORMAT_ERROR",
	1078:  "YUBI_PIN_REQUIRED_ERROR",
	1079:  "YUBI_DEFAULT_PIN_ERROR",
	1080:  "AGENT_CONNECT_ERROR",
	2001:  "INSERT_ERROR",
	2002:  "UPDATE_ERROR",
	3001:  "KEX_WRAPPER_ERROR",
	4001:  "MERKLE_NO_ROOT_ERROR",
	4002:  "MERKLE_LEAF_NOT_FOUND_ERROR",
	4003:  "MERKLE_VERIFY_ERROR",
	5001:  "HOSTCHAIN_ERROR",
	6001:  "CHAIN_LOADER_ERROR",
	7001:  "TEAM_ERROR",
	7002:  "TEAM_RACE_ERROR",
	7003:  "TEAM_BEARER_TOKEN_STALE_ERROR",
	7004:  "TEAM_NOT_FOUND_ERROR",
	7005:  "TEAM_CERT_ERROR",
	7006:  "TEAM_ROSTER_ERROR",
	7007:  "TEAM_KEY_ERROR",
	7008:  "TEAM_NO_SRC_ROLE_ERROR",
	7009:  "TEAM_REMOVAL_KEY_ERROR",
	7010:  "TEAM_EXPLORE_ERROR",
	7011:  "TEAM_PTK_NOT_FOUND_ERROR",
	7012:  "TEAM_CYCLE_ERROR",
	7013:  "TEAM_INDEX_RANGE_ERROR",
	7014:  "TEAM_BAD_INBOX_ROW_ERROR",
	7015:  "TEAM_INVITE_ALREADY_ACCEPTED_ERROR",
	8001:  "KV_TOO_BIG_ERROR",
	8002:  "KV_UPLOAD_ERROR",
	8003:  "KV_RACE_ERROR",
	8005:  "KV_PATH_ERROR",
	8006:  "KV_MKDIR_ERROR",
	8007:  "KV_EXISTS_ERROR",
	8008:  "KV_TYPE_ERROR",
	8009:  "KV_NEED_FILE_ERROR",
	8010:  "KV_NEED_DIR_ERROR",
	8011:  "KV_PERM_ERROR",
	8012:  "KV_STALE_CACHE_ERROR",
	8013:  "KV_PATH_TOO_DEEP_ERROR",
	8014:  "KV_LOCK_ALREADY_HELD_ERROR",
	8015:  "KV_LOCK_TIMEOUT_ERROR",
	8016:  "KV_NOENT_ERROR",
	8017:  "KV_UPLOAD_IN_PROGRESS_ERROR",
	8018:  "KV_RMDIR_NEED_RECURSIVE_ERROR",
	8019:  "KV_NOT_AVAILABLE_ERROR",
	8020:  "KV_ABS_PATH_ERROR",
	9001:  "GIT_GENERIC_ERROR",
	9002:  "GIT_BAD_PATH_ERROR",
	10001: "HTTP_ERROR",
	11001: "STRIPE_SESSION_EXISTS_ERROR",
}

type StatusCodeInternal__ StatusCode

func (s StatusCodeInternal__) Import() StatusCode {
	return StatusCode(s)
}
func (s StatusCode) Export() *StatusCodeInternal__ {
	return ((*StatusCodeInternal__)(&s))
}

type HostPinError struct {
	Host Hostname
	Old  HostID
	New  HostID
}
type HostPinErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *HostnameInternal__
	Old     *HostIDInternal__
	New     *HostIDInternal__
}

func (h HostPinErrorInternal__) Import() HostPinError {
	return HostPinError{
		Host: (func(x *HostnameInternal__) (ret Hostname) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Host),
		Old: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Old),
		New: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.New),
	}
}
func (h HostPinError) Export() *HostPinErrorInternal__ {
	return &HostPinErrorInternal__{
		Host: h.Host.Export(),
		Old:  h.Old.Export(),
		New:  h.New.Export(),
	}
}
func (h *HostPinError) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostPinError) Decode(dec rpc.Decoder) error {
	var tmp HostPinErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HostPinError) Bytes() []byte { return nil }

type MethodV2 struct {
	Proto  uint64
	Method uint64
	Name   string
}
type MethodV2Internal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Proto   *uint64
	Method  *uint64
	Name    *string
}

func (m MethodV2Internal__) Import() MethodV2 {
	return MethodV2{
		Proto: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Proto),
		Method: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Method),
		Name: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Name),
	}
}
func (m MethodV2) Export() *MethodV2Internal__ {
	return &MethodV2Internal__{
		Proto:  &m.Proto,
		Method: &m.Method,
		Name:   &m.Name,
	}
}
func (m *MethodV2) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MethodV2) Decode(dec rpc.Decoder) error {
	var tmp MethodV2Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MethodV2) Bytes() []byte { return nil }

type ChainLoaderError struct {
	Err  Status
	Race bool
}
type ChainLoaderErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Err     *StatusInternal__
	Race    *bool
}

func (c ChainLoaderErrorInternal__) Import() ChainLoaderError {
	return ChainLoaderError{
		Err: (func(x *StatusInternal__) (ret Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Err),
		Race: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Race),
	}
}
func (c ChainLoaderError) Export() *ChainLoaderErrorInternal__ {
	return &ChainLoaderErrorInternal__{
		Err:  c.Err.Export(),
		Race: &c.Race,
	}
}
func (c *ChainLoaderError) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChainLoaderError) Decode(dec rpc.Decoder) error {
	var tmp ChainLoaderErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChainLoaderError) Bytes() []byte { return nil }

type SharedKeyNotFound struct {
	Gen  Generation
	Role Role
}
type SharedKeyNotFoundInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Gen     *GenerationInternal__
	Role    *RoleInternal__
}

func (s SharedKeyNotFoundInternal__) Import() SharedKeyNotFound {
	return SharedKeyNotFound{
		Gen: (func(x *GenerationInternal__) (ret Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Gen),
		Role: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Role),
	}
}
func (s SharedKeyNotFound) Export() *SharedKeyNotFoundInternal__ {
	return &SharedKeyNotFoundInternal__{
		Gen:  s.Gen.Export(),
		Role: s.Role.Export(),
	}
}
func (s *SharedKeyNotFound) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKeyNotFound) Decode(dec rpc.Decoder) error {
	var tmp SharedKeyNotFoundInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SharedKeyNotFound) Bytes() []byte { return nil }

type KVOp int

const (
	KVOp_None  KVOp = 0
	KVOp_Read  KVOp = 1
	KVOp_Write KVOp = 2
)

var KVOpMap = map[string]KVOp{
	"None":  0,
	"Read":  1,
	"Write": 2,
}
var KVOpRevMap = map[KVOp]string{
	0: "None",
	1: "Read",
	2: "Write",
}

type KVOpInternal__ KVOp

func (k KVOpInternal__) Import() KVOp {
	return KVOp(k)
}
func (k KVOp) Export() *KVOpInternal__ {
	return ((*KVOpInternal__)(&k))
}

type KVResource int

const (
	KVResource_None KVResource = 0
	KVResource_File KVResource = 1
	KVResource_Dir  KVResource = 2
)

var KVResourceMap = map[string]KVResource{
	"None": 0,
	"File": 1,
	"Dir":  2,
}
var KVResourceRevMap = map[KVResource]string{
	0: "None",
	1: "File",
	2: "Dir",
}

type KVResourceInternal__ KVResource

func (k KVResourceInternal__) Import() KVResource {
	return KVResource(k)
}
func (k KVResource) Export() *KVResourceInternal__ {
	return ((*KVResourceInternal__)(&k))
}

type KVPermError struct {
	Op       KVOp
	Resource KVNodeType
}
type KVPermErrorInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Op       *KVOpInternal__
	Resource *KVNodeTypeInternal__
}

func (k KVPermErrorInternal__) Import() KVPermError {
	return KVPermError{
		Op: (func(x *KVOpInternal__) (ret KVOp) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Op),
		Resource: (func(x *KVNodeTypeInternal__) (ret KVNodeType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Resource),
	}
}
func (k KVPermError) Export() *KVPermErrorInternal__ {
	return &KVPermErrorInternal__{
		Op:       k.Op.Export(),
		Resource: k.Resource.Export(),
	}
}
func (k *KVPermError) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVPermError) Decode(dec rpc.Decoder) error {
	var tmp KVPermErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVPermError) Bytes() []byte { return nil }

type TeamCycleError struct {
	Joiner RationalRange
	Joinee RationalRange
}
type TeamCycleErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Joiner  *RationalRangeInternal__
	Joinee  *RationalRangeInternal__
}

func (t TeamCycleErrorInternal__) Import() TeamCycleError {
	return TeamCycleError{
		Joiner: (func(x *RationalRangeInternal__) (ret RationalRange) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Joiner),
		Joinee: (func(x *RationalRangeInternal__) (ret RationalRange) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Joinee),
	}
}
func (t TeamCycleError) Export() *TeamCycleErrorInternal__ {
	return &TeamCycleErrorInternal__{
		Joiner: t.Joiner.Export(),
		Joinee: t.Joinee.Export(),
	}
}
func (t *TeamCycleError) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamCycleError) Decode(dec rpc.Decoder) error {
	var tmp TeamCycleErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamCycleError) Bytes() []byte { return nil }

type TooBigError struct {
	Actual uint64
	Limit  uint64
	Desc   string
}
type TooBigErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Actual  *uint64
	Limit   *uint64
	Desc    *string
}

func (t TooBigErrorInternal__) Import() TooBigError {
	return TooBigError{
		Actual: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(t.Actual),
		Limit: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(t.Limit),
		Desc: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(t.Desc),
	}
}
func (t TooBigError) Export() *TooBigErrorInternal__ {
	return &TooBigErrorInternal__{
		Actual: &t.Actual,
		Limit:  &t.Limit,
		Desc:   &t.Desc,
	}
}
func (t *TooBigError) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TooBigError) Decode(dec rpc.Decoder) error {
	var tmp TooBigErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TooBigError) Bytes() []byte { return nil }

type ConnectError struct {
	Err  Status
	Desc string
}
type ConnectErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Err     *StatusInternal__
	Desc    *string
}

func (c ConnectErrorInternal__) Import() ConnectError {
	return ConnectError{
		Err: (func(x *StatusInternal__) (ret Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Err),
		Desc: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Desc),
	}
}
func (c ConnectError) Export() *ConnectErrorInternal__ {
	return &ConnectErrorInternal__{
		Err:  c.Err.Export(),
		Desc: &c.Desc,
	}
}
func (c *ConnectError) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ConnectError) Decode(dec rpc.Decoder) error {
	var tmp ConnectErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ConnectError) Bytes() []byte { return nil }

type HttpError struct {
	Code uint64
	Err  Status
	Desc string
}
type HttpErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Code    *uint64
	Err     *StatusInternal__
	Desc    *string
}

func (h HttpErrorInternal__) Import() HttpError {
	return HttpError{
		Code: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(h.Code),
		Err: (func(x *StatusInternal__) (ret Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Err),
		Desc: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(h.Desc),
	}
}
func (h HttpError) Export() *HttpErrorInternal__ {
	return &HttpErrorInternal__{
		Code: &h.Code,
		Err:  h.Err.Export(),
		Desc: &h.Desc,
	}
}
func (h *HttpError) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HttpError) Decode(dec rpc.Decoder) error {
	var tmp HttpErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HttpError) Bytes() []byte { return nil }

type DNSError struct {
	Stage string
	Err   Status
}
type DNSErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Stage   *string
	Err     *StatusInternal__
}

func (d DNSErrorInternal__) Import() DNSError {
	return DNSError{
		Stage: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(d.Stage),
		Err: (func(x *StatusInternal__) (ret Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Err),
	}
}
func (d DNSError) Export() *DNSErrorInternal__ {
	return &DNSErrorInternal__{
		Stage: &d.Stage,
		Err:   d.Err.Export(),
	}
}
func (d *DNSError) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DNSError) Decode(dec rpc.Decoder) error {
	var tmp DNSErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DNSError) Bytes() []byte { return nil }

type SocketError struct {
	Path string
	Msg  string
}
type SocketErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Path    *string
	Msg     *string
}

func (s SocketErrorInternal__) Import() SocketError {
	return SocketError{
		Path: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Path),
		Msg: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Msg),
	}
}
func (s SocketError) Export() *SocketErrorInternal__ {
	return &SocketErrorInternal__{
		Path: &s.Path,
		Msg:  &s.Msg,
	}
}
func (s *SocketError) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocketError) Decode(dec rpc.Decoder) error {
	var tmp SocketErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocketError) Bytes() []byte { return nil }

type OAuth2TokenError struct {
	Err   Status
	Which string
}
type OAuth2TokenErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Err     *StatusInternal__
	Which   *string
}

func (o OAuth2TokenErrorInternal__) Import() OAuth2TokenError {
	return OAuth2TokenError{
		Err: (func(x *StatusInternal__) (ret Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Err),
		Which: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(o.Which),
	}
}
func (o OAuth2TokenError) Export() *OAuth2TokenErrorInternal__ {
	return &OAuth2TokenErrorInternal__{
		Err:   o.Err.Export(),
		Which: &o.Which,
	}
}
func (o *OAuth2TokenError) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2TokenError) Decode(dec rpc.Decoder) error {
	var tmp OAuth2TokenErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o *OAuth2TokenError) Bytes() []byte { return nil }

type OAuth2IdPError struct {
	Code uint64
	Err  string
	Desc string
}
type OAuth2IdPErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Code    *uint64
	Err     *string
	Desc    *string
}

func (o OAuth2IdPErrorInternal__) Import() OAuth2IdPError {
	return OAuth2IdPError{
		Code: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(o.Code),
		Err: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(o.Err),
		Desc: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(o.Desc),
	}
}
func (o OAuth2IdPError) Export() *OAuth2IdPErrorInternal__ {
	return &OAuth2IdPErrorInternal__{
		Code: &o.Code,
		Err:  &o.Err,
		Desc: &o.Desc,
	}
}
func (o *OAuth2IdPError) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2IdPError) Decode(dec rpc.Decoder) error {
	var tmp OAuth2IdPErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o *OAuth2IdPError) Bytes() []byte { return nil }

type Status struct {
	Sc     StatusCode
	F_1__  *string               `json:"f1,omitempty"`
	F_2__  *uint64               `json:"f2,omitempty"`
	F_3__  *MethodV2             `json:"f3,omitempty"`
	F_4__  *Status               `json:"f4,omitempty"`
	F_5__  *YubiKeyInfoHybrid    `json:"f5,omitempty"`
	F_6__  *HostPinError         `json:"f6,omitempty"`
	F_7__  *SecretKeyStorageType `json:"f7,omitempty"`
	F_8__  *ChainLoaderError     `json:"f8,omitempty"`
	F_9__  *SharedKeyNotFound    `json:"f9,omitempty"`
	F_10__ *KVPermError          `json:"f10,omitempty"`
	F_11__ *PathVersionVector    `json:"f11,omitempty"`
	F_12__ *UISessionID          `json:"f12,omitempty"`
	F_13__ *TeamCycleError       `json:"f13,omitempty"`
	F_14__ *TooBigError          `json:"f14,omitempty"`
	F_15__ *ConnectError         `json:"f15,omitempty"`
	F_16__ *HttpError            `json:"f16,omitempty"`
	F_17__ *DNSError             `json:"f17,omitempty"`
	F_18__ *SocketError          `json:"f18,omitempty"`
	F_19__ *OAuth2TokenError     `json:"f19,omitempty"`
	F_20__ *OAuth2IdPError       `json:"f20,omitempty"`
	F_21__ *int64                `json:"f21,omitempty"`
	F_0__  *string               `json:"f0,omitempty"`
}
type StatusInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Sc       StatusCode
	Switch__ StatusInternalSwitch__
}
type StatusInternalSwitch__ struct {
	_struct struct{}                        `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *string                         `codec:"1"`
	F_2__   *uint64                         `codec:"2"`
	F_3__   *MethodV2Internal__             `codec:"3"`
	F_4__   *StatusInternal__               `codec:"4"`
	F_5__   *YubiKeyInfoHybridInternal__    `codec:"5"`
	F_6__   *HostPinErrorInternal__         `codec:"6"`
	F_7__   *SecretKeyStorageTypeInternal__ `codec:"7"`
	F_8__   *ChainLoaderErrorInternal__     `codec:"8"`
	F_9__   *SharedKeyNotFoundInternal__    `codec:"9"`
	F_10__  *KVPermErrorInternal__          `codec:"a"`
	F_11__  *PathVersionVectorInternal__    `codec:"b"`
	F_12__  *UISessionIDInternal__          `codec:"c"`
	F_13__  *TeamCycleErrorInternal__       `codec:"d"`
	F_14__  *TooBigErrorInternal__          `codec:"e"`
	F_15__  *ConnectErrorInternal__         `codec:"f"`
	F_16__  *HttpErrorInternal__            `codec:"g"`
	F_17__  *DNSErrorInternal__             `codec:"h"`
	F_18__  *SocketErrorInternal__          `codec:"i"`
	F_19__  *OAuth2TokenErrorInternal__     `codec:"j"`
	F_20__  *OAuth2IdPErrorInternal__       `codec:"k"`
	F_21__  *int64                          `codec:"l"`
	F_0__   *string                         `codec:"0"`
}

func (s Status) GetSc() (ret StatusCode, err error) {
	switch s.Sc {
	case StatusCode_OK, StatusCode_AUTH_ERROR, StatusCode_TIMEOUT_ERROR, StatusCode_REPLAY_ERROR, StatusCode_BAD_PASSPHRASE_ERROR, StatusCode_RATE_LIMIT_ERROR, StatusCode_TX_RETRY_ERROR, StatusCode_WRONG_USER_ERROR, StatusCode_BAD_INVITE_CODE_ERROR, StatusCode_NOT_IMPLEMENTED, StatusCode_USERNAME_IN_USE_ERROR, StatusCode_MERKLE_NO_ROOT_ERROR, StatusCode_NO_DEFAULT_HOST_ERROR, StatusCode_KEY_IN_USE_ERROR, StatusCode_MERKLE_LEAF_NOT_FOUND_ERROR, StatusCode_USER_NOT_FOUND_ERROR, StatusCode_ROW_NOT_FOUND_ERROR, StatusCode_KEX_BAD_SECRET, StatusCode_PASSPHRASE_LOCKED_ERROR, StatusCode_NO_ACTIVE_USER_ERROR, StatusCode_SIGNING_KEY_NOT_FULLY_PROVISIONED_ERROR, StatusCode_CANCELED_INPUT_ERROR, StatusCode_TESTING_ONLY_ERROR, StatusCode_PASSPHRASE_NOT_FOUND_ERROR, StatusCode_RPC_EOF, StatusCode_TEAM_NOT_FOUND_ERROR, StatusCode_TEAM_NO_SRC_ROLE_ERROR, StatusCode_NEED_LOGIN_ERROR, StatusCode_BAD_RANGE_ERROR, StatusCode_HOSTID_NOT_FOUND_ERROR, StatusCode_KV_UPLOAD_IN_PROGRESS_ERROR, StatusCode_KV_EXISTS_ERROR, StatusCode_KV_NEED_FILE_ERROR, StatusCode_KV_NEED_DIR_ERROR, StatusCode_KV_PATH_TOO_DEEP_ERROR, StatusCode_KV_LOCK_ALREADY_HELD_ERROR, StatusCode_KV_LOCK_TIMEOUT_ERROR, StatusCode_KV_RMDIR_NEED_RECURSIVE_ERROR, StatusCode_CONTEXT_CANCELED_ERROR, StatusCode_NETWORK_CONDITIONER_ERROR, StatusCode_WEB_SESSION_NOT_FOUND_ERROR, StatusCode_NO_ACTIVE_PLAN_ERROR, StatusCode_OVER_QUOTA_ERROR, StatusCode_PLAN_EXISTS_ERROR, StatusCode_EXPIRED_ERROR, StatusCode_STRIPE_SESSION_EXISTS_ERROR, StatusCode_SSO_IDP_LOCKED_ERROR, StatusCode_TEAM_INVITE_ALREADY_ACCEPTED_ERROR, StatusCode_DEVICE_ALREADY_PROVISIONED_ERROR, StatusCode_KV_NOT_AVAILABLE_ERROR, StatusCode_YUBI_DEFAULT_MANAGEMENT_KEY_ERROR, StatusCode_YUBI_BAD_PIN_FORMAT_ERROR, StatusCode_YUBI_PIN_REQUIRED_ERROR, StatusCode_YUBI_DEFAULT_PIN_ERROR:
		break
	case StatusCode_TLS_ERROR, StatusCode_CONFIG_ERROR, StatusCode_DUPLICATE_ERROR, StatusCode_RESERVATION_ERROR, StatusCode_LINK_ERROR, StatusCode_VALIDATION_ERROR, StatusCode_VERIFY_ERROR, StatusCode_X509_ERROR, StatusCode_PERMISSION_ERROR, StatusCode_PREV_ERROR, StatusCode_BOX_ERROR, StatusCode_INSERT_ERROR, StatusCode_UPDATE_ERROR, StatusCode_REVOKE_ERROR, StatusCode_COMMITMENT_ERROR, StatusCode_YUBI_ERROR, StatusCode_HOSTCHAIN_ERROR, StatusCode_GRANT_ERROR, StatusCode_NO_CHANGE_ERROR, StatusCode_BAD_ARGS_ERROR, StatusCode_KEY_NOT_FOUND_ERROR, StatusCode_PROTO_DATA_ERROR, StatusCode_HOST_MISMATCH_ERROR, StatusCode_BAD_FORMAT_ERROR, StatusCode_AMBIGUOUS_ERROR, StatusCode_ROLE_ERROR, StatusCode_REVOKE_RACE_ERROR, StatusCode_MERKLE_VERIFY_ERROR, StatusCode_TEAM_ERROR, StatusCode_TEAM_RACE_ERROR, StatusCode_TEAM_BEARER_TOKEN_STALE_ERROR, StatusCode_TEAM_CERT_ERROR, StatusCode_TEAM_ROSTER_ERROR, StatusCode_TEAM_KEY_ERROR, StatusCode_TEAM_INDEX_RANGE_ERROR, StatusCode_TEAM_REMOVAL_KEY_ERROR, StatusCode_TEAM_EXPLORE_ERROR, StatusCode_GENERIC_NOT_FOUND_ERROR, StatusCode_KV_UPLOAD_ERROR, StatusCode_KV_RACE_ERROR, StatusCode_KV_PATH_ERROR, StatusCode_KV_MKDIR_ERROR, StatusCode_KV_TYPE_ERROR, StatusCode_KV_NOENT_ERROR, StatusCode_GIT_GENERIC_ERROR, StatusCode_GIT_BAD_PATH_ERROR, StatusCode_UPGRADE_NEEDED_ERROR, StatusCode_VERSION_NOT_SUPPORTED_ERROR, StatusCode_HOST_IN_USE_ERROR, StatusCode_OAUTH2_ERROR, StatusCode_KV_ABS_PATH_ERROR, StatusCode_YUBI_BUS_ERROR, StatusCode_KEYCHAIN_ERROR, StatusCode_AGENT_CONNECT_ERROR:
		if s.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case StatusCode_PROTO_NOT_FOUND_ERROR:
		if s.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case StatusCode_METHOD_NOT_FOUND_ERROR:
		if s.F_3__ == nil {
			return ret, errors.New("unexpected nil case for F_3__")
		}
	case StatusCode_KEX_WRAPPER_ERROR, StatusCode_AUTOCERT_FAILED_ERROR, StatusCode_OAUTH2_AUTH_ERROR:
		if s.F_4__ == nil {
			return ret, errors.New("unexpected nil case for F_4__")
		}
	case StatusCode_YUBI_LOCKED_ERROR:
		if s.F_5__ == nil {
			return ret, errors.New("unexpected nil case for F_5__")
		}
	case StatusCode_HOST_PIN_ERROR:
		if s.F_6__ == nil {
			return ret, errors.New("unexpected nil case for F_6__")
		}
	case StatusCode_SECRET_KEY_STORAGE_TYPE_ERROR:
		if s.F_7__ == nil {
			return ret, errors.New("unexpected nil case for F_7__")
		}
	case StatusCode_CHAIN_LOADER_ERROR:
		if s.F_8__ == nil {
			return ret, errors.New("unexpected nil case for F_8__")
		}
	case StatusCode_TEAM_PTK_NOT_FOUND_ERROR:
		if s.F_9__ == nil {
			return ret, errors.New("unexpected nil case for F_9__")
		}
	case StatusCode_KV_PERM_ERROR:
		if s.F_10__ == nil {
			return ret, errors.New("unexpected nil case for F_10__")
		}
	case StatusCode_KV_STALE_CACHE_ERROR:
		if s.F_11__ == nil {
			return ret, errors.New("unexpected nil case for F_11__")
		}
	case StatusCode_SESSION_NOT_FOUND_ERROR:
		if s.F_12__ == nil {
			return ret, errors.New("unexpected nil case for F_12__")
		}
	case StatusCode_TEAM_CYCLE_ERROR:
		if s.F_13__ == nil {
			return ret, errors.New("unexpected nil case for F_13__")
		}
	case StatusCode_KV_TOO_BIG_ERROR:
		if s.F_14__ == nil {
			return ret, errors.New("unexpected nil case for F_14__")
		}
	case StatusCode_CONNECT_ERROR:
		if s.F_15__ == nil {
			return ret, errors.New("unexpected nil case for F_15__")
		}
	case StatusCode_HTTP_ERROR:
		if s.F_16__ == nil {
			return ret, errors.New("unexpected nil case for F_16__")
		}
	case StatusCode_DNS_ERROR:
		if s.F_17__ == nil {
			return ret, errors.New("unexpected nil case for F_17__")
		}
	case StatusCode_SOCKET_ERROR:
		if s.F_18__ == nil {
			return ret, errors.New("unexpected nil case for F_18__")
		}
	case StatusCode_OAUTH2_TOKEN_ERROR:
		if s.F_19__ == nil {
			return ret, errors.New("unexpected nil case for F_19__")
		}
	case StatusCode_OAUTH2_IDP_ERROR:
		if s.F_20__ == nil {
			return ret, errors.New("unexpected nil case for F_20__")
		}
	case StatusCode_YUBI_AUTH_ERROR:
		if s.F_21__ == nil {
			return ret, errors.New("unexpected nil case for F_21__")
		}
	default:
		if s.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	}
	return s.Sc, nil
}
func (s Status) TlsError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TLS_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TlsError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) ConfigError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_CONFIG_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when ConfigError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) DuplicateError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_DUPLICATE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when DuplicateError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) ReservationError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_RESERVATION_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when ReservationError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) LinkError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_LINK_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when LinkError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) ValidationError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_VALIDATION_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when ValidationError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) VerifyError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_VERIFY_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when VerifyError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) X509Error() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_X509_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when X509Error is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) PermissionError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_PERMISSION_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when PermissionError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) PrevError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_PREV_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when PrevError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) BoxError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_BOX_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when BoxError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) InsertError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_INSERT_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when InsertError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) UpdateError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_UPDATE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when UpdateError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) RevokeError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_REVOKE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when RevokeError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) CommitmentError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_COMMITMENT_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when CommitmentError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) YubiError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_YUBI_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when YubiError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) HostchainError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_HOSTCHAIN_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when HostchainError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) GrantError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_GRANT_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when GrantError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) NoChangeError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_NO_CHANGE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when NoChangeError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) BadArgsError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_BAD_ARGS_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when BadArgsError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) KeyNotFoundError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KEY_NOT_FOUND_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KeyNotFoundError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) ProtoDataError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_PROTO_DATA_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when ProtoDataError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) HostMismatchError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_HOST_MISMATCH_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when HostMismatchError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) BadFormatError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_BAD_FORMAT_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when BadFormatError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) AmbiguousError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_AMBIGUOUS_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when AmbiguousError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) RoleError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_ROLE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when RoleError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) RevokeRaceError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_REVOKE_RACE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when RevokeRaceError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) MerkleVerifyError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_MERKLE_VERIFY_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when MerkleVerifyError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) TeamError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) TeamRaceError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_RACE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamRaceError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) TeamBearerTokenStaleError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_BEARER_TOKEN_STALE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamBearerTokenStaleError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) TeamCertError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_CERT_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamCertError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) TeamRosterError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_ROSTER_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamRosterError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) TeamKeyError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_KEY_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamKeyError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) TeamIndexRangeError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_INDEX_RANGE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamIndexRangeError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) TeamRemovalKeyError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_REMOVAL_KEY_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamRemovalKeyError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) TeamExploreError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_EXPLORE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamExploreError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) GenericNotFoundError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_GENERIC_NOT_FOUND_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when GenericNotFoundError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) KvUploadError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KV_UPLOAD_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KvUploadError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) KvRaceError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KV_RACE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KvRaceError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) KvPathError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KV_PATH_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KvPathError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) KvMkdirError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KV_MKDIR_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KvMkdirError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) KvTypeError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KV_TYPE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KvTypeError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) KvNoentError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KV_NOENT_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KvNoentError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) GitGenericError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_GIT_GENERIC_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when GitGenericError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) GitBadPathError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_GIT_BAD_PATH_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when GitBadPathError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) UpgradeNeededError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_UPGRADE_NEEDED_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when UpgradeNeededError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) VersionNotSupportedError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_VERSION_NOT_SUPPORTED_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when VersionNotSupportedError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) HostInUseError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_HOST_IN_USE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when HostInUseError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) Oauth2Error() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_OAUTH2_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when Oauth2Error is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) KvAbsPathError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KV_ABS_PATH_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KvAbsPathError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) YubiBusError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_YUBI_BUS_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when YubiBusError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) KeychainError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KEYCHAIN_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KeychainError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) AgentConnectError() string {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_AGENT_CONNECT_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when AgentConnectError is called", s.Sc))
	}
	return *s.F_1__
}
func (s Status) ProtoNotFoundError() uint64 {
	if s.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_PROTO_NOT_FOUND_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when ProtoNotFoundError is called", s.Sc))
	}
	return *s.F_2__
}
func (s Status) MethodNotFoundError() MethodV2 {
	if s.F_3__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_METHOD_NOT_FOUND_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when MethodNotFoundError is called", s.Sc))
	}
	return *s.F_3__
}
func (s Status) KexWrapperError() Status {
	if s.F_4__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KEX_WRAPPER_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KexWrapperError is called", s.Sc))
	}
	return *s.F_4__
}
func (s Status) AutocertFailedError() Status {
	if s.F_4__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_AUTOCERT_FAILED_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when AutocertFailedError is called", s.Sc))
	}
	return *s.F_4__
}
func (s Status) Oauth2AuthError() Status {
	if s.F_4__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_OAUTH2_AUTH_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when Oauth2AuthError is called", s.Sc))
	}
	return *s.F_4__
}
func (s Status) YubiLockedError() YubiKeyInfoHybrid {
	if s.F_5__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_YUBI_LOCKED_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when YubiLockedError is called", s.Sc))
	}
	return *s.F_5__
}
func (s Status) HostPinError() HostPinError {
	if s.F_6__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_HOST_PIN_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when HostPinError is called", s.Sc))
	}
	return *s.F_6__
}
func (s Status) SecretKeyStorageTypeError() SecretKeyStorageType {
	if s.F_7__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_SECRET_KEY_STORAGE_TYPE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when SecretKeyStorageTypeError is called", s.Sc))
	}
	return *s.F_7__
}
func (s Status) ChainLoaderError() ChainLoaderError {
	if s.F_8__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_CHAIN_LOADER_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when ChainLoaderError is called", s.Sc))
	}
	return *s.F_8__
}
func (s Status) TeamPtkNotFoundError() SharedKeyNotFound {
	if s.F_9__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_PTK_NOT_FOUND_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamPtkNotFoundError is called", s.Sc))
	}
	return *s.F_9__
}
func (s Status) KvPermError() KVPermError {
	if s.F_10__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KV_PERM_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KvPermError is called", s.Sc))
	}
	return *s.F_10__
}
func (s Status) KvStaleCacheError() PathVersionVector {
	if s.F_11__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KV_STALE_CACHE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KvStaleCacheError is called", s.Sc))
	}
	return *s.F_11__
}
func (s Status) SessionNotFoundError() UISessionID {
	if s.F_12__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_SESSION_NOT_FOUND_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when SessionNotFoundError is called", s.Sc))
	}
	return *s.F_12__
}
func (s Status) TeamCycleError() TeamCycleError {
	if s.F_13__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_TEAM_CYCLE_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when TeamCycleError is called", s.Sc))
	}
	return *s.F_13__
}
func (s Status) KvTooBigError() TooBigError {
	if s.F_14__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_KV_TOO_BIG_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when KvTooBigError is called", s.Sc))
	}
	return *s.F_14__
}
func (s Status) ConnectError() ConnectError {
	if s.F_15__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_CONNECT_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when ConnectError is called", s.Sc))
	}
	return *s.F_15__
}
func (s Status) HttpError() HttpError {
	if s.F_16__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_HTTP_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when HttpError is called", s.Sc))
	}
	return *s.F_16__
}
func (s Status) DnsError() DNSError {
	if s.F_17__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_DNS_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when DnsError is called", s.Sc))
	}
	return *s.F_17__
}
func (s Status) SocketError() SocketError {
	if s.F_18__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_SOCKET_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when SocketError is called", s.Sc))
	}
	return *s.F_18__
}
func (s Status) Oauth2TokenError() OAuth2TokenError {
	if s.F_19__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_OAUTH2_TOKEN_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when Oauth2TokenError is called", s.Sc))
	}
	return *s.F_19__
}
func (s Status) Oauth2IdpError() OAuth2IdPError {
	if s.F_20__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_OAUTH2_IDP_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when Oauth2IdpError is called", s.Sc))
	}
	return *s.F_20__
}
func (s Status) YubiAuthError() int64 {
	if s.F_21__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.Sc != StatusCode_YUBI_AUTH_ERROR {
		panic(fmt.Sprintf("unexpected switch value (%v) when YubiAuthError is called", s.Sc))
	}
	return *s.F_21__
}
func (s Status) Default() string {
	if s.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	return *s.F_0__
}
func NewStatusWithOk() Status {
	return Status{
		Sc: StatusCode_OK,
	}
}
func NewStatusWithAuthError() Status {
	return Status{
		Sc: StatusCode_AUTH_ERROR,
	}
}
func NewStatusWithTimeoutError() Status {
	return Status{
		Sc: StatusCode_TIMEOUT_ERROR,
	}
}
func NewStatusWithReplayError() Status {
	return Status{
		Sc: StatusCode_REPLAY_ERROR,
	}
}
func NewStatusWithBadPassphraseError() Status {
	return Status{
		Sc: StatusCode_BAD_PASSPHRASE_ERROR,
	}
}
func NewStatusWithRateLimitError() Status {
	return Status{
		Sc: StatusCode_RATE_LIMIT_ERROR,
	}
}
func NewStatusWithTxRetryError() Status {
	return Status{
		Sc: StatusCode_TX_RETRY_ERROR,
	}
}
func NewStatusWithWrongUserError() Status {
	return Status{
		Sc: StatusCode_WRONG_USER_ERROR,
	}
}
func NewStatusWithBadInviteCodeError() Status {
	return Status{
		Sc: StatusCode_BAD_INVITE_CODE_ERROR,
	}
}
func NewStatusWithNotImplemented() Status {
	return Status{
		Sc: StatusCode_NOT_IMPLEMENTED,
	}
}
func NewStatusWithUsernameInUseError() Status {
	return Status{
		Sc: StatusCode_USERNAME_IN_USE_ERROR,
	}
}
func NewStatusWithMerkleNoRootError() Status {
	return Status{
		Sc: StatusCode_MERKLE_NO_ROOT_ERROR,
	}
}
func NewStatusWithNoDefaultHostError() Status {
	return Status{
		Sc: StatusCode_NO_DEFAULT_HOST_ERROR,
	}
}
func NewStatusWithKeyInUseError() Status {
	return Status{
		Sc: StatusCode_KEY_IN_USE_ERROR,
	}
}
func NewStatusWithMerkleLeafNotFoundError() Status {
	return Status{
		Sc: StatusCode_MERKLE_LEAF_NOT_FOUND_ERROR,
	}
}
func NewStatusWithUserNotFoundError() Status {
	return Status{
		Sc: StatusCode_USER_NOT_FOUND_ERROR,
	}
}
func NewStatusWithRowNotFoundError() Status {
	return Status{
		Sc: StatusCode_ROW_NOT_FOUND_ERROR,
	}
}
func NewStatusWithKexBadSecret() Status {
	return Status{
		Sc: StatusCode_KEX_BAD_SECRET,
	}
}
func NewStatusWithPassphraseLockedError() Status {
	return Status{
		Sc: StatusCode_PASSPHRASE_LOCKED_ERROR,
	}
}
func NewStatusWithNoActiveUserError() Status {
	return Status{
		Sc: StatusCode_NO_ACTIVE_USER_ERROR,
	}
}
func NewStatusWithSigningKeyNotFullyProvisionedError() Status {
	return Status{
		Sc: StatusCode_SIGNING_KEY_NOT_FULLY_PROVISIONED_ERROR,
	}
}
func NewStatusWithCanceledInputError() Status {
	return Status{
		Sc: StatusCode_CANCELED_INPUT_ERROR,
	}
}
func NewStatusWithTestingOnlyError() Status {
	return Status{
		Sc: StatusCode_TESTING_ONLY_ERROR,
	}
}
func NewStatusWithPassphraseNotFoundError() Status {
	return Status{
		Sc: StatusCode_PASSPHRASE_NOT_FOUND_ERROR,
	}
}
func NewStatusWithRpcEof() Status {
	return Status{
		Sc: StatusCode_RPC_EOF,
	}
}
func NewStatusWithTeamNotFoundError() Status {
	return Status{
		Sc: StatusCode_TEAM_NOT_FOUND_ERROR,
	}
}
func NewStatusWithTeamNoSrcRoleError() Status {
	return Status{
		Sc: StatusCode_TEAM_NO_SRC_ROLE_ERROR,
	}
}
func NewStatusWithNeedLoginError() Status {
	return Status{
		Sc: StatusCode_NEED_LOGIN_ERROR,
	}
}
func NewStatusWithBadRangeError() Status {
	return Status{
		Sc: StatusCode_BAD_RANGE_ERROR,
	}
}
func NewStatusWithHostidNotFoundError() Status {
	return Status{
		Sc: StatusCode_HOSTID_NOT_FOUND_ERROR,
	}
}
func NewStatusWithKvUploadInProgressError() Status {
	return Status{
		Sc: StatusCode_KV_UPLOAD_IN_PROGRESS_ERROR,
	}
}
func NewStatusWithKvExistsError() Status {
	return Status{
		Sc: StatusCode_KV_EXISTS_ERROR,
	}
}
func NewStatusWithKvNeedFileError() Status {
	return Status{
		Sc: StatusCode_KV_NEED_FILE_ERROR,
	}
}
func NewStatusWithKvNeedDirError() Status {
	return Status{
		Sc: StatusCode_KV_NEED_DIR_ERROR,
	}
}
func NewStatusWithKvPathTooDeepError() Status {
	return Status{
		Sc: StatusCode_KV_PATH_TOO_DEEP_ERROR,
	}
}
func NewStatusWithKvLockAlreadyHeldError() Status {
	return Status{
		Sc: StatusCode_KV_LOCK_ALREADY_HELD_ERROR,
	}
}
func NewStatusWithKvLockTimeoutError() Status {
	return Status{
		Sc: StatusCode_KV_LOCK_TIMEOUT_ERROR,
	}
}
func NewStatusWithKvRmdirNeedRecursiveError() Status {
	return Status{
		Sc: StatusCode_KV_RMDIR_NEED_RECURSIVE_ERROR,
	}
}
func NewStatusWithContextCanceledError() Status {
	return Status{
		Sc: StatusCode_CONTEXT_CANCELED_ERROR,
	}
}
func NewStatusWithNetworkConditionerError() Status {
	return Status{
		Sc: StatusCode_NETWORK_CONDITIONER_ERROR,
	}
}
func NewStatusWithWebSessionNotFoundError() Status {
	return Status{
		Sc: StatusCode_WEB_SESSION_NOT_FOUND_ERROR,
	}
}
func NewStatusWithNoActivePlanError() Status {
	return Status{
		Sc: StatusCode_NO_ACTIVE_PLAN_ERROR,
	}
}
func NewStatusWithOverQuotaError() Status {
	return Status{
		Sc: StatusCode_OVER_QUOTA_ERROR,
	}
}
func NewStatusWithPlanExistsError() Status {
	return Status{
		Sc: StatusCode_PLAN_EXISTS_ERROR,
	}
}
func NewStatusWithExpiredError() Status {
	return Status{
		Sc: StatusCode_EXPIRED_ERROR,
	}
}
func NewStatusWithStripeSessionExistsError() Status {
	return Status{
		Sc: StatusCode_STRIPE_SESSION_EXISTS_ERROR,
	}
}
func NewStatusWithSsoIdpLockedError() Status {
	return Status{
		Sc: StatusCode_SSO_IDP_LOCKED_ERROR,
	}
}
func NewStatusWithTeamInviteAlreadyAcceptedError() Status {
	return Status{
		Sc: StatusCode_TEAM_INVITE_ALREADY_ACCEPTED_ERROR,
	}
}
func NewStatusWithDeviceAlreadyProvisionedError() Status {
	return Status{
		Sc: StatusCode_DEVICE_ALREADY_PROVISIONED_ERROR,
	}
}
func NewStatusWithKvNotAvailableError() Status {
	return Status{
		Sc: StatusCode_KV_NOT_AVAILABLE_ERROR,
	}
}
func NewStatusWithYubiDefaultManagementKeyError() Status {
	return Status{
		Sc: StatusCode_YUBI_DEFAULT_MANAGEMENT_KEY_ERROR,
	}
}
func NewStatusWithYubiBadPinFormatError() Status {
	return Status{
		Sc: StatusCode_YUBI_BAD_PIN_FORMAT_ERROR,
	}
}
func NewStatusWithYubiPinRequiredError() Status {
	return Status{
		Sc: StatusCode_YUBI_PIN_REQUIRED_ERROR,
	}
}
func NewStatusWithYubiDefaultPinError() Status {
	return Status{
		Sc: StatusCode_YUBI_DEFAULT_PIN_ERROR,
	}
}
func NewStatusWithTlsError(v string) Status {
	return Status{
		Sc:    StatusCode_TLS_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithConfigError(v string) Status {
	return Status{
		Sc:    StatusCode_CONFIG_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithDuplicateError(v string) Status {
	return Status{
		Sc:    StatusCode_DUPLICATE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithReservationError(v string) Status {
	return Status{
		Sc:    StatusCode_RESERVATION_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithLinkError(v string) Status {
	return Status{
		Sc:    StatusCode_LINK_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithValidationError(v string) Status {
	return Status{
		Sc:    StatusCode_VALIDATION_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithVerifyError(v string) Status {
	return Status{
		Sc:    StatusCode_VERIFY_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithX509Error(v string) Status {
	return Status{
		Sc:    StatusCode_X509_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithPermissionError(v string) Status {
	return Status{
		Sc:    StatusCode_PERMISSION_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithPrevError(v string) Status {
	return Status{
		Sc:    StatusCode_PREV_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithBoxError(v string) Status {
	return Status{
		Sc:    StatusCode_BOX_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithInsertError(v string) Status {
	return Status{
		Sc:    StatusCode_INSERT_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithUpdateError(v string) Status {
	return Status{
		Sc:    StatusCode_UPDATE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithRevokeError(v string) Status {
	return Status{
		Sc:    StatusCode_REVOKE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithCommitmentError(v string) Status {
	return Status{
		Sc:    StatusCode_COMMITMENT_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithYubiError(v string) Status {
	return Status{
		Sc:    StatusCode_YUBI_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithHostchainError(v string) Status {
	return Status{
		Sc:    StatusCode_HOSTCHAIN_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithGrantError(v string) Status {
	return Status{
		Sc:    StatusCode_GRANT_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithNoChangeError(v string) Status {
	return Status{
		Sc:    StatusCode_NO_CHANGE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithBadArgsError(v string) Status {
	return Status{
		Sc:    StatusCode_BAD_ARGS_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithKeyNotFoundError(v string) Status {
	return Status{
		Sc:    StatusCode_KEY_NOT_FOUND_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithProtoDataError(v string) Status {
	return Status{
		Sc:    StatusCode_PROTO_DATA_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithHostMismatchError(v string) Status {
	return Status{
		Sc:    StatusCode_HOST_MISMATCH_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithBadFormatError(v string) Status {
	return Status{
		Sc:    StatusCode_BAD_FORMAT_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithAmbiguousError(v string) Status {
	return Status{
		Sc:    StatusCode_AMBIGUOUS_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithRoleError(v string) Status {
	return Status{
		Sc:    StatusCode_ROLE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithRevokeRaceError(v string) Status {
	return Status{
		Sc:    StatusCode_REVOKE_RACE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithMerkleVerifyError(v string) Status {
	return Status{
		Sc:    StatusCode_MERKLE_VERIFY_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithTeamError(v string) Status {
	return Status{
		Sc:    StatusCode_TEAM_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithTeamRaceError(v string) Status {
	return Status{
		Sc:    StatusCode_TEAM_RACE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithTeamBearerTokenStaleError(v string) Status {
	return Status{
		Sc:    StatusCode_TEAM_BEARER_TOKEN_STALE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithTeamCertError(v string) Status {
	return Status{
		Sc:    StatusCode_TEAM_CERT_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithTeamRosterError(v string) Status {
	return Status{
		Sc:    StatusCode_TEAM_ROSTER_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithTeamKeyError(v string) Status {
	return Status{
		Sc:    StatusCode_TEAM_KEY_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithTeamIndexRangeError(v string) Status {
	return Status{
		Sc:    StatusCode_TEAM_INDEX_RANGE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithTeamRemovalKeyError(v string) Status {
	return Status{
		Sc:    StatusCode_TEAM_REMOVAL_KEY_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithTeamExploreError(v string) Status {
	return Status{
		Sc:    StatusCode_TEAM_EXPLORE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithGenericNotFoundError(v string) Status {
	return Status{
		Sc:    StatusCode_GENERIC_NOT_FOUND_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithKvUploadError(v string) Status {
	return Status{
		Sc:    StatusCode_KV_UPLOAD_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithKvRaceError(v string) Status {
	return Status{
		Sc:    StatusCode_KV_RACE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithKvPathError(v string) Status {
	return Status{
		Sc:    StatusCode_KV_PATH_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithKvMkdirError(v string) Status {
	return Status{
		Sc:    StatusCode_KV_MKDIR_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithKvTypeError(v string) Status {
	return Status{
		Sc:    StatusCode_KV_TYPE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithKvNoentError(v string) Status {
	return Status{
		Sc:    StatusCode_KV_NOENT_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithGitGenericError(v string) Status {
	return Status{
		Sc:    StatusCode_GIT_GENERIC_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithGitBadPathError(v string) Status {
	return Status{
		Sc:    StatusCode_GIT_BAD_PATH_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithUpgradeNeededError(v string) Status {
	return Status{
		Sc:    StatusCode_UPGRADE_NEEDED_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithVersionNotSupportedError(v string) Status {
	return Status{
		Sc:    StatusCode_VERSION_NOT_SUPPORTED_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithHostInUseError(v string) Status {
	return Status{
		Sc:    StatusCode_HOST_IN_USE_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithOauth2Error(v string) Status {
	return Status{
		Sc:    StatusCode_OAUTH2_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithKvAbsPathError(v string) Status {
	return Status{
		Sc:    StatusCode_KV_ABS_PATH_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithYubiBusError(v string) Status {
	return Status{
		Sc:    StatusCode_YUBI_BUS_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithKeychainError(v string) Status {
	return Status{
		Sc:    StatusCode_KEYCHAIN_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithAgentConnectError(v string) Status {
	return Status{
		Sc:    StatusCode_AGENT_CONNECT_ERROR,
		F_1__: &v,
	}
}
func NewStatusWithProtoNotFoundError(v uint64) Status {
	return Status{
		Sc:    StatusCode_PROTO_NOT_FOUND_ERROR,
		F_2__: &v,
	}
}
func NewStatusWithMethodNotFoundError(v MethodV2) Status {
	return Status{
		Sc:    StatusCode_METHOD_NOT_FOUND_ERROR,
		F_3__: &v,
	}
}
func NewStatusWithKexWrapperError(v Status) Status {
	return Status{
		Sc:    StatusCode_KEX_WRAPPER_ERROR,
		F_4__: &v,
	}
}
func NewStatusWithAutocertFailedError(v Status) Status {
	return Status{
		Sc:    StatusCode_AUTOCERT_FAILED_ERROR,
		F_4__: &v,
	}
}
func NewStatusWithOauth2AuthError(v Status) Status {
	return Status{
		Sc:    StatusCode_OAUTH2_AUTH_ERROR,
		F_4__: &v,
	}
}
func NewStatusWithYubiLockedError(v YubiKeyInfoHybrid) Status {
	return Status{
		Sc:    StatusCode_YUBI_LOCKED_ERROR,
		F_5__: &v,
	}
}
func NewStatusWithHostPinError(v HostPinError) Status {
	return Status{
		Sc:    StatusCode_HOST_PIN_ERROR,
		F_6__: &v,
	}
}
func NewStatusWithSecretKeyStorageTypeError(v SecretKeyStorageType) Status {
	return Status{
		Sc:    StatusCode_SECRET_KEY_STORAGE_TYPE_ERROR,
		F_7__: &v,
	}
}
func NewStatusWithChainLoaderError(v ChainLoaderError) Status {
	return Status{
		Sc:    StatusCode_CHAIN_LOADER_ERROR,
		F_8__: &v,
	}
}
func NewStatusWithTeamPtkNotFoundError(v SharedKeyNotFound) Status {
	return Status{
		Sc:    StatusCode_TEAM_PTK_NOT_FOUND_ERROR,
		F_9__: &v,
	}
}
func NewStatusWithKvPermError(v KVPermError) Status {
	return Status{
		Sc:     StatusCode_KV_PERM_ERROR,
		F_10__: &v,
	}
}
func NewStatusWithKvStaleCacheError(v PathVersionVector) Status {
	return Status{
		Sc:     StatusCode_KV_STALE_CACHE_ERROR,
		F_11__: &v,
	}
}
func NewStatusWithSessionNotFoundError(v UISessionID) Status {
	return Status{
		Sc:     StatusCode_SESSION_NOT_FOUND_ERROR,
		F_12__: &v,
	}
}
func NewStatusWithTeamCycleError(v TeamCycleError) Status {
	return Status{
		Sc:     StatusCode_TEAM_CYCLE_ERROR,
		F_13__: &v,
	}
}
func NewStatusWithKvTooBigError(v TooBigError) Status {
	return Status{
		Sc:     StatusCode_KV_TOO_BIG_ERROR,
		F_14__: &v,
	}
}
func NewStatusWithConnectError(v ConnectError) Status {
	return Status{
		Sc:     StatusCode_CONNECT_ERROR,
		F_15__: &v,
	}
}
func NewStatusWithHttpError(v HttpError) Status {
	return Status{
		Sc:     StatusCode_HTTP_ERROR,
		F_16__: &v,
	}
}
func NewStatusWithDnsError(v DNSError) Status {
	return Status{
		Sc:     StatusCode_DNS_ERROR,
		F_17__: &v,
	}
}
func NewStatusWithSocketError(v SocketError) Status {
	return Status{
		Sc:     StatusCode_SOCKET_ERROR,
		F_18__: &v,
	}
}
func NewStatusWithOauth2TokenError(v OAuth2TokenError) Status {
	return Status{
		Sc:     StatusCode_OAUTH2_TOKEN_ERROR,
		F_19__: &v,
	}
}
func NewStatusWithOauth2IdpError(v OAuth2IdPError) Status {
	return Status{
		Sc:     StatusCode_OAUTH2_IDP_ERROR,
		F_20__: &v,
	}
}
func NewStatusWithYubiAuthError(v int64) Status {
	return Status{
		Sc:     StatusCode_YUBI_AUTH_ERROR,
		F_21__: &v,
	}
}
func NewStatusDefault(s StatusCode, v string) Status {
	return Status{
		Sc:    s,
		F_0__: &v,
	}
}
func (s StatusInternal__) Import() Status {
	return Status{
		Sc:    s.Sc,
		F_1__: s.Switch__.F_1__,
		F_2__: s.Switch__.F_2__,
		F_3__: (func(x *MethodV2Internal__) *MethodV2 {
			if x == nil {
				return nil
			}
			tmp := (func(x *MethodV2Internal__) (ret MethodV2) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_3__),
		F_4__: (func(x *StatusInternal__) *Status {
			if x == nil {
				return nil
			}
			tmp := (func(x *StatusInternal__) (ret Status) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_4__),
		F_5__: (func(x *YubiKeyInfoHybridInternal__) *YubiKeyInfoHybrid {
			if x == nil {
				return nil
			}
			tmp := (func(x *YubiKeyInfoHybridInternal__) (ret YubiKeyInfoHybrid) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_5__),
		F_6__: (func(x *HostPinErrorInternal__) *HostPinError {
			if x == nil {
				return nil
			}
			tmp := (func(x *HostPinErrorInternal__) (ret HostPinError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_6__),
		F_7__: (func(x *SecretKeyStorageTypeInternal__) *SecretKeyStorageType {
			if x == nil {
				return nil
			}
			tmp := (func(x *SecretKeyStorageTypeInternal__) (ret SecretKeyStorageType) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_7__),
		F_8__: (func(x *ChainLoaderErrorInternal__) *ChainLoaderError {
			if x == nil {
				return nil
			}
			tmp := (func(x *ChainLoaderErrorInternal__) (ret ChainLoaderError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_8__),
		F_9__: (func(x *SharedKeyNotFoundInternal__) *SharedKeyNotFound {
			if x == nil {
				return nil
			}
			tmp := (func(x *SharedKeyNotFoundInternal__) (ret SharedKeyNotFound) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_9__),
		F_10__: (func(x *KVPermErrorInternal__) *KVPermError {
			if x == nil {
				return nil
			}
			tmp := (func(x *KVPermErrorInternal__) (ret KVPermError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_10__),
		F_11__: (func(x *PathVersionVectorInternal__) *PathVersionVector {
			if x == nil {
				return nil
			}
			tmp := (func(x *PathVersionVectorInternal__) (ret PathVersionVector) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_11__),
		F_12__: (func(x *UISessionIDInternal__) *UISessionID {
			if x == nil {
				return nil
			}
			tmp := (func(x *UISessionIDInternal__) (ret UISessionID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_12__),
		F_13__: (func(x *TeamCycleErrorInternal__) *TeamCycleError {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamCycleErrorInternal__) (ret TeamCycleError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_13__),
		F_14__: (func(x *TooBigErrorInternal__) *TooBigError {
			if x == nil {
				return nil
			}
			tmp := (func(x *TooBigErrorInternal__) (ret TooBigError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_14__),
		F_15__: (func(x *ConnectErrorInternal__) *ConnectError {
			if x == nil {
				return nil
			}
			tmp := (func(x *ConnectErrorInternal__) (ret ConnectError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_15__),
		F_16__: (func(x *HttpErrorInternal__) *HttpError {
			if x == nil {
				return nil
			}
			tmp := (func(x *HttpErrorInternal__) (ret HttpError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_16__),
		F_17__: (func(x *DNSErrorInternal__) *DNSError {
			if x == nil {
				return nil
			}
			tmp := (func(x *DNSErrorInternal__) (ret DNSError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_17__),
		F_18__: (func(x *SocketErrorInternal__) *SocketError {
			if x == nil {
				return nil
			}
			tmp := (func(x *SocketErrorInternal__) (ret SocketError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_18__),
		F_19__: (func(x *OAuth2TokenErrorInternal__) *OAuth2TokenError {
			if x == nil {
				return nil
			}
			tmp := (func(x *OAuth2TokenErrorInternal__) (ret OAuth2TokenError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_19__),
		F_20__: (func(x *OAuth2IdPErrorInternal__) *OAuth2IdPError {
			if x == nil {
				return nil
			}
			tmp := (func(x *OAuth2IdPErrorInternal__) (ret OAuth2IdPError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_20__),
		F_21__: s.Switch__.F_21__,
		F_0__:  s.Switch__.F_0__,
	}
}
func (s Status) Export() *StatusInternal__ {
	return &StatusInternal__{
		Sc: s.Sc,
		Switch__: StatusInternalSwitch__{
			F_1__: s.F_1__,
			F_2__: s.F_2__,
			F_3__: (func(x *MethodV2) *MethodV2Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_3__),
			F_4__: (func(x *Status) *StatusInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_4__),
			F_5__: (func(x *YubiKeyInfoHybrid) *YubiKeyInfoHybridInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_5__),
			F_6__: (func(x *HostPinError) *HostPinErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_6__),
			F_7__: (func(x *SecretKeyStorageType) *SecretKeyStorageTypeInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_7__),
			F_8__: (func(x *ChainLoaderError) *ChainLoaderErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_8__),
			F_9__: (func(x *SharedKeyNotFound) *SharedKeyNotFoundInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_9__),
			F_10__: (func(x *KVPermError) *KVPermErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_10__),
			F_11__: (func(x *PathVersionVector) *PathVersionVectorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_11__),
			F_12__: (func(x *UISessionID) *UISessionIDInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_12__),
			F_13__: (func(x *TeamCycleError) *TeamCycleErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_13__),
			F_14__: (func(x *TooBigError) *TooBigErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_14__),
			F_15__: (func(x *ConnectError) *ConnectErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_15__),
			F_16__: (func(x *HttpError) *HttpErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_16__),
			F_17__: (func(x *DNSError) *DNSErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_17__),
			F_18__: (func(x *SocketError) *SocketErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_18__),
			F_19__: (func(x *OAuth2TokenError) *OAuth2TokenErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_19__),
			F_20__: (func(x *OAuth2IdPError) *OAuth2IdPErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_20__),
			F_21__: s.F_21__,
			F_0__:  s.F_0__,
		},
	}
}
func (s *Status) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *Status) Decode(dec rpc.Decoder) error {
	var tmp StatusInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *Status) Bytes() []byte { return nil }
