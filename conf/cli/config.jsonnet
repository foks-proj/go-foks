local lcl = import 'local.libsonnet';
local ret = {
    probe_root_CAs : [ "-" ],
    hosts : {
        probe : lcl.primary_hostname + ":4430",
        beacon : lcl.primary_hostname + ":4431"
    },
    debug : {
       	spinners : true
    },
    local_keyring : {
   	    default_encryption_mode : "passphrase"
    },
    dns_aliases : [],
} + if lcl.test then {
    probe_root_CAs +: [ lcl.top_dir + "/srv/tls/probe_ca.rootca.cert" ],
    dns_aliases +: [
        {
            from : lcl.primary_hostname,
            to : "localhost"
        },
        {
            from : lcl.big_top_hostname,
            to : "localhost"
        },
        {
            from : lcl.mgmt_hostname,
            to : "localhost"
        }
    ] + if std.length(lcl.canned_domain) > 0 then [
        {
            from : "*." + lcl.canned_domain,
            to : "localhost"
        }
    ] else []
} else {};

ret