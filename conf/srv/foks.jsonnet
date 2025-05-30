
local pre = import 'local.pre.libsonnet';
local post = import 'local.post.libsonnet';

local base = pre.base({
    local top = self,
    localhost_test : false,
    top_dir : '../',
    keys_dir : self.top_dir + 'keys/',
    certs_dir : self.top_dir + 'tls/',
    vhosts_dir : self.top_dir + 'vhosts/',
    vanity_rootpki_dir : self.top_dir + 'vanity/rootpki/',
    vanity_hostchain_dir : self.top_dir + 'vanity/hostchain/',
    ca : self.certs_dir + "main.rootca.cert",
    probe_ca : self.certs_dir + "probe_ca.rootca.cert",
    bind_addr_ext : "127.0.0.1",
    bind_addr_int : "127.0.0.1",
    external_addr : "localhost",
    internal_addr : "localhost",
    base_ext_port : 4430,
    base_int_port : self.base_ext_port + 10000,
    web_ports : {
        internal : 443,
        external : 443,
    },
    probe_port : self.base_ext_port,
    beacon : {
        hostname : "localhost",
        port : top.base_ext_port + 1,
    },
    autocert_port : 80,
    db : {
        host : "127.0.0.1",
        port : 54320,
        user : "foks",
        "no-tls" : true,
    },
});

local make_listen(base, port, nm, ext, user_ca) = 
    if ext then {
        port : base.base_ext_port + port,
        bind_addr : base.bind_addr_ext,
        external_addr : base.external_addr,
    } else {
        port : base.base_int_port + port,
        bind_addr : base.bind_addr_int,
        external_addr : base.internal_addr,
    };

local make_listen_probe(base, port) = 
    make_listen(base, port, "probe", true, false);

local make_listen_web(base) =
    {
        bind_addr : base.bind_addr_ext,
        external_addr : base.external_addr,
        port : base.web_ports.internal,
    };

// make_listen_ufs creates listen blocks for User-Facing-Servers (UFSs)
// that are signed by the hostchain-based CA, and not by the root CAs like
// Let's Encrypt.
local make_listen_ufs(base, port, name, user_ca) = 
    make_listen(base, port, name, true, user_ca);

local make_db(nm) = base.db + { name : nm };
local make_db_shard(nm, id, active) = 
    make_db(nm + "_" + std.toString(id)) + { active : active, id : id };

local test_dns_aliases(base, final) = if base.localhost_test then [
        {
            from : base.external_addr,
            to : "localhost"
        } ] + [
            {
                from : "*." + x.domain,
                to : "localhost"
            } for x in final.vhosts.canned_domains
        ] else []
;


post.final(pre.final({
    local top = self,
    base : base,
    queue_service : {
        native : true
    },
    autocert_service : { bind_port : base.autocert_port },
    host_id : {
        short : 1,
    },
    db : {
        template1 : make_db("template1"),
        foks_users : make_db("foks_users"),
        foks_queue_service : make_db("foks_queue_service"),
        foks_merkle_raft : make_db("foks_merkle_raft"),
        foks_server_config : make_db("foks_server_config"),
        foks_beacon : make_db("foks_beacon"),
        foks_merkle_tree : make_db("foks_merkle_tree"),
    },

    db_kv_shards : [
        make_db_shard("foks_kv_store", 1, true),
        make_db_shard("foks_kv_store", 2, true)
    ],

    root_CAs: {
        backend : [], 
        frontend : [],
        probe : [ "-" ] + if base.localhost_test then [ base.probe_ca ] else [],
    },

    global_services : {
        beacon : {
            addr : base.beacon.hostname + ":" + base.beacon.port,
            CAs : [ "-" ] + if base.localhost_test then [ base.probe_ca ] else [],
        }
    },

    vhosts : {
        private_keys_dir : base.vhosts_dir,
        vanity : {
            dns_resolvers : {
                hosts : [
                    "1.1.1.1",
                    "8.8.8.8"
                ],
                timeout : "10s",
            },
        },
        dns_set_strategy : "aws",
    },

    listen : {
        probe : make_listen_probe(base, 0),
        beacon : make_listen(base, 1, "beacon", true, false) + {
            external_addr : base.beacon.hostname,
        },
        reg : make_listen_ufs(base, 2, "reg", false),
        user: make_listen_ufs(base, 3, "user", true),
        kv_store : make_listen_ufs(base, 4, "kv_store", true),
        merkle_query : make_listen_ufs(base, 5, "merkle_query", false),
        internal_ca : make_listen(base, 0, "internal_ca", false, false),
        merkle_batcher : make_listen(base, 1, "merkle_batcher", false, true),
        merkle_builder : make_listen(base, 2, "merkle_builder", false, true),
        merkle_signer : make_listen(base, 3, "merkle_signer", false, true),
        queue : make_listen(base, 4, "queue", false, true),
        quota : make_listen(base, 5, "quota", false, true),
        autocert : make_listen(base, 6, "autocert", false, true),
        web : make_listen_web(base)
    },

    apps : {
        reg : {
            username_resrvation_timeout_sec : 7200,
        },
        user : {
            bad_login_rate_limit : {
                num : 8,
                window_secs : 60,
            }
        },
        merkle : {
            poll_wait_msec : 1000,
            runlock_timeout_sec : 30,
            work_timeout_sec : 60,
            batch_size : 10,
            signing_key : base.keys_dir + "merkle.host.key",
        },
        kv_store : {
            blob_store_path : "sql"
        },
        web : {
            use_tls : base.web_use_tls,
            external_port : base.web_ports.external,
            session_duration : "240h",
            session_param : "s",
            debug_delay : "1s"
        }
    },
    stripe : {},
    cks : {},
    dns_aliases : [] + test_dns_aliases(base, self),
}))