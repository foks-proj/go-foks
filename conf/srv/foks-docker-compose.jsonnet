
local pre = import 'local.pre.libsonnet';

local base = pre.base({
    local top = self,
    top_dir : '../',
    keys_dir : self.top_dir + 'keys/',
    base_ext_port : 4430,
    base_int_port : self.base_ext_port + 10000,
    docker_compose : true,
    external_addr : "localhost",
    db : {
        host : "postgresql", // asigned by docker-compose
        port : 5432,         // standard PostgreSQL port
        user : "foks",
        "no-tls" : true,
    },
});

local make_listen(base, port, nm, ext) =  
    {
        port : (if ext then base.base_ext_port else base.base_int_port) + port,
        bind_addr : "0.0.0.0", // allow connections from inside the docker-compose LAN
        external_addr : (if base.docker_compose then nm else base.external_addr),
    };

local make_db(nm) = base.db + { name : nm };
local make_db_shard(nm, id, active) = 
    make_db(nm + "_" + std.toString(id)) + { active : active, id : id };

pre.final({
    local top = self,
    base : base,
    queue_service : {
        native : true
    },
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
    ],

    root_CAs: {
        probe : [ "-" ]
    },

    global_services : {
        beacon : {
            addr : "b0.foks.app:4431",
            CAs : [ "-" ],
        }
    },

    listen : {
        probe : make_listen(base, 0, "probe", true),
        reg : make_listen(base, 2, "reg", true),
        user: make_listen(base, 3, "user", true),
        kv_store : make_listen(base, 4, "kv_store", true),
        merkle_query : make_listen(base, 5, "merkle_query", true),
        internal_ca : make_listen(base, 0, "internal_ca", false),
        merkle_batcher : make_listen(base, 1, "merkle_batcher", false),
        merkle_builder : make_listen(base, 2, "merkle_builder", false),
        merkle_signer : make_listen(base, 3, "merkle_signer", false),
        queue : make_listen(base, 4, "queue", false),
        quota : make_listen(base, 5, "quota", false),
        autocert : make_listen(base, 6, "autocert", false),
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
        }
    },
    cks : {},
})