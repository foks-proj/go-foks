// run with:
//
//  > npm i -g pm2
//  > pm2 start
//

const lcl = require(process.cwd() + '/ecosystem.config.local.js')
const top = './'
const config = ['--config-path', top+'conf/foks.jsonnet']
const logs = top + "logs/"
const bin = top + 'bin/foks-server'

function app(name, which) {
  return {
    "exec_interpreter": "none",
    "exec_mode"  : "fork_mode",
    name: name,
    args : config.concat(which).join(' '),
    script: bin,
    error_file : logs + name + '.err.log',
    out_file : logs + name + '.out.log'
  }
}

function bash_app(name, which) {
  return {
    "exec_interpreter": "bash",
    "exec_mode"  : "fork_mode",
    name: name,
    script: top + 'bin/' + which,
    error_file : logs + name + '.err.log',
    out_file : logs + name + '.out.log'
  }
}

function apps() {
  return [
    app('reg', 'reg'),
    app('user', 'user'),
    app('merkle_query', 'merkle-query'),
    app('internal_ca', 'internal-ca'),
    app('probe', 'probe'),
    app('merkle_batcher', 'merkle-batcher'),
    app('merkle_builder', 'merkle-builder'),
    app('merkle_signer', 'merkle-signer'),
    app('queue', 'queue'),
    app('kv_store', 'kv-store'),
    app('quota', 'quota'),
    app('autocert', 'autocert'),
    bash_app('ssh-tun', 'ssh-tun.sh'),
  ].concat(lcl.beacon ? [app('beacon', 'beacon')] : [])
   .concat(lcl.web ? [app('web', 'web')] : [])
}

module.exports = {
  apps : apps()
};
