require('babel-register')
var AccessControlList = require('acl')
var RethinkDBACLBackend = require('../../node-acl-backend-rethink/src/index').default //'acl-backend-rethinkdb'
var rethinkdbdash = require('rethinkdbdash')
var ACLPlugin = require('../src/index').default

var r = rethinkdbdash()
var acl = new AccessControlList(new RethinkDBACLBackend(r, {
  prefix: 'acl_',
  table: 'access',
  useSingle:  true,
  ensureTable: true
}))

var plugin = new ACLPlugin(acl)

plugin.createAdmin().then(res => {
  console.log(JSON.stringify(res, null, '  '))
  r.getPoolMaster().drain()
  process.exit()
}, err => {
  console.error(err)
  r.getPoolMaster().drain()
  process.exit()
})

