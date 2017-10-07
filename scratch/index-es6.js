import _ from 'lodash'
import * as graphql from 'graphql'
import GraphQLFactory from '../../graphql-factory/src/index' // 'graphql-factory'
import definition from './definition'
import ACLPlugin from '../index' //'../src/index'
import AccessControlList from 'acl'
import RethinkDBACLBackend from 'acl-backend-rethinkdb'
import rethinkdbdash from 'rethinkdbdash'
import http from 'http'
import Express from 'express'
import Graphiql from 'express-graphql'
import jwt from 'jsonwebtoken'

const inmem = false

const secret = 'asdfjkl12345'

let token = jwt.sign({ userId: 'admin@localhost' }, secret, { expiresIn: '7d' })

let r = rethinkdbdash()

let rethinkBackend = new RethinkDBACLBackend(r, {
  prefix: 'acl_',
  table: 'access',
  useSingle:  true,
  ensureTable: true
})

let memoryBackend = new AccessControlList.memoryBackend()
let acl = inmem ? new AccessControlList(memoryBackend) : new AccessControlList(rethinkBackend)
let plugin = new ACLPlugin(acl, { secret })

if (inmem) {
  plugin.createAdmin()
  console.log(memoryBackend)
}

let factory = GraphQLFactory(graphql)
let lib = factory.make(definition, { plugin: [ plugin ] })


// Set up express server for graphiql testing
let app = Express()
let server = http.Server(app)

_.forEach(lib._definitions.schemas, (schema, name) => {
  app.use(`/gql/${name}`, Graphiql({
    schema,
    graphiql: true,
    rootValue: {
      jwt: token
    }
  }))
})


server.listen(8087, err => {
  if (err) {
    console.error('GraphQL server failed to start', err)
    process.exit()
  }
  console.log('Started graphql server!')
})

/*
lib.Users(`query ListUsers {
  listUsers {
    id,
    name,
    email
  }
}`)
.then(res => {
  console.log(JSON.stringify(res, null, '  '))
  process.exit()
}, err => {
  console.error(err)
  process.exit()
})
*/