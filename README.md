# graphql-factory-acl
ACL Middleware/plugin for GraphQL Factory

## About
A `graphql-factory` plugin that provides granular control over `graphql`
operations as well as a `graphql` api for the `acl` library itself.

* [Permissions](#permissions)
* [Authorization](#authorization)

## Example

```js
import * as graphql from 'graphql'
import GraphQLFactory from 'graphql-factory'
import ACLPlugin from 'graphql-factory-acl'
import ACL from 'acl'
import jwt from 'jsonwebtoken'

// import a graphql-factory definition that has been
// tagged with _factoryACL
import definition from './definition'

const userId = 'admin@localhost'
const options = { secret: 'abc123' }
const acl = new ACL(new ACL.memoryBackend())
const plugin = new ACLPlugin(acl, options)
const factory = GraphQLFactory(graphql)
const lib = factory.make(definition, {
    plugin: [ plugin ]
})

const token = jwt.sign({ userId }, options.secret)

lib.Foo(`
    query BarQuery {
        readBar {
            baz
        }
    }
`, { jwt: token })
.then(result => {
    ...
})

```

## Permissions

**Tagging**

Permissions are applied to an operation by adding them via the
`allow` mutation (or directly with an `acl` instance) and tagging
the query/mutation/subscription field with a `_factoryACL` tag who's
value is the required permission for that operation.

```js
{
  schemas: {
    Foo: {
      query: {
        fields: {
          Bar: {
            type: ['Baz'],
            resolve () {...},
            _factoryACL: 'read'
          }
        }
      }
    }
  }
}
```


**Resource Path**

Resource paths are how this plugin uniquely identifies a schema,
operation type, field, argument, and/or selection. Resource paths can
also be used to specify inherited permissions by ending the path with
an `*` which indicates that the permission be applied to that path and
everything below it.

For example

```js
// gives the admin role access to all operations in the ACL schema
acl.allow('admin', 'ACL.*', '*')

// allow users role to read all properties of the hasRole query
acl.allow('users', 'ACL.query.hasRole.*', 'read')

// allow the dev role access to read and write only the
// baz field of the mutation Bar in the schema Foo
acl.allow('dev', [
  'Foo.mutation.Bar.args.baz',
  'Foo.mutation.Bar.selection.baz'
], '*')
```

Explicit deny paths aka `!paths` can also be allowed in order to
explicitly deny access to a resource path

For example the following permissions would allow the `helpdesk` role
complete access to the `User` schema but error on any selection of
the `password` field. However setting the password is still possible
since `!User.mutation.createUser.args.password` has not been allowed

```js
acl.allow('helpdesk', [
  'User.*',
  '!User.mutation.createUser.selection.password',
  '!User.query.readUser.selection.password',
  '!User.subscription.subscribeUser.selection.password'
], '*')
```

Additionally the resource path `*` gives access to everything that is
tagged with `_factoryACL`

**Permissions**

In general when securing a graphql api using the `*` permission is
sufficient since the resource path itself contains information on
what type of operation (mutation/query/subscription) is taking place.
Named permissions can however be used to allow partial access to a
schema.

For example if you wanted to allow `users` full access to the `Foo`
schemas mutations except for the ability to delete things you can
tag all mutations that delete with a `delete` permission and the rest
with a `write` permission and use the following allow

```js
acl.allow('users', 'Foo.mutations.*', 'write')
```

When the permission for `delete` is evaulated it will fail for the `users`
role as expected. Of course an alternative is also to add an explicit deny
with `!Foo.mutations.deleteFoo.*`

## Authorization

JSON Web Tokens (`jwt`) are used for authorization. When setting up the plugin
a secret option can be supplied and will be used during verification of
any `jwt` provided in the `rootValue.jwt` property of the graphql request.

Additionally a `systemApiKey` option can be set and provided in `rootValue.apikey`
in order to give unrestricted access. This can be useful for operations like
subscriptions that run for extended periods of time and could potentially encounter
and expired `jwt`. Or event for server side scheduled tasks that require calls to the
`graphql` api.

#### JWT

JSON web tokens are used for authorization because they can be rotated and
carry information in their payload. `jwt` should be generated by an
authentication service that issues `jwt` signed with the same secret
configured on the acl plugin.

**payload**

The payload MUST be an object with a `userId` field containing the requesting
users id. If you wish to use a field other than `userId` (because your
jwt service puts it in a different path) you can set the `userIdField`
in the plugin options with a `lodash` compatible path string.

**rotating secrets**

The plugin verifies every `jwt` on each request and looks up the current
secret during that process. This is why the secret value is intentionally
stored in the plugin options object. This way you can keep a reference
to the options object in your main project and simply update the `secret`
field.

Additionally, when setting up a new ACL database or during development
you may wish to bypass ACL authentication. To bypass all ACL checks
simply do not set a secret in the options. This can be useful when
setting up a new admin user with access to the ACL api to set up
future permissions. Additionally a helper method `createAdmin` has been
provided to add complete access to the ACL schema.

## API

#### ACLPlugin (acl:Acl, options:Object)

Creates a new acl plugin

**Parameters**

* `acl` - An acl instance initialized with a backend
* `options`
  * [`schemaName=ACL`] {`string`} - Customizable graphql schema name
  * [`secret`] {`string`} - Secret to use when signing jsonwebtokens. If omitted no
  acl rules will be evaluated (should only be omitted during dev or initial setup)
  * [`systemUserId`] {`string`} - Optional userId that will not be checked against
  acl rules and will have unrestricted access to all graphql schemas.
  * [`systemApiKey`] { `string` } - Optional system apikey for unrestricted access.
  must be passed in the `rootValue.apikey` property.

## GraphQL API

The plugin provides a complete graphql api for the `acl` library and
adds additional shortcut/helper methods for managing permissions on
graphql resources. The original [`acl documentation`](https://github.com/optimalbits/node_acl)
is a good place to start for understanding the `acl` API.

Please refer to the [`ACL Schema Definition`](https://github.com/graphql-factory/graphql-factory-acl/blob/master/src/schemas.js)
for included query/mutations. Additional operations added are

* queries
  * `listUsers` - provides a list of users
* mutations
  * `allowUserId` - same as `allow` except allows a specific `userId`
  * `removeAllowUserId` - same as `removeAllow` except it removes permissions for a specific `userId`
  * `allowGraphQL` - constructs a `graphql` resource path and allows access to it
  * `removeAllowGraphQL` - constructs a `graphql` resource path and removes access to it

