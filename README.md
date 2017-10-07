# graphql-factory-acl
ACL Middleware/plugin for GraphQL Factory

## About
A `graphql-factory` plugin that provides granular control over `graphql`
operations as well as a `graphql` api for the `acl` library itself.

* [Permissions](#permissions)

## Example

```js
import * as graphql from 'graphql'
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
role as expected.

Adding permissions

```
[!]<SchemaName>.
<*|OperationName>.
<*|fieldName>.
<*|args|query>.
<*|fieldName>
[.<*|fieldName>, ...]
```

Examples
`ACL.*`
`ACL.mutation.*`
`ACL.mutation.allow.*`
`ACL.mutation.allow.args.*`
`ACL.mutation.allow.args.userId`
`ACL.mutation.allow.query.*`