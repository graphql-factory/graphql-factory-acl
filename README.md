# graphql-factory-acl
ACL Middleware/plugin for GraphQL Factory

## About


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