export default {
  AllowItemInput: {
    type: 'Input',
    fields: {
      resources: [ 'String' ],
      permissions: [ 'String' ]
    },
    description: 'ACL permissions array allows array item'
  },
  PermissionItemInput: {
    type: 'Input',
    fields: {
      roles: [ 'String' ],
      allows: [ 'AllowItemInput' ]
    },
    description: 'ACL permissions array item'
  }
}
