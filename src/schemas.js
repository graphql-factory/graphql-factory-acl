const USER_ROLE = 'user'

export default function schemas (plugin) {
  let { schemaName, acl } = plugin

  return {
    [schemaName]: {
      query: {
        fields: {
          allowedPermissions: {
            type: 'JSON',
            args: {
              userId: { type: 'JSON', nullable: false },
              resources: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.allowedPermissions(args.userId, args.resources, (err, obj) => {
                  return err ? reject(err) : resolve(obj)
                })
              })
            },
            _factoryACL: 'read'
          },
          areAnyRolesAllowed: {
            type: 'JSON',
            args: {
              roles: { type: 'JSON', nullable: false },
              resource: { type: 'String', nullable: false },
              permissions: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.areAnyRolesAllowed(args.roles, args.resource, args.permissions, (err, allowed) => {
                  return err ? reject(err) : resolve(allowed)
                })
              })
            },
            _factoryACL: 'read'
          },
          isAllowed: {
            type: 'Boolean',
            args: {
              userId: { type: 'JSON', nullable: false },
              resource: { type: 'String', nullable: false },
              permissions: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.isAllowed(args.userId, args.resource, args.permissions, (err, allowed) => {
                  return err ? reject(err) : resolve(allowed)
                })
              })
            },
            _factoryACL: 'read'
          },
          listUsers: {
            type: 'JSON',
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.roleUsers(USER_ROLE, (err, users) => {
                  return err ? reject(err) : resolve(users)
                })
              })
            },
            _factoryACL: 'read'
          },
          userRoles: {
            type: 'JSON',
            args: {
              userId: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.userRoles(args.userId, (err, roles) => {
                  return err ? reject(err) : resolve(roles)
                })
              })
            },
            _factoryACL: 'read'
          },
          roleUsers: {
            type: 'JSON',
            args: {
              rolename: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.roleUsers(args.rolename, (err, users) => {
                  return err ? reject(err) : resolve(users)
                })
              })
            },
            _factoryACL: 'read'
          },
          hasRole: {
            type: 'Boolean',
            args: {
              userId: { type: 'JSON', nullable: false },
              rolename: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.hasRole(args.userId, args.rolename, (err, hasRole) => {
                  return err ? reject(err) : resolve(hasRole)
                })
              })
            },
            _factoryACL: 'read'
          },
          whatResources: {
            type: 'JSON',
            args: {
              role: { type: 'JSON', nullable: false },
              permissions: { type: 'JSON' }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                if (args.permissions) {
                  return acl.whatResources(args.role, args.permissions, (err, obj) => {
                    return err ? reject(err) : resolve(obj)
                  })
                }
                return acl.whatResources(args.role, (err, obj) => {
                  return err ? reject(err) : resolve(obj)
                })
              })
            },
            //_factoryACL: 'read'
          }
        }
      },
      mutation: {
        fields: {
          addRoleParents: {
            type: 'JSON',
            args: {
              role: { type: 'JSON', nullable: false },
              parents: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.addRoleParents(args.role, args.parents, err => {
                  return err ? reject(err) : resolve(null)
                })
              })
            },
            _factoryACL: 'update'
          },
          addUserRoles: {
            type: 'JSON',
            args: {
              userId: { type: 'JSON', nullable: false },
              roles: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                // always add user to its own role and user. this is a hack/workaround to
                // apply permissions on a user level as well as to list/add users
                let roles = args.roles.concat([args.userId, USER_ROLE])
                return acl.addUserRoles(args.userId, roles, err => {
                  return err ? reject(err) : resolve(null)
                })
              })
            },
            _factoryACL: 'update'
          },
          allow: {
            type: 'JSON',
            args: {
              roles: { type: 'JSON' },
              resources: { type: 'JSON' },
              permissions: { type: 'JSON' },
              permissionsArray: { type: ['JSON'] }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                if (args.permissionsArray) {
                  return acl.allow(args.permissionsArray, err => {
                    return err ? reject(err) : resolve(null)
                  })
                } else if (!args.roles || !args.resources || !args.permissions) {
                  return reject(new Error('roles, resources, and permissions are required'))
                }

                return acl.allow(args.roles, args.resources, args.permissions, err => {
                  return err ? reject(err) : resolve(null)
                })
              })
            },
            _factoryACL: 'update'
          },
          removeAllow: {
            type: 'JSON',
            args: {
              role: { type: 'String', nullable: false },
              resources: { type: 'JSON', nullable: false },
              permissions: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.removeAllow(args.roles, args.resources, args.permissions, err => {
                  return err ? reject(err) : resolve(null)
                })
              })
            },
            _factoryACL: 'update'
          },
          removeResource: {
            type: 'JSON',
            args: {
              resource: { type: 'String', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.removeResource(args.resource, err => {
                  return err ? reject(err) : resolve(null)
                })
              })
            },
            _factoryACL: 'delete'
          },
          removeRole: {
            type: 'JSON',
            args: {
              role: { type: 'String', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.removeRole(args.role, err => {
                  return err ? reject(err) : resolve(null)
                })
              })
            },
            _factoryACL: 'delete'
          },
          removeRoleParents: {
            type: 'JSON',
            args: {
              role: { type: 'String', nullable: false },
              parents: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                return acl.removeRoleParents(args.role, args.parents, err => {
                  return err ? reject(err) : resolve(null)
                })
              })
            },
            _factoryACL: 'update'
          },
          removeUserRoles: {
            type: 'JSON',
            args: {
              userId: { type: 'JSON', nullable: false },
              roles: { type: 'JSON', nullable: false }
            },
            resolve (source, args, context, info) {
              return new Promise((resolve, reject) => {
                // filter out the user and self role
                let roles = args.roles.filter(role => [args.userId, USER_ROLE].indexOf(role) === -1)
                return acl.removeUserRoles(args.userId, roles, err => {
                  return err ? reject(err) : resolve(null)
                })
              })
            },
            _factoryACL: 'update'
          }
        }
      }
    }
  }
}