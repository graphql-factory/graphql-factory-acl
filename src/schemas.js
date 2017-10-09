import _ from 'lodash'
import { SYSTEM_PREFIX, USER_ROLE } from './const'

/**
 * Constructs a resource path or errors
 * @param args
 * @param cb
 * @returns {*}
 */
function constructPath (args, cb) {
  try {
    const {
      deny,
      schema,
      mutation,
      query,
      subscription,
      arg,
      selection
    } = args
    const resourcePath = [ schema ]
    let inherit = true

    // potentially add query, mutation, subscription
    if (query) {
      resourcePath.push('query')
      resourcePath.push(query)
    } else if (mutation) {
      resourcePath.push('mutation')
      resourcePath.push(mutation)
    } else if (subscription) {
      resourcePath.push('subscription')
      resourcePath.push(subscription)
    }

    // potentially add args, selection
    if (arg) {
      if (resourcePath.length === 1) {
        return cb(new Error('An arg path cannot be '
          + 'specified without a query, mutation, or subscription'))
      }
      resourcePath.push('args')
      resourcePath.push(arg)
      inherit = false
    } else if (selection) {
      if (resourcePath.length === 1) {
        return cb(new Error('A selection path cannot be '
          + 'specified without a query, mutation, or subscription'))
      }
      resourcePath.push('selection')
      resourcePath.push(selection)
      inherit = false
    }

    // if the path is lower than an arg or selection
    // its permissions are inherited
    if (inherit) resourcePath.push('*')

    // construct the resource
    const resource = `${deny ? '!' : ''}${resourcePath.join('.')}`
    return cb(undefined, resource)
  } catch (err) {
    return cb(err)
  }
}

export default function schemas (plugin) {
  const { schemaName, acl } = plugin

  return {
    [schemaName]: {
      query: {
        fields: {
          allowedPermissions: {
            type: 'JSON',
            description: 'Returns all the allowable permissions '
            + 'a given user have to access the given resources.',
            args: {
              userId: { type: 'String', nullable: false },
              resources: { type: [ 'String' ] }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { userId, resources } = args
              return new Promise((resolve, reject) => {
                return acl.allowedPermissions(userId, resources, (err, obj) => {
                  return err ? reject(err) : resolve(obj)
                })
              })
            },
            _factoryACL: 'read'
          },
          areAnyRolesAllowed: {
            type: 'Boolean',
            description: 'Returns true if any of the given '
            + 'roles have the right permissions.',
            args: {
              roles: { type: [ 'String' ], nullable: false },
              resource: { type: 'String', nullable: false },
              permissions: { type: [ 'String' ], nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { roles, resource, permissions } = args
              return new Promise((resolve, reject) => {
                return acl.areAnyRolesAllowed(roles, resource, permissions, (err, allowed) => {
                  return err ? reject(err) : resolve(allowed)
                })
              })
            },
            _factoryACL: 'read'
          },
          isAllowed: {
            type: 'Boolean',
            description: 'Checks if the given user is allowed to access '
            + 'the resource for the given permissions (note: it must fulfill '
            + 'all the permissions).',
            args: {
              userId: { type: 'String', nullable: false },
              resource: { type: 'String', nullable: false },
              permissions: { type: [ 'String' ], nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { userId, resource, permissions } = args
              return new Promise((resolve, reject) => {
                return acl.isAllowed(userId, resource, permissions, (err, allowed) => {
                  return err ? reject(err) : resolve(allowed)
                })
              })
            },
            _factoryACL: 'read'
          },
          listUsers: {
            type: [ 'String' ],
            description: 'Returns a list of all users currently assigned permissions',
            resolve () {
              return new Promise((resolve, reject) => {
                return acl.roleUsers(USER_ROLE, (err, users) => {
                  return err ? reject(err) : resolve(users)
                })
              })
            },
            _factoryACL: 'read'
          },
          userRoles: {
            type: [ 'String' ],
            description: 'Return all the roles from a given user.',
            args: {
              userId: { type: 'String', nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { userId } = args
              return new Promise((resolve, reject) => {
                return acl.userRoles(userId, (err, roles) => {
                  return err ? reject(err) : resolve(roles)
                })
              })
            },
            _factoryACL: 'read'
          },
          roleUsers: {
            type: [ 'String' ],
            description: 'Return all users who has a given role.',
            args: {
              role: { type: 'String', nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { role } = args
              return new Promise((resolve, reject) => {
                return acl.roleUsers(role, (err, users) => {
                  return err ? reject(err) : resolve(users)
                })
              })
            },
            _factoryACL: 'read'
          },
          hasRole: {
            type: 'Boolean',
            description: 'Return boolean whether user has the role.',
            args: {
              userId: { type: 'String', nullable: false },
              role: { type: 'String', nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { userId, role } = args
              return new Promise((resolve, reject) => {
                return acl.hasRole(userId, role, (err, hasRole) => {
                  return err ? reject(err) : resolve(hasRole)
                })
              })
            },
            _factoryACL: 'read'
          },
          whatResources: {
            type: 'JSON',
            description: 'Returns what resources a given role has permissions over.',
            args: {
              roles: { type: [ 'String' ], nullable: false },
              permissions: { type: [ 'String' ] }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { roles, permissions } = args
              return new Promise((resolve, reject) => {
                if (permissions) {
                  return acl.whatResources(roles, permissions, (err, obj) => {
                    return err ? reject(err) : resolve(obj)
                  })
                }
                return acl.whatResources(roles, (err, obj) => {
                  return err ? reject(err) : resolve(obj)
                })
              })
            },
            _factoryACL: 'read'
          }
        }
      },
      mutation: {
        fields: {
          addRoleParents: {
            type: 'Boolean',
            description: 'Adds a parent or parent list to role.',
            args: {
              role: { type: 'String', nullable: false },
              parents: { type: [ 'String' ], nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { role, parents } = args
              return new Promise((resolve, reject) => {
                return acl.addRoleParents(role, parents, err => {
                  return err ? reject(err) : resolve(true)
                })
              })
            },
            _factoryACL: 'update'
          },
          addUserRoles: {
            type: 'Boolean',
            description: 'Adds roles to a given user id.',
            args: {
              userId: { type: 'String', nullable: false },
              roles: { type: [ 'String' ], nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { userId, roles } = args
              return new Promise((resolve, reject) => {
                // always add user to its own role and user. this is a hack/workaround to
                // apply permissions on a user level as well as to list/add users
                const _roles = _.union(roles, [
                  `${SYSTEM_PREFIX}.${userId}`,
                  USER_ROLE
                ])
                return acl.addUserRoles(userId, _roles, err => {
                  return err ? reject(err) : resolve(true)
                })
              })
            },
            _factoryACL: 'update'
          },
          allow: {
            type: 'Boolean',
            description: 'Adds the given permissions to the '
            + 'given roles over the given resources.',
            args: {
              roles: { type: [ 'String' ] },
              resources: { type: [ 'String' ] },
              permissions: { type: [ 'String' ] },
              permissionsArray: { type: [ 'PermissionItemInput' ] }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { roles, resources, permissions, permissionsArray } = args
              const GraphQLError = _.get(this, 'graphql.GraphQLError', Error)
              return new Promise((resolve, reject) => {
                if (permissionsArray) {
                  return acl.allow(permissionsArray, err => {
                    return err ? reject(err) : resolve(true)
                  })
                } else if (!roles || !resources || !permissions) {
                  return reject(new GraphQLError('roles, resources, '
                    + 'and permissions are required'))
                }

                return acl.allow(roles, resources, permissions, err => {
                  return err ? reject(err) : resolve(true)
                })
              })
            },
           _factoryACL: 'update'
          },
          allowUserId: {
            type: 'Boolean',
            description: 'Allows a specific userId permissions to the '
            + 'given roles using the user\'s system generated role',
            args: {
              userId: { type: 'String', nullable: false },
              resources: { type: [ 'String' ], nullable: false },
              permissions: { type: [ 'String' ], nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { userId, resources, permissions } = args
              const roles = `${SYSTEM_PREFIX}.${userId}`
              return new Promise((resolve, reject) => {
                return acl.allow(roles, resources, permissions, err => {
                  return err ? reject(err) : resolve(true)
                })
              })
            },
            _factoryACL: 'update'
          },
          removeAllow: {
            type: 'Boolean',
            description: 'Remove permissions from the given '
            + 'resources owned by the given role.',
            args: {
              role: { type: 'String', nullable: false },
              resources: { type: [ 'String' ], nullable: false },
              permissions: { type: [ 'String' ] }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { role, resources, permissions } = args
              return new Promise((resolve, reject) => {
                return permissions
                  ? acl.removeAllow(role, resources, permissions, err => {
                    return err ? reject(err) : resolve(true)
                  })
                  : acl.removeAllow(role, resources, err => {
                    return err ? reject(err) : resolve(true)
                  })
              })
            },
            _factoryACL: 'update'
          },
          removeAllowUserId: {
            type: 'Boolean',
            description: 'Remove permissions from the given '
            + 'resources owned by the given userId.',
            args: {
              userId: { type: 'String', nullable: false },
              resources: { type: [ 'String' ], nullable: false },
              permissions: { type: [ 'String' ] }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { userId, resources, permissions } = args
              const role = `${SYSTEM_PREFIX}.${userId}`
              return new Promise((resolve, reject) => {
                return permissions
                  ? acl.removeAllow(role, resources, permissions, err => {
                    return err ? reject(err) : resolve(true)
                  })
                  : acl.removeAllow(role, resources, err => {
                    return err ? reject(err) : resolve(true)
                  })
              })
            },
            _factoryACL: 'update'
          },
          removeResource: {
            type: 'Boolean',
            description: 'Removes a resource from the system.',
            args: {
              resource: { type: 'String', nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { resource } = args
              return new Promise((resolve, reject) => {
                return acl.removeResource(resource, err => {
                  return err ? reject(err) : resolve(true)
                })
              })
            },
            _factoryACL: 'delete'
          },
          removeRole: {
            type: 'Boolean',
            description: 'Removes a role from the system.',
            args: {
              role: { type: 'String', nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { role } = args
              return new Promise((resolve, reject) => {
                if (role.match(new RegExp(`^${SYSTEM_PREFIX}.`))) {
                  return reject(new Error(`Cannot remove system role ${role}`))
                }
                return acl.removeRole(role, err => {
                  return err ? reject(err) : resolve(true)
                })
              })
            },
            _factoryACL: 'delete'
          },
          removeRoleParents: {
            type: 'Boolean',
            description: 'Removes a parent or parent list from role. '
            + 'If parents is not specified, removes all parents.',
            args: {
              role: { type: 'String', nullable: false },
              parents: { type: [ 'String' ], nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { role, parents } = args
              return new Promise((resolve, reject) => {
                return acl.removeRoleParents(role, parents, err => {
                  return err ? reject(err) : resolve(true)
                })
              })
            },
            _factoryACL: 'update'
          },
          removeUserRoles: {
            type: 'Boolean',
            description: 'Remove roles from a given user.',
            args: {
              userId: { type: 'String', nullable: false },
              roles: { type: [ 'String' ], nullable: false }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { userId, roles } = args
              return new Promise((resolve, reject) => {
                // filter out the user and self role
                const _roles = roles.filter(role => {
                  return [
                    `${SYSTEM_PREFIX}.${userId}`,
                    USER_ROLE
                  ].indexOf(role) === -1
                })
                return acl.removeUserRoles(userId, _roles, err => {
                  return err ? reject(err) : resolve(true)
                })
              })
            },
            _factoryACL: 'update'
          },
          allowGraphQL: {
            type: 'JSON',
            description: 'Allows access to GraphQL.',
            args: {
              roles: {
                type: [ 'String' ],
                nullable: false,
                description: 'Roles to add permissions for.'
              },
              permissions: {
                type: [ 'String' ],
                defaultValue: [ '*' ],
                description: 'Permissions to add.'
              },
              deny: {
                type: 'Boolean',
                defaultValue: false,
                description: 'Add the permission as an explicit deny.'
              },
              schema: {
                type: 'String',
                nullable: false,
                description: 'The schema to add the permission on.'
              },
              mutation: {
                type: 'String',
                description: 'Name of the mutation field to add a permission on.'
              },
              query: {
                type: 'String',
                description: 'Name of the query field to add a permission on.'
              },
              subscription: {
                type: 'String',
                description: 'Name of the subscription field to add a permission on.'
              },
              arg: {
                type: 'String',
                description: 'Name of the argument field to add a permission on.'
              },
              selection: {
                type: 'String',
                description: 'Name of the selection field to add a permission on.'
              }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { roles, permissions } = args

              return new Promise((resolve, reject) => {
                return constructPath(args, (pathErr, resource) => {
                  if (pathErr) return reject(pathErr)
                  const output = {
                    allowed: {
                      resource,
                      roles,
                      permissions
                    }
                  }
                  return acl.allow(roles, resource, permissions, err => {
                    return err ? reject(err) : resolve(output)
                  })
                })
              })
            },
            _factoryACL: 'update'
          },
          removeAllowGraphQL: {
            type: 'JSON',
            description: 'Removes access to GraphQL.',
            args: {
              role: {
                type: 'String',
                nullable: false,
                description: 'Role to remove permissions for.'
              },
              permissions: {
                type: [ 'String' ],
                description: 'Permissions to remove.'
              },
              deny: {
                type: 'Boolean',
                defaultValue: false,
                description: 'Permission to remove is an explicit deny.'
              },
              schema: {
                type: 'String',
                nullable: false,
                description: 'The schema to remove the permission on.'
              },
              mutation: {
                type: 'String',
                description: 'Name of the mutation field to remove a permission on.'
              },
              query: {
                type: 'String',
                description: 'Name of the query field to remove a permission on.'
              },
              subscription: {
                type: 'String',
                description: 'Name of the subscription field to remove a permission on.'
              },
              arg: {
                type: 'String',
                description: 'Name of the argument field to remove a permission on.'
              },
              selection: {
                type: 'String',
                description: 'Name of the selection field to remove a permission on.'
              }
            },
            resolve (source, args, context, info) {
              _.noop(source, context, info)
              const { role, permissions } = args

              return new Promise((resolve, reject) => {
                return constructPath(args, (pathErr, resource) => {
                  if (pathErr) return reject(pathErr)
                  const output = {
                    removed: {
                      resource,
                      role,
                      permissions
                    }
                  }
                  return permissions
                    ? acl.removeAllow(role, resource, permissions, err => {
                      return err ? reject(err) : resolve(output)
                    })
                    : acl.removeAllow(role, resource, err => {
                      return err ? reject(err) : resolve(output)
                    })
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
