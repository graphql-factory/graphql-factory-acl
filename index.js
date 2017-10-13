'use strict';

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var _ = _interopDefault(require('lodash'));
var jwt = _interopDefault(require('jsonwebtoken'));

var ADMIN_ROLE = 'admin';
var SYSTEM_PREFIX = '__system';
var USER_ROLE = SYSTEM_PREFIX + '.user';

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

/**
 * Constructs a resource path or errors
 * @param args
 * @param cb
 * @returns {*}
 */
function constructPath(args, cb) {
  try {
    var deny = args.deny,
        schema = args.schema,
        mutation = args.mutation,
        query = args.query,
        subscription = args.subscription,
        arg = args.arg,
        selection = args.selection;

    var resourcePath = [schema];
    var inherit = true;

    // potentially add query, mutation, subscription
    if (query) {
      resourcePath.push('query');
      resourcePath.push(query);
    } else if (mutation) {
      resourcePath.push('mutation');
      resourcePath.push(mutation);
    } else if (subscription) {
      resourcePath.push('subscription');
      resourcePath.push(subscription);
    }

    // potentially add args, selection
    if (arg) {
      if (resourcePath.length === 1) {
        return cb(new Error('An arg path cannot be ' + 'specified without a query, mutation, or subscription'));
      }
      resourcePath.push('args');
      resourcePath.push(arg);
      inherit = false;
    } else if (selection) {
      if (resourcePath.length === 1) {
        return cb(new Error('A selection path cannot be ' + 'specified without a query, mutation, or subscription'));
      }
      resourcePath.push('selection');
      resourcePath.push(selection);
      inherit = false;
    }

    // if the path is lower than an arg or selection
    // its permissions are inherited
    if (inherit) resourcePath.push('*');

    // construct the resource
    var resource = '' + (deny ? '!' : '') + resourcePath.join('.');
    return cb(undefined, resource);
  } catch (err) {
    return cb(err);
  }
}

function schemas(plugin) {
  var schemaName = plugin.schemaName,
      acl = plugin.acl;


  return _defineProperty({}, schemaName, {
    query: {
      fields: {
        allowedPermissions: {
          type: 'JSON',
          description: 'Returns all the allowable permissions ' + 'a given user have to access the given resources.',
          args: {
            userId: { type: 'String', nullable: false },
            resources: { type: ['String'] }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var userId = args.userId,
                resources = args.resources;

            return new Promise(function (resolve, reject) {
              return acl.allowedPermissions(userId, resources, function (err, obj) {
                return err ? reject(err) : resolve(obj);
              });
            });
          },

          _factoryACL: 'read'
        },
        areAnyRolesAllowed: {
          type: 'Boolean',
          description: 'Returns true if any of the given ' + 'roles have the right permissions.',
          args: {
            roles: { type: ['String'], nullable: false },
            resource: { type: 'String', nullable: false },
            permissions: { type: ['String'], nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var roles = args.roles,
                resource = args.resource,
                permissions = args.permissions;

            return new Promise(function (resolve, reject) {
              return acl.areAnyRolesAllowed(roles, resource, permissions, function (err, allowed) {
                return err ? reject(err) : resolve(allowed);
              });
            });
          },

          _factoryACL: 'read'
        },
        isAllowed: {
          type: 'Boolean',
          description: 'Checks if the given user is allowed to access ' + 'the resource for the given permissions (note: it must fulfill ' + 'all the permissions).',
          args: {
            userId: { type: 'String', nullable: false },
            resource: { type: 'String', nullable: false },
            permissions: { type: ['String'], nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var userId = args.userId,
                resource = args.resource,
                permissions = args.permissions;

            return new Promise(function (resolve, reject) {
              return acl.isAllowed(userId, resource, permissions, function (err, allowed) {
                return err ? reject(err) : resolve(allowed);
              });
            });
          },

          _factoryACL: 'read'
        },
        listUsers: {
          type: ['String'],
          description: 'Returns a list of all users currently assigned permissions',
          resolve: function resolve() {
            return new Promise(function (resolve, reject) {
              return acl.roleUsers(USER_ROLE, function (err, users) {
                return err ? reject(err) : resolve(users);
              });
            });
          },

          _factoryACL: 'read'
        },
        userRoles: {
          type: ['String'],
          description: 'Return all the roles from a given user.',
          args: {
            userId: { type: 'String', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var userId = args.userId;

            return new Promise(function (resolve, reject) {
              return acl.userRoles(userId, function (err, roles) {
                return err ? reject(err) : resolve(roles);
              });
            });
          },

          _factoryACL: 'read'
        },
        roleUsers: {
          type: ['String'],
          description: 'Return all users who has a given role.',
          args: {
            role: { type: 'String', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var role = args.role;

            return new Promise(function (resolve, reject) {
              return acl.roleUsers(role, function (err, users) {
                return err ? reject(err) : resolve(users);
              });
            });
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
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var userId = args.userId,
                role = args.role;

            return new Promise(function (resolve, reject) {
              return acl.hasRole(userId, role, function (err, hasRole) {
                return err ? reject(err) : resolve(hasRole);
              });
            });
          },

          _factoryACL: 'read'
        },
        whatResources: {
          type: 'JSON',
          description: 'Returns what resources a given role has permissions over.',
          args: {
            roles: { type: ['String'], nullable: false },
            permissions: { type: ['String'] }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var roles = args.roles,
                permissions = args.permissions;

            return new Promise(function (resolve, reject) {
              if (permissions) {
                return acl.whatResources(roles, permissions, function (err, obj) {
                  return err ? reject(err) : resolve(obj);
                });
              }
              return acl.whatResources(roles, function (err, obj) {
                return err ? reject(err) : resolve(obj);
              });
            });
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
            parents: { type: ['String'], nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var role = args.role,
                parents = args.parents;

            return new Promise(function (resolve, reject) {
              return acl.addRoleParents(role, parents, function (err) {
                return err ? reject(err) : resolve(true);
              });
            });
          },

          _factoryACL: 'update'
        },
        addUserRoles: {
          type: 'Boolean',
          description: 'Adds roles to a given user id.',
          args: {
            userId: { type: 'String', nullable: false },
            roles: { type: ['String'], nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var userId = args.userId,
                roles = args.roles;

            return new Promise(function (resolve, reject) {
              // always add user to its own role and user. this is a hack/workaround to
              // apply permissions on a user level as well as to list/add users
              var _roles = _.union(roles, [SYSTEM_PREFIX + '.' + userId, USER_ROLE]);
              return acl.addUserRoles(userId, _roles, function (err) {
                return err ? reject(err) : resolve(true);
              });
            });
          },

          _factoryACL: 'update'
        },
        allow: {
          type: 'Boolean',
          description: 'Adds the given permissions to the ' + 'given roles over the given resources.',
          args: {
            roles: { type: ['String'] },
            resources: { type: ['String'] },
            permissions: { type: ['String'] },
            permissionsArray: { type: ['PermissionItemInput'] }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var roles = args.roles,
                resources = args.resources,
                permissions = args.permissions,
                permissionsArray = args.permissionsArray;

            var GraphQLError = _.get(this, 'graphql.GraphQLError', Error);
            return new Promise(function (resolve, reject) {
              if (permissionsArray) {
                return acl.allow(permissionsArray, function (err) {
                  return err ? reject(err) : resolve(true);
                });
              } else if (!roles || !resources || !permissions) {
                return reject(new GraphQLError('roles, resources, ' + 'and permissions are required'));
              }

              return acl.allow(roles, resources, permissions, function (err) {
                return err ? reject(err) : resolve(true);
              });
            });
          },

          _factoryACL: 'update'
        },
        allowUserId: {
          type: 'Boolean',
          description: 'Allows a specific userId permissions to the ' + 'given roles using the user\'s system generated role',
          args: {
            userId: { type: 'String', nullable: false },
            resources: { type: ['String'], nullable: false },
            permissions: { type: ['String'], nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var userId = args.userId,
                resources = args.resources,
                permissions = args.permissions;

            var roles = SYSTEM_PREFIX + '.' + userId;
            return new Promise(function (resolve, reject) {
              return acl.allow(roles, resources, permissions, function (err) {
                return err ? reject(err) : resolve(true);
              });
            });
          },

          _factoryACL: 'update'
        },
        removeAllow: {
          type: 'Boolean',
          description: 'Remove permissions from the given ' + 'resources owned by the given role.',
          args: {
            role: { type: 'String', nullable: false },
            resources: { type: ['String'], nullable: false },
            permissions: { type: ['String'] }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var role = args.role,
                resources = args.resources,
                permissions = args.permissions;

            return new Promise(function (resolve, reject) {
              return permissions ? acl.removeAllow(role, resources, permissions, function (err) {
                return err ? reject(err) : resolve(true);
              }) : acl.removeAllow(role, resources, function (err) {
                return err ? reject(err) : resolve(true);
              });
            });
          },

          _factoryACL: 'update'
        },
        removeAllowUserId: {
          type: 'Boolean',
          description: 'Remove permissions from the given ' + 'resources owned by the given userId.',
          args: {
            userId: { type: 'String', nullable: false },
            resources: { type: ['String'], nullable: false },
            permissions: { type: ['String'] }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var userId = args.userId,
                resources = args.resources,
                permissions = args.permissions;

            var role = SYSTEM_PREFIX + '.' + userId;
            return new Promise(function (resolve, reject) {
              return permissions ? acl.removeAllow(role, resources, permissions, function (err) {
                return err ? reject(err) : resolve(true);
              }) : acl.removeAllow(role, resources, function (err) {
                return err ? reject(err) : resolve(true);
              });
            });
          },

          _factoryACL: 'update'
        },
        removeResource: {
          type: 'Boolean',
          description: 'Removes a resource from the system.',
          args: {
            resource: { type: 'String', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var resource = args.resource;

            return new Promise(function (resolve, reject) {
              return acl.removeResource(resource, function (err) {
                return err ? reject(err) : resolve(true);
              });
            });
          },

          _factoryACL: 'delete'
        },
        removeRole: {
          type: 'Boolean',
          description: 'Removes a role from the system.',
          args: {
            role: { type: 'String', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var role = args.role;

            return new Promise(function (resolve, reject) {
              if (role.match(new RegExp('^' + SYSTEM_PREFIX + '.'))) {
                return reject(new Error('Cannot remove system role ' + role));
              }
              return acl.removeRole(role, function (err) {
                return err ? reject(err) : resolve(true);
              });
            });
          },

          _factoryACL: 'delete'
        },
        removeRoleParents: {
          type: 'Boolean',
          description: 'Removes a parent or parent list from role. ' + 'If parents is not specified, removes all parents.',
          args: {
            role: { type: 'String', nullable: false },
            parents: { type: ['String'], nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var role = args.role,
                parents = args.parents;

            return new Promise(function (resolve, reject) {
              return acl.removeRoleParents(role, parents, function (err) {
                return err ? reject(err) : resolve(true);
              });
            });
          },

          _factoryACL: 'update'
        },
        removeUserRoles: {
          type: 'Boolean',
          description: 'Remove roles from a given user.',
          args: {
            userId: { type: 'String', nullable: false },
            roles: { type: ['String'], nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var userId = args.userId,
                roles = args.roles;

            return new Promise(function (resolve, reject) {
              // filter out the user and self role
              var _roles = roles.filter(function (role) {
                return [SYSTEM_PREFIX + '.' + userId, USER_ROLE].indexOf(role) === -1;
              });
              return acl.removeUserRoles(userId, _roles, function (err) {
                return err ? reject(err) : resolve(true);
              });
            });
          },

          _factoryACL: 'update'
        },
        allowGraphQL: {
          type: 'JSON',
          description: 'Allows access to GraphQL.',
          args: {
            roles: {
              type: ['String'],
              nullable: false,
              description: 'Roles to add permissions for.'
            },
            permissions: {
              type: ['String'],
              defaultValue: ['*'],
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
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var roles = args.roles,
                permissions = args.permissions;


            return new Promise(function (resolve, reject) {
              return constructPath(args, function (pathErr, resource) {
                if (pathErr) return reject(pathErr);
                var output = {
                  allowed: {
                    resource: resource,
                    roles: roles,
                    permissions: permissions
                  }
                };
                return acl.allow(roles, resource, permissions, function (err) {
                  return err ? reject(err) : resolve(output);
                });
              });
            });
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
              type: ['String'],
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
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            var role = args.role,
                permissions = args.permissions;


            return new Promise(function (resolve, reject) {
              return constructPath(args, function (pathErr, resource) {
                if (pathErr) return reject(pathErr);
                var output = {
                  removed: {
                    resource: resource,
                    role: role,
                    permissions: permissions
                  }
                };
                return permissions ? acl.removeAllow(role, resource, permissions, function (err) {
                  return err ? reject(err) : resolve(output);
                }) : acl.removeAllow(role, resource, function (err) {
                  return err ? reject(err) : resolve(output);
                });
              });
            });
          },

          _factoryACL: 'update'
        }
      }
    }
  });
}

var typesDef = {
  AllowItemInput: {
    type: 'Input',
    fields: {
      resources: ['String'],
      permissions: ['String']
    },
    description: 'ACL permissions array allows array item'
  },
  PermissionItemInput: {
    type: 'Input',
    fields: {
      roles: ['String'],
      allows: ['AllowItemInput']
    },
    description: 'ACL permissions array item'
  }
};

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

/**
 * Creates a list of resource paths the user is requesting access to
 * which includes not paths, selection paths, and args paths
 * @param info
 * @param args
 * @param schemaName
 * @returns {[null]}
 */
function buildResources(info, args, schemaName) {
  var paths = [];
  var op = _.get(info, 'operation.operation');

  // recursive function to traverse selections adding paths
  var traverseSelections = function traverseSelections(selectionSet, path, _paths) {
    if (!selectionSet) return _paths.push(path.join('.'));

    _.forEach(selectionSet.selections, function (sel) {
      var p = path.slice();
      p.push(sel.name.value);
      if (sel.selectionSet) _paths.push(p.concat('*').join('.'));
      traverseSelections(sel.selectionSet, p, _paths);
    });
  };

  var traverseArgs = function traverseArgs(obj, path, _paths) {
    if (!_.isObject(obj) || _.isArray(obj)) return _paths.push(path.join('.'));

    _.forEach(obj, function (val, name) {
      var p = path.slice();
      p.push(name);
      if (_.isObject(obj[name]) && !_.isArray(obj[name])) {
        _paths.push(p.concat('*').join('.'));
      }
      traverseArgs(obj[name], p, _paths);
    });
  };

  _.forEach(info.fieldNodes || info.fieldASTs, function (node) {
    var field = node.name.value;
    var base = [schemaName, op, field];
    var notBase = ['!' + schemaName, op, field];

    paths.push('*');
    paths.push(schemaName + '.*');
    paths.push(schemaName + '.' + op + '.*');
    paths.push(schemaName + '.' + op + '.' + field + '.*');
    paths.push(schemaName + '.' + op + '.' + field + '.selection.*');
    paths.push(schemaName + '.' + op + '.' + field + '.args.*');

    traverseSelections(node.selectionSet, notBase.slice().concat('selection'), paths);
    traverseSelections(node.selectionSet, base.slice().concat('selection'), paths);
    if (args) {
      traverseArgs(args, notBase.slice().concat('args'), paths);
      traverseArgs(args, base.slice().concat('args'), paths);
    }
  });

  return [].concat(_toConsumableArray(new Set(paths)));
}

/**
 * creates paths for the requested selections and args
 * @param info
 * @param args
 * @param basePath
 * @returns {Array}
 */
function createRequestPaths(info, args, basePath) {
  var paths = [];
  var traverseSelections = function traverseSelections(selectionSet, path) {
    if (!_.get(selectionSet, 'selections')) return;
    _.forEach(selectionSet.selections, function (sel) {
      var p = path.slice();
      p.push(sel.name.value);
      paths.push(p.join('.'));
      traverseSelections(sel.selectionSet, p);
    });
  };

  var traverseArgs = function traverseArgs(a, path) {
    if (!_.isObject(a) || _.isArray(a)) return;
    _.forEach(a, function (val, key) {
      var p = path.slice();
      p.push(key);
      paths.push(p.join('.'));
      traverseArgs(val, p);
    });
  };

  _.forEach(info.fieldNodes || info.fieldASTs, function (node) {
    traverseSelections(node.selectionSet, [basePath, 'selection']);
  });

  traverseArgs(args, [basePath, 'args']);
  return paths;
}

/**
 * @description GraphQLFactoryACLPlugin provides granular ACL control on graphql requests.
 * It also provides a graphql api for the ACL library.
 */

var GraphQLFactoryACLPlugin = function () {
  function GraphQLFactoryACLPlugin(acl, options) {
    _classCallCheck(this, GraphQLFactoryACLPlugin);

    var opts = _.isObject(options) ? options : {};
    this.schemaName = _.isString(opts.schemaName) && opts.schemaName ? opts.schemaName : 'ACL';

    this.systemUserId = _.isString(opts.systemUserId) && opts.systemUserId ? opts.systemUserId : undefined;

    this.options = opts;
    this.acl = acl;
  }

  _createClass(GraphQLFactoryACLPlugin, [{
    key: 'createAdmin',
    value: function createAdmin(adminId) {
      var _this2 = this;

      var _adminId = _.isString(adminId) && adminId ? adminId : 'admin@localhost';
      var resources = this.schemaName + '.*';
      var roles = [ADMIN_ROLE, USER_ROLE, SYSTEM_PREFIX + '.' + adminId];
      return new Promise(function (resolve, reject) {
        try {
          return _this2.acl.addUserRoles(_adminId, roles, function (err) {
            if (err) return reject(err);
            return _this2.acl.allow(ADMIN_ROLE, resources, '*', function (allowErr) {
              return allowErr ? reject(allowErr) : resolve({
                enforced: [{
                  apply: true,
                  user: adminId,
                  roles: [ADMIN_ROLE]
                }, {
                  apply: true,
                  roles: [ADMIN_ROLE],
                  resources: resources
                }]
              });
            });
          });
        } catch (err) {
          return reject(err);
        }
      });
    }

    /**
     * Returns the types
     * @returns {{}}
     */

  }, {
    key: 'install',


    /**
     * Installs the ACL plugin in graphql-factory
     * @param definition
     */
    value: function install(definition) {
      var _this = this;
      var acl = this.acl;

      // make sure the types plugin is registered
      definition.registerPlugin('types');

      // add the acl middleware
      definition.beforeResolve(function (resolverArgs, next) {
        try {
          var requiredPerm = _.get(this, 'fieldDef._factoryACL');
          var secret = _.get(_this.options, 'secret');
          var args = resolverArgs.args,
              info = resolverArgs.info;

          // if no jwt secret has been provided authentication is disabled
          // or if not marked as an ACL continue to the next middleware

          if (!requiredPerm || !secret) return next();

          // check for system api key
          var apikey = _.get(info, 'rootValue.apikey');
          if (apikey && _this.options.systemApiKey === apikey) return next();

          // otherwise continue acl check
          var errors = [];
          var GraphQLError = this.graphql.GraphQLError;
          var op = _.get(info, 'operation.operation');
          var userIdField = _.get(_this.options, 'userIdField', 'userId');
          var schemaName = info.schema._factory.key;
          var basePath = schemaName + '.' + op + '.' + info.fieldName;
          var requiredPerms = [requiredPerm, '*'];
          var token = _.get(info, 'rootValue.jwt');

          // check that the secret is in the correct format
          if (!_.isString(secret) && !(secret instanceof Buffer)) {
            // log a warning to the factory
            var secretErr = new Error('ACLError: The secret provided ' + 'by the application is incorrectly formatted, ' + 'please contact your system admin');
            definition.log('warn', 'acl-plugin', secretErr.message);
            return next(secretErr);
          }

          // check for jwt in the rootValue
          if (!token || !_.isString(token)) {
            return next(new Error('No jwt was provided in the rootValue ' + 'of the request (rootValue.jwt)'));
          }

          return jwt.verify(token, secret, function (jwtErr, decoded) {
            if (jwtErr) return next(jwtErr);
            var userId = _.get(decoded, userIdField);
            if (!userId) return next(new Error('No userId found in the provided jwt'));

            // check for system user
            if (_this.systemUserId && userId === _this.systemUserId) return next();

            // otherwise build resource and request paths
            var resources = buildResources(info, args, schemaName);
            var reqPaths = createRequestPaths(info, args, basePath);

            // get all permissions for the user on the current request
            return acl.allowedPermissions(userId, resources, function (aclErr, list) {
              if (aclErr) return next(aclErr);

              // check that there are some permissions, if not then the userid has no access
              if (!Object.keys(_.pickBy(list, function (perm) {
                return perm.length > 0;
              })).length) {
                return next(new Error('User "' + userId + '" has no permissions on "' + basePath + '"'));
              }

              // check if the not list contains the argument
              reqPaths.map(function (v) {
                return '!' + v;
              }).forEach(function (p) {
                var perms = _.union(_.get(list, p, []), _.get(list, p + '.*', []));
                if (perms.length) errors.push(p.replace(/^!/, ''));
              });

              // check each field
              reqPaths.forEach(function (v) {
                // check all permutations of privileges on the current path
                // and reduce those perms to a list that can be evaluated
                // against the required permissions
                var perms = _.reduce(v.split('.'), function (accum, part) {
                  accum.path.push(part);
                  var perm = _.union(_.get(list, '*'), _.get(list, accum.path.join('.')), _.get(list, accum.path.concat('*').join('.')));
                  accum.perm = _.union(accum.perm, perm);
                  return accum;
                }, { path: [], perm: [] }).perm;

                if (!_.intersection(perms, requiredPerms).length) {
                  errors.push(v);
                }
              });

              // return the response
              return errors.length ? next(new GraphQLError('Insufficient permissions on ' + errors + ' for userId "' + userId + '"')) : next();
            });
          });
        } catch (err) {
          return next(err);
        }
      });
    }
  }, {
    key: 'types',
    get: function get() {
      return typesDef;
    }

    /**
     * Returns a schema that acts as a graphql api for the ACL library.
     * @returns {{}}
     */

  }, {
    key: 'schemas',
    get: function get() {
      return schemas(this);
    }
  }]);

  return GraphQLFactoryACLPlugin;
}();

module.exports = GraphQLFactoryACLPlugin;
