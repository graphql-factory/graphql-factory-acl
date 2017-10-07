'use strict';

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var _ = _interopDefault(require('lodash'));
var jwt = _interopDefault(require('jsonwebtoken'));

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var USER_ROLE = 'user';

function schemas(plugin) {
  var schemaName = plugin.schemaName,
      acl = plugin.acl;


  return _defineProperty({}, schemaName, {
    query: {
      fields: {
        allowedPermissions: {
          type: 'JSON',
          args: {
            userId: { type: 'JSON', nullable: false },
            resources: { type: 'JSON', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              return acl.allowedPermissions(args.userId, args.resources, function (err, obj) {
                return err ? reject(err) : resolve(obj);
              });
            });
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
          args: {
            userId: { type: 'JSON', nullable: false },
            resource: { type: 'String', nullable: false },
            permissions: { type: 'JSON', nullable: false }
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
          type: 'JSON',
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              return acl.roleUsers(USER_ROLE, function (err, users) {
                return err ? reject(err) : resolve(users);
              });
            });
          },

          _factoryACL: 'read'
        },
        userRoles: {
          type: 'JSON',
          args: {
            userId: { type: 'JSON', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              return acl.userRoles(args.userId, function (err, roles) {
                return err ? reject(err) : resolve(roles);
              });
            });
          },

          _factoryACL: 'read'
        },
        roleUsers: {
          type: 'JSON',
          args: {
            rolename: { type: 'JSON', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              return acl.roleUsers(args.rolename, function (err, users) {
                return err ? reject(err) : resolve(users);
              });
            });
          },

          _factoryACL: 'read'
        },
        hasRole: {
          type: 'Boolean',
          args: {
            userId: { type: 'JSON', nullable: false },
            rolename: { type: 'JSON', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              return acl.hasRole(args.userId, args.rolename, function (err, hasRole) {
                return err ? reject(err) : resolve(hasRole);
              });
            });
          },

          _factoryACL: 'read'
        },
        whatResources: {
          type: 'JSON',
          args: {
            role: { type: 'JSON', nullable: false },
            permissions: { type: 'JSON' }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              if (args.permissions) {
                return acl.whatResources(args.role, args.permissions, function (err, obj) {
                  return err ? reject(err) : resolve(obj);
                });
              }
              return acl.whatResources(args.role, function (err, obj) {
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
          type: 'JSON',
          args: {
            role: { type: 'JSON', nullable: false },
            parents: { type: 'JSON', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              return acl.addRoleParents(args.role, args.parents, function (err) {
                return err ? reject(err) : resolve(null);
              });
            });
          },

          _factoryACL: 'update'
        },
        addUserRoles: {
          type: 'JSON',
          args: {
            userId: { type: 'JSON', nullable: false },
            roles: { type: 'JSON', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              // always add user to its own role and user. this is a hack/workaround to
              // apply permissions on a user level as well as to list/add users
              var roles = args.roles.concat([args.userId, USER_ROLE]);
              return acl.addUserRoles(args.userId, roles, function (err) {
                return err ? reject(err) : resolve(null);
              });
            });
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
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              if (args.permissionsArray) {
                return acl.allow(args.permissionsArray, function (err) {
                  return err ? reject(err) : resolve(null);
                });
              } else if (!args.roles || !args.resources || !args.permissions) {
                return reject(new Error('roles, resources, and permissions are required'));
              }

              return acl.allow(args.roles, args.resources, args.permissions, function (err) {
                return err ? reject(err) : resolve(null);
              });
            });
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
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              return acl.removeAllow(args.roles, args.resources, args.permissions, function (err) {
                return err ? reject(err) : resolve(null);
              });
            });
          },

          _factoryACL: 'update'
        },
        removeResource: {
          type: 'JSON',
          args: {
            resource: { type: 'String', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              return acl.removeResource(args.resource, function (err) {
                return err ? reject(err) : resolve(null);
              });
            });
          },

          _factoryACL: 'delete'
        },
        removeRole: {
          type: 'JSON',
          args: {
            role: { type: 'String', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              return acl.removeRole(args.role, function (err) {
                return err ? reject(err) : resolve(null);
              });
            });
          },

          _factoryACL: 'delete'
        },
        removeRoleParents: {
          type: 'JSON',
          args: {
            role: { type: 'String', nullable: false },
            parents: { type: 'JSON', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              return acl.removeRoleParents(args.role, args.parents, function (err) {
                return err ? reject(err) : resolve(null);
              });
            });
          },

          _factoryACL: 'update'
        },
        removeUserRoles: {
          type: 'JSON',
          args: {
            userId: { type: 'JSON', nullable: false },
            roles: { type: 'JSON', nullable: false }
          },
          resolve: function resolve(source, args, context, info) {
            _.noop(source, context, info);
            return new Promise(function (resolve, reject) {
              // filter out the user and self role
              var roles = args.roles.filter(function (role) {
                return [args.userId, USER_ROLE].indexOf(role) === -1;
              });
              return acl.removeUserRoles(args.userId, roles, function (err) {
                return err ? reject(err) : resolve(null);
              });
            });
          },

          _factoryACL: 'update'
        }
      }
    }
  });
}

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

var ADMIN_ROLE = 'admin';

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

    var opts = (typeof options === 'undefined' ? 'undefined' : _typeof(options)) === 'object' ? options : {};
    this.schemaName = _.isString(opts.schemaName) && opts.schemaName ? opts.schemaName : 'ACL';

    this.options = opts;
    this.acl = acl;
  }

  _createClass(GraphQLFactoryACLPlugin, [{
    key: 'createAdmin',
    value: function createAdmin() {
      var _this2 = this;

      var adminId = _.get(this.options, 'adminId', 'admin@localhost');
      var resources = this.schemaName + '.*';
      return new Promise(function (resolve, reject) {
        try {
          return _this2.acl.addUserRoles(adminId, ADMIN_ROLE, function (err) {
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
     * Returns a schema that acts as a graphql api for the ACL library.
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
          var errors = [];
          var GraphQLError = this.graphql.GraphQLError;
          var args = resolverArgs.args,
              info = resolverArgs.info;

          var op = _.get(info, 'operation.operation');
          var secret = _.get(_this.options, 'secret');
          var userIdField = _.get(_this.options, 'userIdField', 'userId');
          var schemaName = info.schema._factory.key;
          var basePath = schemaName + '.' + op + '.' + info.fieldName;

          // if not marked as an ACL continue to the next middleware
          if (!this.fieldDef || !this.fieldDef._factoryACL) return next();

          var requiredPerms = [this.fieldDef._factoryACL, '*'];

          // if no jwt secret has been provided authentication is disabled
          if (!secret) return next();

          // check that the secret is in the correct format
          if (!_.isString(secret) && !(secret instanceof Buffer)) {
            // log a warning to the factory
            var secretErr = new Error('ACLError: The secret provided ' + 'by the application is incorrectly formatted, ' + 'please contact your system admin');
            definition.log('warn', 'acl-plugin', secretErr.message);
            return next(secretErr);
          }

          // check for jwt in the rootValue
          var token = _.get(info, 'rootValue.jwt');
          if (!token || !_.isString(token)) {
            return next(new Error('No jwt was provided in the rootValue ' + 'of the request (rootValue.jwt)'));
          }

          return jwt.verify(token, secret, function (jwtErr, decoded) {
            if (jwtErr) return next(jwtErr);
            var userId = _.get(decoded, userIdField);
            if (!userId) return next(new Error('No userId found in the provided jwt'));

            var resources = buildResources(info, args, schemaName);
            var reqPaths = createRequestPaths(info, args, basePath);

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
    key: 'schemas',
    get: function get() {
      return schemas(this);
    }
  }]);

  return GraphQLFactoryACLPlugin;
}();

module.exports = GraphQLFactoryACLPlugin;
