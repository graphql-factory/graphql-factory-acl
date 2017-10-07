import _ from 'lodash'
import jwt from 'jsonwebtoken'
import schemaDef from './schemas'

const ADMIN_ROLE = 'admin'

/**
 * Creates a list of resource paths the user is requesting access to
 * which includes not paths, selection paths, and args paths
 * @param info
 * @param args
 * @param schemaName
 * @returns {[null]}
 */
function buildResources (info, args, schemaName) {
  const paths = []
  const op = _.get(info, 'operation.operation')

  // recursive function to traverse selections adding paths
  const traverseSelections = (selectionSet, path, _paths) => {
    if (!selectionSet) return _paths.push(path.join('.'))

    _.forEach(selectionSet.selections, sel => {
      const p = path.slice()
      p.push(sel.name.value)
      if (sel.selectionSet) _paths.push(p.concat('*').join('.'))
      traverseSelections(sel.selectionSet, p, _paths)
    })
  }

  const traverseArgs = (obj, path, _paths) => {
    if (!_.isObject(obj) || _.isArray(obj)) return _paths.push(path.join('.'))

    _.forEach(obj, (val, name) => {
      const p = path.slice()
      p.push(name)
      if (_.isObject(obj[name]) && !_.isArray(obj[name])) {
        _paths.push(p.concat('*').join('.'))
      }
      traverseArgs(obj[name], p, _paths)
    })
  }

  _.forEach(info.fieldNodes || info.fieldASTs, node => {
    const field = node.name.value
    const base = [ schemaName, op, field ]
    const notBase = [ `!${schemaName}`, op, field ]

    paths.push('*')
    paths.push(`${schemaName}.*`)
    paths.push(`${schemaName}.${op}.*`)
    paths.push(`${schemaName}.${op}.${field}.*`)
    paths.push(`${schemaName}.${op}.${field}.selection.*`)
    paths.push(`${schemaName}.${op}.${field}.args.*`)

    traverseSelections(node.selectionSet, notBase.slice().concat('selection'), paths)
    traverseSelections(node.selectionSet, base.slice().concat('selection'), paths)
    if (args) {
      traverseArgs(args, notBase.slice().concat('args'), paths)
      traverseArgs(args, base.slice().concat('args'), paths)
    }
  })

  return [ ...new Set(paths) ]
}

/**
 * creates paths for the requested selections and args
 * @param info
 * @param args
 * @param basePath
 * @returns {Array}
 */
function createRequestPaths (info, args, basePath) {
  const paths = []
  const traverseSelections = (selectionSet, path) => {
    if (!_.get(selectionSet, 'selections')) return
    _.forEach(selectionSet.selections, sel => {
      const p = path.slice()
      p.push(sel.name.value)
      paths.push(p.join('.'))
      traverseSelections(sel.selectionSet, p)
    })
  }

  const traverseArgs = (a, path) => {
    if (!_.isObject(a) || _.isArray(a)) return
    _.forEach(a, (val, key) => {
      const p = path.slice()
      p.push(key)
      paths.push(p.join('.'))
      traverseArgs(val, p)
    })
  }

  _.forEach(info.fieldNodes || info.fieldASTs, node => {
    traverseSelections(node.selectionSet, [ basePath, 'selection' ])
  })

  traverseArgs(args, [ basePath, 'args' ])
  return paths
}

/**
 * @description GraphQLFactoryACLPlugin provides granular ACL control on graphql requests.
 * It also provides a graphql api for the ACL library.
 */
export default class GraphQLFactoryACLPlugin {
  constructor (acl, options) {
    const opts = typeof options === 'object'
      ? options
      : {}
    this.schemaName = _.isString(opts.schemaName) && opts.schemaName
      ? opts.schemaName
      : 'ACL'

    this.options = opts
    this.acl = acl
  }

  createAdmin () {
    const adminId = _.get(this.options, 'adminId', 'admin@localhost')
    const resources = `${this.schemaName}.*`
    return new Promise((resolve, reject) => {
      try {
        return this.acl.addUserRoles(adminId, ADMIN_ROLE, err => {
          if (err) return reject(err)
          return this.acl.allow(ADMIN_ROLE, resources, '*', allowErr => {
            return allowErr
              ? reject(allowErr)
              : resolve({
                enforced: [
                  {
                    apply: true,
                    user: adminId,
                    roles: [ ADMIN_ROLE ]
                  },
                  {
                    apply: true,
                    roles: [ ADMIN_ROLE ],
                    resources
                  }
                ]
              })
          })
        })
      } catch (err) {
        return reject(err)
      }
    })
  }

  /**
   * Returns a schema that acts as a graphql api for the ACL library.
   * @returns {{}}
   */
  get schemas () {
    return schemaDef(this)
  }

  /**
   * Installs the ACL plugin in graphql-factory
   * @param definition
   */
  install (definition) {
    const _this = this
    const acl = this.acl

    // make sure the types plugin is registered
    definition.registerPlugin('types')

    // add the acl middleware
    definition.beforeResolve(function (resolverArgs, next) {
      try {
        const errors = []
        const GraphQLError = this.graphql.GraphQLError
        const { args, info } = resolverArgs
        const op = _.get(info, 'operation.operation')
        const secret = _.get(_this.options, 'secret')
        const userIdField = _.get(_this.options, 'userIdField', 'userId')
        const schemaName = info.schema._factory.key
        const basePath = `${schemaName}.${op}.${info.fieldName}`

        // if not marked as an ACL continue to the next middleware
        if (!this.fieldDef || !this.fieldDef._factoryACL) return next()

        const requiredPerms = [ this.fieldDef._factoryACL, '*' ]

        // if no jwt secret has been provided authentication is disabled
        if (!secret) return next()

        // check that the secret is in the correct format
        if (!_.isString(secret) && !(secret instanceof Buffer)) {
          return next(new Error('ACLError: The secret provided '
            + 'by the application is incorrectly formatted'))
        }

        // check for jwt in the rootValue
        const token = _.get(info, 'rootValue.jwt')
        if (!token || !_.isString(token)) {
          return next(new Error('ACLError: No jwt was provided in the rootValue of the request'))
        }

        return jwt.verify(token, secret, (jwtErr, decoded) => {
          if (jwtErr) return next(jwtErr)
          const userId = _.get(decoded, userIdField)
          if (!userId) return next(new Error('ACLError: No userId found in the provided jwt'))

          const resources = buildResources(info, args, schemaName)
          const reqPaths = createRequestPaths(info, args, basePath)

          return acl.allowedPermissions(userId, resources, (aclErr, list) => {
            if (aclErr) return next(aclErr)

            // check that there are some permissions, if not then the userid has no access
            if (!Object.keys(_.pickBy(list, perm => perm.length > 0)).length) {
              return next(new Error(`User "${userId}" has no permissions on "${basePath}"`))
            }

            // check if the not list contains the argument
            reqPaths.map(v => `!${v}`).forEach(p => {
              const perms = _.union(_.get(list, p, []), _.get(list, `${p}.*`, []))
              if (perms.length) errors.push(p.replace(/^!/, ''))
            })

            // check each field
            reqPaths.forEach(v => {
              // check all permutations of privileges on the current path
              // and reduce those perms to a list that can be evaluated
              // against the required permissions
              const perms = _.reduce(v.split('.'), (accum, part) => {
                accum.path.push(part)
                const perm = _.union(
                  _.get(list, '*'),
                  _.get(list, accum.path.join('.')),
                  _.get(list, accum.path.concat('*').join('.'))
                )
                accum.perm = _.union(accum.perm, perm)
                return accum
              }, { path: [], perm: [] }).perm

              if (!_.intersection(perms, requiredPerms).length) {
                errors.push(v)
              }
            })

            // return the response
            return errors.length
              ? next(new GraphQLError('Insufficient permissions on '
                + errors + ' for userId "' + userId + '"'))
              : next()
          })
        })
      } catch (err) {
        return next(err)
      }
    })
  }
}
