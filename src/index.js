import _ from 'lodash'
import jwt from 'jsonwebtoken'
import schemaDef from './schemas'

const ADMIN_ROLE = 'admin'

/**
 * Creates a list of resource paths the user is requesting access to
 * which includes not paths, query paths, and args paths
 * @param info
 * @returns {[null]}
 */
function buildResources (info, args, schemaName) {
  const paths = []
  const op = _.get(info, 'operation.operation')

  // recursive function to traverse selections adding paths
  let traverseSelections = (selectionSet, path, paths) => {
    if (!selectionSet) return paths.push(path.join('.'))

    _.forEach(selectionSet.selections, sel => {
      let p = path.slice()
      p.push(sel.name.value)
      if (sel.selectionSet) paths.push(p.concat('*').join('.'))
      traverseSelections(sel.selectionSet, p, paths)
    })
  }

  let traverseArgs = (obj, path, paths) => {
    if (!_.isObject(obj) || _.isArray(obj)) return paths.push(path.join('.'))

    _.forEach(obj, (val, name) => {
      let p = path.slice()
      p.push(name)
      if (_.isObject(obj[name]) && !_.isArray(obj[name])) {
        paths.push(p.concat('*').join('.'))
      }
      traverseArgs(obj[name], p, paths)
    })
  }

  _.forEach(info.fieldNodes || info.fieldASTs, node => {
    const field = node.name.value
    const base = [schemaName, op, field]
    const notBase = [`!${schemaName}`, op, field]

    paths.push('*')
    paths.push(`${schemaName}.*`)
    paths.push(`${schemaName}.${op}.*`)
    paths.push(`${schemaName}.${op}.${field}.*`)
    paths.push(`${schemaName}.${op}.${field}.query.*`)
    paths.push(`${schemaName}.${op}.${field}.args.*`)

    traverseSelections(node.selectionSet, notBase.slice().concat('query'), paths)
    traverseSelections(node.selectionSet, base.slice().concat('query'), paths)
    if (args) {
      traverseArgs(args, notBase.slice().concat('args'), paths)
      traverseArgs(args, base.slice().concat('args'), paths)
    }
  })

  return [ ...new Set(paths) ]
}

/**
 * Creates an object that can be used to filter the selection set
 * @param info
 * @param list
 * @param requiredPerms
 * @param basePath
 */
function buildKeepObject (info, list, requiredPerms, basePath) {
  return _.reduce(list, (obj, perms, path) => {
    // if the required permission is not present, move on
    if (!_.intersection(perms, requiredPerms).length) return obj

    // remove the basepath since we are only interested in the requested fields
    path = path.replace(new RegExp(`^${basePath}.`), '')

    // check for inherited path
    if (path.match(/\.\*$/)) {
      _.set(obj, path.replace(/\.\*$/, ''), true)
      return obj
    }

    let o = obj
    let fields = _.toPath(path)

    // look for already set paths so that they are not overwritten
    for (let i = 0; i < fields.length; i++) {
      if (o[fields[i]] === true) return obj
      else o = o[fields[i]]
      if (o === undefined) break
    }

    // set the path if it has not been set
    _.set(obj, path, true)

    return obj
  }, {})
}

/**
 * Builds a list of fields that the user does not have access to
 * @param info
 * @param keep
 * @param basePath
 * @param errors
 * @returns {Array}
 */
function buildErrorList (info, keep, basePath, errors = []) {
  let traverseSelections = (selectionSet, path) => {
    if (!_.get(selectionSet, 'selections')) return
    _.forEach(selectionSet.selections, sel => {
      let p = path.slice()
      p.push(sel.name.value)
      let keepValue = _.get(keep, p)
      if (!keepValue) {
        errors.push(`${basePath}.${p.join('.')}`)
      } else if (keepValue !== true) {
        traverseSelections(sel.selectionSet, p)
      }
    })
  }

  _.forEach(info.fieldNodes || info.fieldASTs, node => {
    traverseSelections(node.selectionSet, [])
  })

  return errors
}

/**
 * @description GraphQLFactoryACLPlugin provides granular ACL control on graphql requests.
 * It also provides a graphql api for the ACL library.
 */
export default class GraphQLFactoryACLPlugin {
  constructor (acl, options) {
    options = typeof options === 'object'
      ? options
      : {}
    this.schemaName = _.isString(options.schemaName) && options.schemaName
      ? options.schemaName
      : 'ACL'

    this.options = options
    this.acl = acl
  }

  createAdmin () {
    let adminId = _.get(this.options, 'adminId', 'admin@localhost')
    let resources = `${this.schemaName}.*`
    return new Promise((resolve, reject) => {
      try {
        return this.acl.addUserRoles(adminId, ADMIN_ROLE, err => {
          if (err) return reject(err)
          return this.acl.allow(ADMIN_ROLE, resources, '*', err => {
            return err
              ? reject(err)
              : resolve({
                enforced: [
                  {
                    apply: true,
                    user: adminId,
                    roles: [ADMIN_ROLE]
                  },
                  {
                    apply: true,
                    roles: [ADMIN_ROLE],
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
    let _this = this
    let acl = this.acl

    // make sure the types plugin is registered
    definition.registerPlugin('types')

    // add the acl middleware
    definition.beforeResolve(function (resolverArgs, next) {
      try {
        const GraphQLError = this.graphql.GraphQLError
        let { args, info } = resolverArgs
        let op = _.get(info, 'operation.operation')
        let secret = _.get(_this.options, 'secret')
        let userIdField = _.get(_this.options, 'userIdField', 'userId')
        let schemaName = info.schema._factory.key
        let basePath = `${schemaName}.${op}.${info.fieldName}`

        // if not marked as an ACL continue to the next middleware
        if (!this.fieldDef || !this.fieldDef._factoryACL) return next()

        let requiredPerms = [this.fieldDef._factoryACL, '*']

        // if no jwt secret has been provided. We keep secret in the options object so that
        // it can be rotated and re-evaluated every request
        if (!secret || (!_.isString(secret) && !(secret instanceof Buffer))) return next()

        // check for jwt in the rootValue
        let token = _.get(info, 'rootValue.jwt')
        if (!token || !_.isString(token)) return next(new Error('ACLError: No jwt was provided in the rootValue of the request'))

        return jwt.verify(token, secret, (err, decoded) => {
          if (err) return next(err)
          let userId = _.get(decoded, userIdField)
          if (!userId) return next(new Error('ACLError: No userId found in the provided jwt'))

          const resources = buildResources(info, args, schemaName)

          return acl.allowedPermissions(userId, resources, (err, list) => {
            if (err) return next(err)

            console.log(list)

            // check for all access
            if (_.intersection(_.get(list, '*', []), requiredPerms).length) {
              return next()
            }

            // check that there are some permissions, if not then the userid has no access
            if (!Object.keys(_.pickBy(list, perm => perm.length > 0)).length) {
              return next(new Error(`User "${userId}" has no permissions on "${basePath}"`))
            }

            // get cumulative base permissions for query an args
            const baseQueryPerms = _.reduce([schemaName, op, info.fieldName, 'query'], (accum, cur) => {
              accum.path.push(cur)
              accum.perms = _.union(accum.perms, _.get(list, accum.path.concat('*').join('.'), []))
              return accum
            }, { path: [], perms: [] }).perms
            const baseArgsPerms = _.reduce([schemaName, op, info.fieldName, 'args'], (accum, cur) => {
              accum.path.push(cur)
              accum.perms = _.union(accum.perms, _.get(list, accum.path.concat('*').join('.'), []))
              return accum
            }, { path: [], perms: [] }).perms

            // check for the * resource and permission, if found then authorize
            if (_.intersection(baseQueryPerms, requiredPerms).length) {
              if (!_.keys(args).length || _.intersection(baseArgsPerms, requiredPerms).length) {
                return next()
              }
            }

            // TODO: re-work the keep and error evauluators to handle the new path structure and not cases

            // build an object that represents the fields to keep
            let keep = buildKeepObject(info, list, requiredPerms, basePath)

            // next build an error list
            let errors = _.keys(keep).length
              ? buildErrorList(info, keep, basePath)
              : [basePath]

            // return the response
            return errors.length
              ? next(new GraphQLError(`Insufficient permissions on ${errors} for userId "${userId}"`))
              : next()
          })
        })
      } catch (err) {
        return next(err)
      }
    })
  }
}
