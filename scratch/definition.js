export default {
  types: {
    FooInput: {
      type: 'Input',
      fields: {
        bar: { type: 'String' },
        baz: ['String']
      }
    },
    User: {
      fields: {
        id: { type: 'String', primary: true },
        name: 'String',
        email: 'String',
        manager: {
          type: 'User',
          resolve (source, args, context, info) {
            return {
              id: '2',
              name: 'Bossman',
              email: 'Bossman@hotmail.com'
            }
          }
        }
      }
    }
  },
  schemas: {
    Users: {
      query: {
        fields: {
          listUsers: {
            type: ['User'],
            resolve (source, args, context, info) {
              return [{id: '1', name: 'John', email: 'john@aol.com'}]
            },
            _factoryACL: 'read'
          }
        }
      },
      mutation: {
        fields: {
          createUser: {
            type: 'User',
            args: {
              name: { type: 'String', nullable: false },
              email: { type: 'String', nullable: false },
              foo: 'FooInput'
            },
            resolve (source, args) {
              return Object.assign(args, { id: '2' })
            },
            _factoryACL: 'create'
          },
          deleteUser: {
            type: 'Boolean',
            args: {
              id: { type: 'String', nullable: false }
            },
            resolve () {
              return true
            },
            _factoryACL: 'delete'
          }
        }
      }
    }
  }
}