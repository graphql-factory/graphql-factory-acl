export default {
  types: {
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
              return [{id: '1', name: 'John', email: 'John@aol.com'}]
            },
            _factoryACL: 'read'
          }
        }
      }
    }
  }
}