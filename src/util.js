export function forEach (obj, fn) {
  try {
    if (Array.isArray(obj)) {
      let idx = 0
      for (let val of obj) {
        if (fn(val, idx) === false) break
        idx++
      }
    } else {
      for (const key in obj) {
        if (fn(obj[key], key) === false) break
      }
    }
  } catch (err) {
    return
  }
}

export function pickBy (obj, fn) {
  let newObj = {}
  if (typeof obj !== 'object') return newObj
  forEach(obj, (v, k) => {
    if (fn(v, k)) newObj[k] = v
  })
  return newObj
}

export function intersection () {
  let args = [ ...arguments ]
  if (!args.length) return []

  return args.reduce((prev, cur) => {
    if (!Array.isArray(prev) || !Array.isArray(cur)) return []
    let left = new Set(prev)
    let right = new Set(cur)
    let i = [ ...left ].filter(item => right.has(item))
    return [ ...i ]
  }, args[0])
}

export function toPath (pathString) {
  if (Array.isArray(pathString)) return pathString
  if (typeof pathString === 'number') return [ pathString ]

  // taken from lodash - https://github.com/lodash/lodash
  let pathRx = /[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(\.|\[\])(?:\4|$))/g
  let pathArray = []

  if (typeof pathString === 'string') {
    pathString.replace(pathRx, (match, number, quote, string) => {
      pathArray.push(quote ? string : (number !== undefined) ? Number(number) : match)
      return pathArray[pathArray.length - 1]
    })
  }
  return pathArray
}

export function get (obj, path, defaultValue) {
  let fields = Array.isArray(path) ? path : toPath(path)

  let idx = 0
  const length = fields.length

  while (obj !== null && idx < length) {
    obj = obj[fields[idx++]]
  }

  return (idx && idx === length) ? obj : defaultValue
}