import babel from 'rollup-plugin-babel'
import babelrc from 'babelrc-rollup'

const babelConfig = {
  presets: [
    ['env']
  ]
}

export default {
  input: 'src/index.js',
  external: ['lodash', 'jsonwebtoken'],
  plugins: [
    babel(
      babelrc({
        addExternalHelpersPlugin: false,
        config: babelConfig,
        exclude: 'node_modules/**'
      })
    )
  ],
  output: {
    format: 'cjs',
    file: 'index.js'
  }
}