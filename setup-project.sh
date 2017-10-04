#!/bin/bash

# Make source dir
mkdir -p src
mkdir -p build

# Create .babelrc
cat >./.babelrc <<EOL
{
  "presets": ["es2015", "stage-2"],
  "plugins": ["transform-runtime"],
  "comments": false
}
EOL
git add ./.babelrc

# Create .gitignore
cat >./.babelrc <<EOL
.DS_Store
node_modules/
npm-debug.log
selenium-debug.log
.idea/
EOL
git add ./.gitignore

# Create .npmignore
cat >./.npmignore <<EOL
build
assets
example
node_modules
scratch,
src
test
dist
.babelrc
.DS_Store
.idea
npm-debug.log
.npmignore
.travis.yml
.*
package-lock.json
EOL
git add ./.npmignore

# npm stuff
npm init -f

npm install --save-dev babel-core
npm install --save-dev babel-plugin-transform-runtime
npm install --save-dev babel-preset-es2015
npm install --save-dev babel-preset-es2015-rollup
npm install --save-dev babel-preset-stage-2
npm install --save-dev babel-register
npm install --save-dev babel-runtime
npm install --save-dev chai
npm install --save-dev lodash
npm install --save-dev mocha
npm install --save-dev rollup
npm install --save-dev rollup-plugin-babel