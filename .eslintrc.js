/** @type {import('eslint').Linter.Config} */
const config = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    ecmaVersion: 2019,
    sourceType: 'module'
  },
  env: { node: true },
  extends: ['ackama', 'ackama/@typescript-eslint'],
  ignorePatterns: ['!.eslintrc.js', 'coverage', 'lib', 'infra'],
  overrides: [
    {
      files: ['test/**'],
      extends: ['ackama/jest'],
      rules: { 'jest/prefer-expect-assertions': 'off' }
    }
  ],
  rules: {
    '@typescript-eslint/camelcase': 'off',
    '@typescript-eslint/no-unsafe-assignment': 'error',
    '@typescript-eslint/prefer-reduce-type-parameter': 'error',
    'import/no-deprecated': 'error'
  }
};

module.exports = config;
