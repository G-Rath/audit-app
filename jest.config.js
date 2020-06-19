/** @typedef {import('ts-jest')} */

/** @type {import('@jest/types').Config.InitialOptions} */
const config = {
  globals: {
    'ts-jest': {
      isolatedModules: true
    }
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'json', 'jsx', 'node'],
  resetMocks: true,
  restoreMocks: true,
  setupFilesAfterEnv: [
    './test/setupMockFs.ts',
    './test/setupExpectEachTestHasAssertions.ts'
  ],
  testEnvironment: 'node',
  transform: {
    '\\.tsx?': 'ts-jest'
  }
};

module.exports = config;
