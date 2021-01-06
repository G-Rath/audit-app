import { Config } from '@jest/types';
import 'ts-jest';

const config: Config.InitialOptions = {
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

export default config;
