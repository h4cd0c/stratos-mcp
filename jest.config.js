/** @type {import('jest').Config} */
export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        useESM: true,
      },
    ],
  },
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
  ],
  coverageDirectory: 'coverage',
  
  // Fix resource leaks and hanging tests
  testTimeout: 30000,              // 30 second timeout per test
  forceExit: true,                 // Force exit after tests complete
  detectOpenHandles: false,        // Disable for faster runs (enable for debugging)
  maxWorkers: '50%',              // Limit parallel workers
  
  // Avoid false negatives
  clearMocks: true,
  resetMocks: false,
  restoreMocks: false,
};
