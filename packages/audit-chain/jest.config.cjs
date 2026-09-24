// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
module.exports = {
    preset: 'ts-jest',
    // ts-jest compiles the tests under `tsconfig.test.json`, the same program that type-checks
    // them, not `tsconfig.json`, which leaves them out. Two programs over one set of files would let
    // a test pass under ts-jest while failing the type-check, or the other way round.
    transform: {
        '^.+\\.tsx?$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.test.json' }],
    },
    testEnvironment: 'node',
    roots: ['<rootDir>/src', '<rootDir>/tests'],
    testMatch: ['**/*.test.ts'],
    moduleFileExtensions: ['ts', 'js', 'json'],
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1',
    },
    passWithNoTests: true,
};
