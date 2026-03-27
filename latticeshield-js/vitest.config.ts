import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Use Node.js environment — Node 20+ has globalThis.crypto (Web Crypto API)
    environment: 'node',
    globals: false,
    include: ['tests/**/*.test.ts'],
    // Resolve .js extensions to .ts files (TypeScript with ESM)
    resolve: {
      alias: {},
    },
  },
});
