import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// GitHub Pages では https://<user>.github.io/<repo>/ に置かれるため、相対パスで出力する
export default defineConfig({
  base: './',
  plugins: [react()],
  test: {
    include: ['src/**/*.test.ts'],
  },
});
