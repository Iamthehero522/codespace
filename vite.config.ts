// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    exclude: ['lucide-react'],
  },
  build: {
    // emit .map files so errors in the browser console point to your .tsx/.ts lines
    sourcemap: true,
  },
});
