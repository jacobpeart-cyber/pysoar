import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) {
            return undefined
          }

          if (id.includes('react-router')) {
            return 'router-vendor'
          }
          if (id.includes('@tanstack')) {
            return 'query-vendor'
          }
          if (id.includes('recharts') || id.includes('d3-')) {
            return 'charts-vendor'
          }
          if (id.includes('lucide-react')) {
            return 'icons-vendor'
          }
          if (id.includes('axios') || id.includes('date-fns') || id.includes('jwt-decode')) {
            return 'utils-vendor'
          }
          if (id.includes('react')) {
            return 'react-vendor'
          }

          return undefined
        },
      },
    },
  },
})
