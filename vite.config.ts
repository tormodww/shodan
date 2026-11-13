import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'

// I dev proxyes /api til Shodan, og nøkkelen legges på her (fra .env.local),
// akkurat som nginx gjør i produksjon.
export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, process.cwd(), ''), ...process.env }
  const upstream = env.SHODAN_UPSTREAM || 'https://api.shodan.io'
  const idbUpstream = env.IDB_UPSTREAM || 'https://internetdb.shodan.io'
  return {
    base: './',
    plugins: [react()],
    server: {
      proxy: {
        '/api': {
          target: upstream,
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/api/, '') + `&key=${encodeURIComponent(env.SHODAN_API_KEY ?? '')}`,
        },
        '/internetdb': {
          target: idbUpstream,
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/internetdb/, ''),
        },
      },
    },
  }
})
