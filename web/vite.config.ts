import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // The Flask API. Port 5050 everywhere: on macOS, port 5000 belongs to AirPlay Receiver.
    proxy: { '/api': 'http://127.0.0.1:5050' },
  },
})
