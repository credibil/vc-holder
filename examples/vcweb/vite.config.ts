import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
    plugins: [react()],
    server: {
        watch: {
            usePolling: true,
        },
        host: true, // needed for Docker port mapping
        strictPort: true,
        port: 3000,
    },
})
