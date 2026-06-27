/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        darkBg: "#0b111e",      // Dark background
        cardBg: "#111827",      // Default dark card background
        glowGreen: "#10b981",
        glowRed: "#ef4444",
        glowOrange: "#f97316",
        glowBlue: "#3b82f6"
      }
    },
  },
  plugins: [],
}
