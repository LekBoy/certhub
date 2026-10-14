/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.html", "./*/templates/**/*.html", "./*/forms.py", "./*/views.py"],
  theme: {
    extend: {
      colors: {
        // Identidade BCA: azul #193D79 e vermelho #CC1519 (do logótipo)
        brand: {
          50: "#f1f4f8",
          100: "#e3e9f2",
          200: "#c7d3e5",
          300: "#92aedd",
          400: "#497fd9",
          500: "#265cb6",
          600: "#193d79",
          700: "#143161",
          800: "#0f2448",
          900: "#0a1a33",
        },
        accent: { DEFAULT: "#cc1519", dark: "#a81014" },
      },
      fontFamily: { sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "sans-serif"] },
    },
  },
  plugins: [require("@tailwindcss/forms")],
};
