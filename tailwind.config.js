/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.html", "./*/templates/**/*.html"],
  theme: {
    extend: {
      fontFamily: { sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "sans-serif"] },
    },
  },
  plugins: [require("@tailwindcss/forms")],
};
