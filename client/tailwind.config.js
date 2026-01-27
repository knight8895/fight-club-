/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'fighter-black': '#050505',
        'fighter-dark': '#121212',
        'fighter-panel': '#1e1e1e',
        'fighter-red': '#dc2626',
        'fighter-red-hover': '#b91c1c',
        'fighter-gold': '#eab308',
        'fighter-border': '#333333',
      },
      fontFamily: {
        'ops': ['"Black Ops One"', 'cursive'],
        'condensed': ['"Roboto Condensed"', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
