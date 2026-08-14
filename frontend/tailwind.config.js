module.exports = {
  root: true,
  theme: {
    extend: {
      colors: {
        primary: '#3b82f6',
        secondary: '#8b5cf6',
        danger: '#ef4444',
        success: '#22c55e',
        warning: '#f59e0b',
        dark: '#1e293b',
        light: '#f1f5f9'
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif']
      }
    }
  },
  content: [
    './pages/**/*.{js,jsx,ts,tsx}',
    './app/**/*.{js,jsx,ts,tsx}',
    './components/**/*.{js,jsx,ts,tsx}',
  ],
  extensions: [require('tailwindcss-animate')],
  plugins: [require('tailwindcss-animate')],
}