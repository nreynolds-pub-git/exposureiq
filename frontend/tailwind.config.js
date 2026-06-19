/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Tenable primary palette
        'tenable-black': '#1E2426',
        'tenable-yellow': '#E7FF00',

        // Tenable data palette — for charts and categorical UI elements
        'data-gray': '#44494B',
        'data-blue': '#4EA5FF',
        'data-green': '#71FFC6',
        'data-purple': '#BB8FF2',
        'data-orange': '#FF8837',

        // Severity color mapping (chosen against the data palette;
        // see ARCHITECTURE.md for rationale)
        'sev-critical': '#FF8837',
        'sev-high': '#E7FF00',
        'sev-medium': '#4EA5FF',
        'sev-low': '#71FFC6',
        'sev-info': '#44494B',
      },
      fontFamily: {
        // Aeonik Pro is licensed; Work Sans is the Google Fonts equivalent
        // sanctioned by the brand guidelines.
        sans: ['"Work Sans"', 'system-ui', '-apple-system', 'sans-serif'],
      },
      letterSpacing: {
        // Brand spec: Work Sans tracking adjusted -3% to match Aeonik.
        'aeonik-match': '-0.03em',
      },
    },
  },
  plugins: [],
};
