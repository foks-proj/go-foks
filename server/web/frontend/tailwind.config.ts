import type { Config } from "tailwindcss";

export default {
  content: ["../templates/**/*.templ"],
  darkMode: 'class',
  theme: {
    extend: {},
  },
  plugins: [],
} satisfies Config;
