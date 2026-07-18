import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      borderRadius: {
        xl: "0.9rem",
      },
      boxShadow: {
        panel: "0 16px 40px -24px rgba(15, 23, 42, 0.32)",
      },
    },
  },
  plugins: [],
};

export default config;
