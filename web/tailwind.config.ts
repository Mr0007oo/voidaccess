import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        heading:  ["var(--font-space-grotesk)", "ui-sans-serif", "system-ui"],
        display:  ["var(--font-space-grotesk)", "ui-sans-serif", "system-ui"],
        sans:     ["var(--font-inter)", "ui-sans-serif", "system-ui"],
        body:     ["var(--font-inter)", "ui-sans-serif", "system-ui"],
        mono:     ["var(--font-jetbrains-mono)", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
