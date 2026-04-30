import type { Metadata } from "next";
import { Inter, Space_Grotesk, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { KeyboardShortcutsProvider } from "@/components/KeyboardShortcutsProvider";

/**
 * Space Grotesk — display / headings / labels
 * Used via CSS var: --font-display
 */
const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  variable: "--font-space-grotesk",
  display: "swap",
});

/**
 * Inter — body text, UI labels, descriptions
 * Used via CSS var: --font-body  →  --font-inter
 */
const inter = Inter({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600"],
  variable: "--font-inter",
  display: "swap",
});

/**
 * JetBrains Mono — hashes, IPs, onion URLs, IDs, elapsed counters, code
 * Used via CSS var: --font-mono  →  --font-jetbrains-mono
 */
const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "VoidAccess — Dark Web Intelligence",
  description: "Professional dark web OSINT platform for threat intelligence teams.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${spaceGrotesk.variable} ${inter.variable} ${jetbrainsMono.variable}`}
    >
      <body className="font-sans antialiased text-[var(--text-primary)] bg-[var(--bg-void)]">
        <KeyboardShortcutsProvider>
          {children}
        </KeyboardShortcutsProvider>
      </body>
    </html>
  );
}
