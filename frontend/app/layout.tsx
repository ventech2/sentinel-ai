import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "Sentinel AI | Security scanner for AI-native apps",
  description: "Detect, explain, and safely remediate security risks in AI-generated applications.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
