import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SuperSayanMCP — WebMCP Security Intelligence Platform",
  description:
    "Next-generation WebMCP security intelligence platform. Detect headless browsers, AI agent fingerprints, WebMCP tool injection, and covert channel exfiltration vectors.",
  keywords: [
    "WebMCP",
    "MCP",
    "Model Context Protocol",
    "security",
    "headless detection",
    "AI agent detection",
    "digital drones",
    "browser fingerprinting",
    "SuperSayanMCP",
  ],
  authors: [{ name: "SuperSayanMCP" }],
  icons: {
    // Modern browsers: scalable SVG with dark/light media query
    icon: [
      { url: "/favicon.ico", sizes: "32x32", type: "image/x-icon" },
      { url: "/icon.svg", type: "image/svg+xml" },
    ],
    // Apple devices (home screen shortcut, 180×180 with padded solid bg)
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" }],
  },
  manifest: "/site.webmanifest",
  openGraph: {
    title: "SuperSayanMCP — WebMCP Security Intelligence",
    description: "Detect. Defend. Trace. The complete countermeasure suite for the agentic web.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark bg-background" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
