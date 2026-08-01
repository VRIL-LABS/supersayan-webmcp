import type { Metadata, Viewport } from "next";
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

const SITE_URL = "https://supersayan.vril.li";
const SITE_TITLE = "Supersayan WebMCP Security";
const SITE_DESCRIPTION =
  "Next-generation WebMCP security intelligence platform. Detect headless browsers, AI agent fingerprints, WebMCP tool injection, and covert channel exfiltration vectors.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: `${SITE_TITLE} — WebMCP Security Intelligence Platform`,
    template: `%s | ${SITE_TITLE}`,
  },
  description: SITE_DESCRIPTION,
  keywords: [
    "WebMCP",
    "MCP",
    "Model Context Protocol",
    "security",
    "headless detection",
    "AI agent detection",
    "digital drones",
    "browser fingerprinting",
    "Supersayan WebMCP Security",
    "VRIL LABS",
  ],
  authors: [{ name: "VRIL LABS", url: "https://vril.li" }],
  creator: "VRIL LABS",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  alternates: {
    canonical: SITE_URL,
  },
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "32x32", type: "image/x-icon" },
      { url: "/icon.svg", type: "image/svg+xml" },
    ],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" }],
  },
  manifest: "/site.webmanifest",
  openGraph: {
    title: `${SITE_TITLE} — WebMCP Security Intelligence`,
    description: "Detect. Defend. Trace. The complete countermeasure suite for the agentic web.",
    url: SITE_URL,
    siteName: SITE_TITLE,
    type: "website",
    locale: "en_US",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "Supersayan WebMCP Security — Detect. Defend. Trace.",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: `${SITE_TITLE} — WebMCP Security Intelligence`,
    description: "Detect. Defend. Trace. The complete countermeasure suite for the agentic web.",
    creator: "@vrillabs",
    site: "@vrillabs",
    images: ["/og-image.png"],
  },
};

export const viewport: Viewport = {
  themeColor: "#00FFC8",
  colorScheme: "dark",
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
