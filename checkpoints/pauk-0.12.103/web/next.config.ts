import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  images: {
    localPatterns: [{ pathname: "/pauk-emblem.png", search: "?v=f5c682015507" }],
    remotePatterns: [],
    deviceSizes: [640],
    imageSizes: [48, 64, 96, 128, 192, 256, 384, 576],
    qualities: [85],
    formats: ["image/webp"],
    minimumCacheTTL: 14400,
    maximumDiskCacheSize: 32 * 1024 * 1024,
    maximumResponseBody: 3 * 1024 * 1024,
    maximumRedirects: 0,
    dangerouslyAllowLocalIP: false,
    dangerouslyAllowSVG: false,
    contentDispositionType: "attachment",
    contentSecurityPolicy: "default-src 'none'; script-src 'none'; sandbox;",
  },
  async headers() {
    return [{ source: "/sub/:path*", headers: [
      { key: "Cache-Control", value: "private, no-store, max-age=0" },
      { key: "Referrer-Policy", value: "no-referrer" },
      { key: "X-Robots-Tag", value: "noindex, nofollow, noarchive" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "X-Frame-Options", value: "DENY" },
    ] }];
  },
};

export default nextConfig;
