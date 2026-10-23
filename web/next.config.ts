import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

const config: NextConfig = {
  // A small self-contained server for the container image.
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
};

export default withNextIntl(config);
