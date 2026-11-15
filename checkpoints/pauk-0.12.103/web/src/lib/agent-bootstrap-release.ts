// Versioned artifacts are immutable; the installer also verifies its backup component.
export const nativeAgentBootstrapRelease = {
  version: "0.2.51",
  installerFilename: "vpn-node-tool-v0.2.51-r1.py",
  installerSHA256: "883bcd06bfbbfbd33eb6f67e6f63a43d5d3e19308938f5c2c5db2601de009e74",
  binarySHA256: "9179331f96e1053a3e823111072af5e291d194f887fc21cb2b3cde0f84b819a3",
} as const;

export const amneziaWGInstallerRelease = {
  installerFilename: "vpn-node-tool-v0.2.51-r2.py",
  installerSHA256: "8d0f3c21a5a577cdf83a1dd4dec2a93a0cc8f3963e718d48b326f39336318d8b",
} as const;
