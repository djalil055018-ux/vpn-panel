package model

// The PAUK patch fixes the initial S4 read race; source identities and the
// upstream licenses are included in the immutable runtime archive.
const AmneziaWGNativeVersion = "3.1.20260828-pauk.1"
const AmneziaWGDownloadURL = "https://github.com/djalil055018-ux/vpn-panel/releases/download/v0.1.155/amneziawg-3.1.20260828-pauk.1-linux-amd64.tar.gz"
const AmneziaWGArtifactSHA256 = "1fc10912a24cc14178f3937552bd8c6a9d6489d8462f0884053a9ea3091e886a"
const AmneziaWGDaemonSHA256 = "d20241d5cb1369ea203db8ff12f8015975be7566753b27449d25887f83a75136"
const AmneziaWGToolSHA256 = "69d1349275a1a97853478c75b62019fcd6707022f231c794e7f45b00e3d0f8e9"

func AmneziaWGAgentCompatible(version string) bool { return agentMinimumPatch(version, 42) }
