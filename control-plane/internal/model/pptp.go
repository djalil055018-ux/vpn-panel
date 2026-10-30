package model

const PPTPPinnedVersion = "1.14.0-platform.1"
const PPTPPinnedSHA256 = "d6960405b74030750e7b835e3dafef76e26f1d2748a4d347578204fabcdd08a6"
const PPTPManifestSHA256 = "24c056748c71e1351de89c6fa29ad60612b971fd719b79ec182c95b500eb0b69"
const PPTPBinarySHA256 = "8a57f661f57279df86421f85425db2e7d21ce5884596a6da02936d003831d1c2"
const PPTPPinnedDownloadURL = "https://github.com/djalil055018-ux/vpn-panel/releases/download/v0.1.155/pptp-accel-1.14.0-platform.1-linux-amd64.tar.gz"

// PPTP is a legacy IPv4 compatibility runtime. MPPE does not remove the known
// weaknesses of MS-CHAPv2; it must never be advertised as a modern secure VPN.
type PPTPPeer struct {
	Password string `json:"password"`
	Address  string `json:"address"`
}
