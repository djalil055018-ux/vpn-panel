package model

const OpenVPNPinnedVersion = "2.6.19"
const OpenVPNPackageVersion = "2.6.19-0ubuntu0.24.04.4"
const OpenVPNPinnedSHA256 = "d288c3789e825b140258da3e2c40bdb8f07820b8e69ca6480b619b83af8f108a"
const OpenVPNBinarySHA256 = "b02701de7661bae5a46699341d29438948ca00da56965da88d0ad597323f3667"
const OpenVPNPinnedDownloadURL = "https://security.ubuntu.com/ubuntu/pool/main/o/openvpn/openvpn_2.6.19-0ubuntu0.24.04.4_amd64.deb"

type OpenVPNSpec struct {
	CACertificate     string `json:"ca_certificate"`
	ServerCertificate string `json:"server_certificate"`
	ServerPrivateKey  string `json:"server_private_key"`
	TLSCryptKey       string `json:"tls_crypt_key"`
	CRL               string `json:"crl"`
}
