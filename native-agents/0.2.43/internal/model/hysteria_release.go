package model

// Latest reviewed Linux/amd64 release. A registry row alone cannot authorize a binary.
const HysteriaPinnedVersion = "2.13.0"
const HysteriaPinnedSHA256 = "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"
const HysteriaPinnedDownloadURL = "https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64"

// Keep the former reviewed tuple executable for existing nodes and explicit rollback.
const HysteriaLegacyVersion = "2.12.2"
const HysteriaLegacySHA256 = "6493dfffd55b5883f64c76c63880ecc32988f0c568c9ca9014907877b4d55f94"
const HysteriaLegacyDownloadURL = "https://github.com/HyNetworks/hysteria/releases/download/app/v2.12.2/hysteria-linux-amd64"

func ReviewedHysteriaArtifact(version, sha, url string) bool {
	return (version == HysteriaPinnedVersion && sha == HysteriaPinnedSHA256 && url == HysteriaPinnedDownloadURL) ||
		(version == HysteriaLegacyVersion && sha == HysteriaLegacySHA256 && url == HysteriaLegacyDownloadURL)
}

func HysteriaReleaseAgentCompatible(coreVersion, agentVersion string) bool {
	switch coreVersion {
	case HysteriaPinnedVersion:
		return agentMinimumPatch(agentVersion, 43)
	case HysteriaLegacyVersion:
		return agentMinimumPatch(agentVersion, 25)
	default:
		return false
	}
}
