package subscriptioncompat

// The frontend validates the original metadata envelope at startup. Identify
// this implementation honestly; it is not a Remnawave server or source build.
func FrontendMetadata(version string) Options {
	return Options{"version": "VPN Infrastructure Platform " + version,
		"build": Options{"time": "unavailable", "number": "unavailable"},
		"git": Options{"backend": Options{"commitSha": "unavailable", "branch": "unavailable", "commitUrl": ""},
			"frontend": Options{"commitSha": "unavailable", "commitUrl": ""}}}
}
