package agent

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

type SystemInfo struct {
	OSName       string
	OSVersion    string
	Architecture string
}

func DetectSystem() SystemInfo {
	info := SystemInfo{
		OSName:       runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	file, err := os.Open("/etc/os-release")
	if err != nil {
		return info
	}

	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")

		if !ok {
			continue
		}

		values[key] = strings.Trim(value, `"`)
	}

	if values["ID"] != "" {
		info.OSName = values["ID"]
	}

	if values["VERSION_ID"] != "" {
		info.OSVersion = values["VERSION_ID"]
	}

	return info
}
