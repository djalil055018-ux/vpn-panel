package model

import "strings"

func VLESSTLSTransport(transport string) bool {
	return transport == "tcp" || transport == "xhttp" || transport == "ws" || transport == "grpc"
}

func GRPCServiceName(serviceID string) (string, bool) {
	if !xhttpServiceID.MatchString(serviceID) {
		return "", false
	}
	return "vpn" + strings.ReplaceAll(strings.ToLower(serviceID), "-", ""), true
}
