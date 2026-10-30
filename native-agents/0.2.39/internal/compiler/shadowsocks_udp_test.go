package compiler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

func shadowsocksUDPProbe(proxyPort, targetPort int) bool {
	return shadowsocksUDPProbeTo(proxyPort, targetPort, net.ParseIP("127.0.0.1"))
}
func shadowsocksUDPProbeTo(proxyPort, targetPort int, targetIP net.IP) bool {
	tcp, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), time.Second)
	if err != nil {
		return false
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = tcp.Write([]byte{5, 1, 0}); err != nil {
		return false
	}
	response := make([]byte, 2)
	if _, err = io.ReadFull(tcp, response); err != nil || !bytes.Equal(response, []byte{5, 0}) {
		return false
	}
	if _, err = tcp.Write([]byte{5, 3, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return false
	}
	header := make([]byte, 10)
	if _, err = io.ReadFull(tcp, header); err != nil || header[1] != 0 || header[3] != 1 {
		return false
	}
	udp, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IP(header[4:8]), Port: int(binary.BigEndian.Uint16(header[8:10]))})
	if err != nil {
		return false
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(2 * time.Second))
	packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort)}
	copy(packet[4:8], targetIP.To4())
	payload := []byte("ss2022-udp-native-verified")
	packet = append(packet, payload...)
	if _, err = udp.Write(packet); err != nil {
		return false
	}
	buf := make([]byte, 4096)
	n, err := udp.Read(buf)
	return err == nil && n >= 10+len(payload) && buf[2] == 0 && bytes.Equal(buf[n-len(payload):n], payload)
}
