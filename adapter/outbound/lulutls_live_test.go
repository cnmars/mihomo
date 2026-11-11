package outbound

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// TestLulutlsLive dials a real lulutls node end-to-end through the mihomo
// outbound. Skipped unless LULUTLS_SERVER / LULUTLS_PSK are set.
//
//	LULUTLS_SERVER=hk01.example.com:48311 LULUTLS_PSK=<hex> \
//	LULUTLS_SNI=www.bing.com LULUTLS_PATH=/cdn/assets/app.js \
//	LULUTLS_INSECURE=1 go test -run TestLulutlsLive ./adapter/outbound/
func TestLulutlsLive(t *testing.T) {
	server := os.Getenv("LULUTLS_SERVER")
	psk := os.Getenv("LULUTLS_PSK")
	if server == "" || psk == "" {
		t.Skip("LULUTLS_SERVER/LULUTLS_PSK not set")
	}
	host, portStr, err := splitHostPort(server)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("port: %v", err)
	}

	l, err := NewLulutls(LulutlsOption{
		Name:        "live",
		Server:      host,
		Port:        port,
		PSK:         psk,
		NodeKey:     os.Getenv("LULUTLS_NODE_KEY"),
		Lane:        os.Getenv("LULUTLS_LANE"),
		SNI:         os.Getenv("LULUTLS_SNI"),
		Path:        os.Getenv("LULUTLS_PATH"),
		Shape:       os.Getenv("LULUTLS_SHAPE"),
		Cipher:      os.Getenv("LULUTLS_CIPHER"),
		Fingerprint: os.Getenv("LULUTLS_FP"),
		Insecure:    os.Getenv("LULUTLS_INSECURE") == "1",
	})
	if err != nil {
		t.Fatalf("NewLulutls: %v", err)
	}
	defer l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	md := &C.Metadata{Host: "example.com", DstPort: 80, NetWork: C.TCP}
	conn, err := l.DialContext(ctx, md)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.") {
		t.Fatalf("unexpected response: %q", line)
	}
	t.Logf("response: %s", strings.TrimSpace(line))
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("missing port")
	}
	return s[:i], s[i+1:], nil
}

// TestLulutlsLiveUDP sends a DNS query through the tunnel's UDP path.
func TestLulutlsLiveUDP(t *testing.T) {
	server := os.Getenv("LULUTLS_SERVER")
	psk := os.Getenv("LULUTLS_PSK")
	if server == "" || psk == "" {
		t.Skip("LULUTLS_SERVER/LULUTLS_PSK not set")
	}
	host, portStr, err := splitHostPort(server)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("port: %v", err)
	}
	l, err := NewLulutls(LulutlsOption{
		Name: "live-udp", Server: host, Port: port, PSK: psk,
		NodeKey: os.Getenv("LULUTLS_NODE_KEY"), Lane: os.Getenv("LULUTLS_LANE"),
		SNI: os.Getenv("LULUTLS_SNI"), Path: os.Getenv("LULUTLS_PATH"),
		Shape: os.Getenv("LULUTLS_SHAPE"), Cipher: os.Getenv("LULUTLS_CIPHER"),
		Fingerprint: os.Getenv("LULUTLS_FP"), Insecure: os.Getenv("LULUTLS_INSECURE") == "1",
		UDP: true,
	})
	if err != nil {
		t.Fatalf("NewLulutls: %v", err)
	}
	defer l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 8.8.8.8:53 A query for example.com
	md := &C.Metadata{Host: "8.8.8.8", DstPort: 53, NetWork: C.UDP}
	pc, err := l.ListenPacketContext(ctx, md)
	if err != nil {
		t.Fatalf("ListenPacketContext: %v", err)
	}
	defer pc.Close()

	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
	}
	_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := pc.WriteTo(query, md.UDPAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n < 12 || buf[0] != 0x12 || buf[1] != 0x34 {
		t.Fatalf("bad DNS response (%d bytes)", n)
	}
	t.Logf("dns response %d bytes", n)
}
