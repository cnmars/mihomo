package adapter

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"gopkg.in/yaml.v3"
)

// TestParseLulutlsYAML proves the panel-emitted YAML entry maps onto the
// outbound option (all hyphenated keys) and dials successfully.
//
//	LULUTLS_YAML=/tmp/clash.yaml go test -run TestParseLulutlsYAML ./adapter/ \
//	  -v -args -node HK01-LULU
func TestParseLulutlsYAML(t *testing.T) {
	path := os.Getenv("LULUTLS_YAML")
	if path == "" {
		t.Skip("LULUTLS_YAML not set")
	}
	want := os.Getenv("LULUTLS_NODE")
	if want == "" {
		want = "HK01-LULU"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var cfg struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	var entry map[string]any
	for _, p := range cfg.Proxies {
		if p["name"] == want {
			entry = p
			break
		}
	}
	if entry == nil {
		t.Fatalf("proxy %q not found in %s", want, path)
	}
	if entry["type"] != "lulutls" {
		t.Fatalf("type = %v", entry["type"])
	}

	proxy, err := ParseProxy(entry)
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{Host: "example.com", DstPort: 80, NetWork: C.TCP})
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
