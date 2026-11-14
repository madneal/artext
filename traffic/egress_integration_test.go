package traffic

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
)

// TestEgressPoolRoutesPlainHTTP 用一个真实监听的录制代理验证：池里的死代理
// 会让出口请求失败（证明池生效），清空池后回落直连成功。
func TestEgressPoolRoutesPlainHTTP(t *testing.T) {
	dir := t.TempDir()
	// 本地靶标：任何能响应的 HTTP 服务；测试自带一个。
	target := newEchoServer(t)
	// 固定端口：go-mitmproxy 的 :0 动态端口不回填地址，ProxyAddr 拿不到。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	tr, err := Open(dir, portAddr(port))
	if err != nil {
		t.Fatalf("open traffic: %v", err)
	}
	defer tr.Close()
	go tr.Start()

	pxURL, err := url.Parse(tr.ProxyAddr())
	if err != nil {
		t.Fatalf("parse proxy addr: %v", err)
	}
	waitListen(t, pxURL.Host)

	do := func() int {
		req, _ := http.NewRequest(http.MethodGet, target+"/ping", nil)
		transport := &http.Transport{Proxy: http.ProxyURL(pxURL)}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			return -1
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// 池空：直连，靶标应答 200。
	if code := do(); code != 200 {
		t.Fatalf("池空应直连成功，得 %d", code)
	}

	// 池里只有死代理：出口拨号失败，请求应失败（-1 / 502），绝不能 200。
	tr.ReplaceEgressPool([]EgressProxy{mkProxy(1, "http", "127.0.0.1", 59999, "ok", true)}, nil)
	if code := do(); code == 200 {
		t.Fatal("死代理在池中仍返回 200——选路器未生效")
	}

	// 阶段 B：池里只剩 http 死代理（req1 已把它标 down，重推同状态）→ Pick 返回
	// nil → 直连 200。验证降级路径本身不 panic。
	tr.ReplaceEgressPool([]EgressProxy{mkProxy(1, "http", "127.0.0.1", 59999, "down", true)}, nil)
	t.Logf("phase B (pick nil -> direct): %d", do())

	// 阶段 C：socks5 死代理——GetProxyConn socks5 分支在拨号失败时会 conn.Close()
	// 一个 nil conn（go-mitmproxy v1.9.2 的 bug），panic 被 attack 的 recover 吞掉，
	// 这里验证该路径的客户端表现。
	tr.ReplaceEgressPool([]EgressProxy{mkProxy(2, "socks5", "127.0.0.1", 59998, "ok", true)}, nil)
	t.Logf("phase C (socks5 dead): %d", do())
}

func portAddr(port int) string {
	return "127.0.0.1:" + strconv.Itoa(port)
}
