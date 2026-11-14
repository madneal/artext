package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// vlessEntry 构造一条指向指定 host:port 的 vless 池条目（不出库，直接喂引擎）。
func vlessEntry(id int64, host string, port int, transport string) db.ProxyEntry {
	vt := map[string]any{
		"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
	}
	if transport != "" {
		vt["transport"] = transport
		vt["security"] = "tls"
	} else {
		vt["security"] = "none"
	}
	raw, _ := json.Marshal(vt)
	enabled := true
	return db.ProxyEntry{
		ID: id, Scheme: "vless", Host: host, Port: port,
		Transport: raw, Enabled: &enabled, State: "ok",
	}
}

// waitListenPoll 轮询直到 addr 可建立 TCP 连接。
// newEchoTarget 起一个返回 200 的本地 HTTP 靶标，测试结束自动关闭。
func newEchoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

func waitListenPoll(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等 %s 就绪超时", addr)
}

func TestEgressEngineSyncLifecycle(t *testing.T) {
	e := newEgressEngine()
	defer e.Close()

	// 无 vless 条目：不启实例。
	m, err := e.Sync(nil)
	if err != nil || len(m) != 0 {
		t.Fatalf("空集应返回空映射: m=%v err=%v", m, err)
	}

	// 一个 vless 条目：实例启动，本地 socks 入站可连。
	entries := []db.ProxyEntry{vlessEntry(7, "203.0.113.9", 443, "")}
	m, err = e.Sync(entries)
	if err != nil {
		t.Fatalf("Sync 失败: %v", err)
	}
	local := m[7]
	if local == "" {
		t.Fatal("应有映射")
	}
	u, err := url.Parse(local)
	if err != nil {
		t.Fatalf("映射不是合法 URL: %v", err)
	}
	waitListenPoll(t, u.Host)
	if e.Resolve(7) != local {
		t.Fatal("Resolve 应返回映射")
	}

	// 集合不变：Sync 复用实例（端口不变）。
	m2, err := e.Sync(entries)
	if err != nil || m2[7] != local {
		t.Fatalf("同集合 Sync 不应重建: %v vs %v", m2, local)
	}

	// transport 变化：重建（端口变化）。
	entries[0] = vlessEntry(7, "203.0.113.9", 443, "ws")
	m3, err := e.Sync(entries)
	if err != nil {
		t.Fatalf("Sync(transport 变化) 失败: %v", err)
	}
	if m3[7] == local {
		t.Fatalf("transport 变化应重建出新端口: %v == %v", m3[7], local)
	}
	waitListenPoll(t, mustParseHost(t, m3[7]))

	// 条目停用：映射消失。
	disabled := entries[0]
	off := false
	disabled.Enabled = &off
	m4, err := e.Sync([]db.ProxyEntry{disabled})
	if err != nil || len(m4) != 0 {
		t.Fatalf("停用条目应从映射消失: m=%v err=%v", m4, err)
	}
}

func TestEgressEngineSocksDialPropagatesFailure(t *testing.T) {
	// vless 节点指向必关端口：socks 入站接受连接，出站拨号失败 → 客户端报错。
	// 验证「入站→出站→错误传播」整条链路（真实 vless 服务端不在测试范围）。
	e := newEgressEngine()
	defer e.Close()

	m, err := e.Sync([]db.ProxyEntry{vlessEntry(9, "127.0.0.1", 59991, "")})
	if err != nil {
		t.Fatalf("Sync 失败: %v", err)
	}
	u, err := url.Parse(m[9])
	if err != nil {
		t.Fatalf("映射解析失败: %v", err)
	}
	waitListenPoll(t, u.Host)

	// 通过本地 socks 入站请求本地 HTTP 靶标：vless 出站不可达 → 请求应失败。
	target := newEchoTarget(t)
	req, _ := http.NewRequest(http.MethodGet, target+"/ping", nil)
	transport := &http.Transport{Proxy: http.ProxyURL(u)}
	resp, rerr := transport.RoundTrip(req)
	if rerr == nil {
		resp.Body.Close()
		t.Fatalf("vless 出站不可达时应失败，却得到 %d", resp.StatusCode)
	}
}

func mustParseHost(t *testing.T, raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("解析 %s: %v", raw, err)
	}
	return u.Host
}
