package traffic

import (
	"encoding/json"
	"testing"
)

func TestParseVLESSURITLS(t *testing.T) {
	raw := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com&sni=example.com&fp=chrome#节点A"
	p, err := ParseVLESSURI(raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.Scheme != "vless" || p.Host != "example.com" || p.Port != 443 {
		t.Fatalf("基础字段错误: %+v", p)
	}
	if !p.Enabled || p.State != "ok" {
		t.Fatalf("默认状态错误: %+v", p)
	}
	var vt VLESSTransport
	if err := json.Unmarshal(p.Transport, &vt); err != nil {
		t.Fatalf("transport 解析失败: %v", err)
	}
	if vt.UUID != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Fatalf("uuid 错误: %+v", vt)
	}
	if vt.Security != "tls" || vt.Transport != "ws" || vt.WSPath != "/ws" || vt.WSHost != "cdn.example.com" || vt.SNI != "example.com" || vt.FP != "chrome" {
		t.Fatalf("transport 字段错误: %+v", vt)
	}
}

func TestParseVLESSURIDefaults(t *testing.T) {
	// 无 security/sni → none；无 type → tcp。
	p, err := ParseVLESSURI("vless://u@1.2.3.4:8443")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	var vt VLESSTransport
	_ = json.Unmarshal(p.Transport, &vt)
	if vt.Security != "" && vt.Security != "none" {
		t.Fatalf("无 security 应推断为空/none: %+v", vt)
	}
	if vt.Transport != "tcp" {
		t.Fatalf("无 type 应默认 tcp: %+v", vt)
	}

	// 有 sni 无 security → tls
	p, err = ParseVLESSURI("vless://u@1.2.3.4:443?sni=cdn.example.com")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	var vt2 VLESSTransport
	_ = json.Unmarshal(p.Transport, &vt2)
	if vt2.Security != "tls" || vt2.SNI != "cdn.example.com" {
		t.Fatalf("sni 应推断 tls: %+v", vt2)
	}
}

func TestParseVLESSURIReality(t *testing.T) {
	raw := "vless://u@example.com:443?security=reality&pbk=PUBKEY&sni=www.example.com&sid=ab12&fp=chrome&flow=xtls-rprx-vision"
	p, err := ParseVLESSURI(raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	var vt VLESSTransport
	_ = json.Unmarshal(p.Transport, &vt)
	if vt.Security != "reality" || vt.RealityPBK != "PUBKEY" || vt.RealitySID != "ab12" {
		t.Fatalf("reality 字段错误: %+v", vt)
	}
	if vt.Flow != "xtls-rprx-vision" {
		t.Fatalf("flow 错误: %+v", vt)
	}

	// reality 缺 pbk → 报错
	if _, err := ParseVLESSURI("vless://u@h:443?security=reality&sni=a.com"); err == nil {
		t.Fatal("reality 缺 pbk 应报错")
	}
}

func TestParseVLESSURIErrors(t *testing.T) {
	cases := []string{
		"socks5://1.2.3.4:1080",          // 非 vless
		"vless://example.com:443",        // 缺 uuid（user 为空时 URL parse 会把 example.com 当 host——这里没有 @）
		"vless://u@h:notaport",           // 端口无效
		"vless://u@h:443?security=v2ray", // security 白名单外
		"vless://u@h:443?type=kcp",       // 传输层白名单外
		"vless://u@h:443?type=grpc",      // grpc 缺 serviceName
	}
	for _, raw := range cases {
		if _, err := ParseVLESSURI(raw); err == nil {
			t.Fatalf("%q 应报错", raw)
		}
	}
}

func TestParseProxyLineVLESS(t *testing.T) {
	// 统一入口：订阅行/手动录入走 ParseProxyLine。
	p, err := ParseProxyLine("vless://u@1.2.3.4:443?security=tls")
	if err != nil {
		t.Fatalf("ParseProxyLine vless 失败: %v", err)
	}
	if p.Scheme != "vless" || len(p.Transport) == 0 {
		t.Fatalf("ParseProxyLine 应带出 transport: %+v", p)
	}
	// 混合订阅：vless 行与 socks5 行都能解析。
	mixed := "socks5://1.1.1.1:1080\nvless://u@2.2.2.2:443\n# comment"
	got, err := ParseSubscription([]byte(mixed))
	if err != nil {
		t.Fatalf("混合订阅解析失败: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("应解析出 2 条，得 %d", len(got))
	}
	if got[1].Scheme != "vless" {
		t.Fatalf("第二条应为 vless: %+v", got[1])
	}
}

func TestParseVLESSURIVariants(t *testing.T) {
	// 真实机场节点常见变体回归。
	ok := []string{
		"vless://u@1.2.3.4:443?encryption=none&security=tls&sni=cdn.example.com&fp=chrome&type=ws&host=cdn.example.com&path=%2Fws",
		"vless://u@1.2.3.4:2053?security=tls&type=http&host=cdn.example.com&path=%2F",
		"vless://u@1.2.3.4:443?security=tls&type=httpupgrade&host=cdn.example.com&path=%2F",
		"vless://{u}@1.2.3.4:443?security=tls", // 大括号 UUID
		"vless://u@1.2.3.4:443?type=tcp&headerType=none",
		"vless://u@1.2.3.4:443#MIN",
	}
	for _, raw := range ok {
		if _, err := ParseVLESSURI(raw); err != nil {
			t.Fatalf("%q 应解析成功: %v", raw, err)
		}
	}
	// 大括号被剥掉
	p, err := ParseVLESSURI("vless://{my-uuid}@1.2.3.4:443?security=tls")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	var vt VLESSTransport
	_ = json.Unmarshal(p.Transport, &vt)
	if vt.UUID != "my-uuid" {
		t.Fatalf("大括号未剥离: %q", vt.UUID)
	}
	// xhttp 明确报错而非含糊拒绝
	if _, err := ParseVLESSURI("vless://u@1.2.3.4:443?type=xhttp"); err == nil {
		t.Fatal("xhttp 应报错")
	}
}
