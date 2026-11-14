package traffic

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// VLESS 分享链接（vless://uuid@host:port?params#name）的解析与 transport
// 参数白名单。这是阶段 1.5 的数据层：本文件不拨号——vless 出口由 sing-box
// 引擎翻译成本地 socks，见 server/egress_engine.go。
//
// transport JSON 是 vless 条目在 proxy_pool.transport 列的唯一合法形态，
// 字段白名单在这里，server 引擎按它构造 sing-box outbound。

// VLESSTransport 是一条 vless 出口的传输层参数。
type VLESSTransport struct {
	UUID        string `json:"uuid"`
	Flow        string `json:"flow,omitempty"`      // xtls-rprx-vision 等
	Security    string `json:"security"`            // none / tls / reality
	SNI         string `json:"sni,omitempty"`       // TLS/Reality SNI
	FP          string `json:"fp,omitempty"`        // uTLS 指纹（chrome 等默认 chrome）
	ALPN        string `json:"alpn,omitempty"`      // 逗号分隔
	Transport   string `json:"transport,omitempty"` // tcp / ws / grpc（底层网络，security 是其上的加密层）
	WSHost      string `json:"ws_host,omitempty"`
	WSPath      string `json:"ws_path,omitempty"`
	GRPCService string `json:"grpc_service,omitempty"`
	RealityPBK  string `json:"reality_pbk,omitempty"` // Reality 公钥
	RealitySID  string `json:"reality_sid,omitempty"` // Reality shortId
	RealitySPX  string `json:"reality_spx,omitempty"` // Reality spiderX
}

// ParseVLESSURI 解析 vless:// 分享链接为 EgressProxy（Transport 字段填好）。
// 返回的 EgressProxy 没有 ID（调用方入库后获得），Enabled/State 由调用方定。
func ParseVLESSURI(raw string) (EgressProxy, error) {
	raw = strings.TrimSpace(raw)
	// 部分客户端导出的 UUID 带 {}（如 vless://{uuid}@host），url.Parse 视为
	// 非法 userinfo——只在 userinfo 段（首个 @ 之前）剥掉大括号。
	if at := strings.Index(raw, "@"); at > 0 {
		head := strings.Map(func(r rune) rune {
			if r == '{' || r == '}' {
				return -1
			}
			return r
		}, raw[:at])
		raw = head + raw[at:]
	}
	u, err := url.Parse(raw)
	if err != nil {
		return EgressProxy{}, fmt.Errorf("解析 vless URI %q: %w", raw, err)
	}
	if !strings.EqualFold(u.Scheme, "vless") {
		return EgressProxy{}, fmt.Errorf("不是 vless URI: %q", raw)
	}
	if u.User == nil || u.User.Username() == "" {
		return EgressProxy{}, fmt.Errorf("vless URI 缺少 UUID: %q", raw)
	}
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil || host == "" || port <= 0 || port > 65535 {
		return EgressProxy{}, fmt.Errorf("vless URI host/port 无效: %q", raw)
	}
	q := u.Query()

	uuid := strings.TrimSpace(u.User.Username())
	uuid = strings.Trim(uuid, "{}")
	vt := VLESSTransport{
		UUID:        uuid,
		Flow:        q.Get("flow"),
		Security:    strings.ToLower(q.Get("security")),
		SNI:         q.Get("sni"),
		FP:          q.Get("fp"),
		ALPN:        q.Get("alpn"),
		Transport:   strings.ToLower(q.Get("type")),
		WSHost:      q.Get("host"),
		WSPath:      q.Get("path"),
		GRPCService: q.Get("serviceName"),
		RealityPBK:  q.Get("pbk"),
		RealitySID:  q.Get("sid"),
		RealitySPX:  q.Get("spx"),
	}
	if vt.Transport == "" {
		vt.Transport = "tcp"
	}
	if vt.Security == "" && (vt.RealityPBK != "" || vt.RealitySID != "") {
		vt.Security = "reality"
	}
	if vt.Security == "" && vt.SNI != "" {
		vt.Security = "tls"
	}
	switch vt.Security {
	case "", "none", "tls", "reality":
	default:
		return EgressProxy{}, fmt.Errorf("不支持的 vless security %q（none/tls/reality）", vt.Security)
	}
	// xhttp 是 Xray 独有传输层，sing-box 没有——明确报错而不是含糊拒绝。
	if vt.Transport == "xhttp" || vt.Transport == "splithttp" {
		return EgressProxy{}, fmt.Errorf("xhttp/splithttp 传输层暂不支持（sing-box 无此传输）")
	}
	switch vt.Transport {
	case "tcp", "ws", "grpc", "http", "httpupgrade":
	default:
		return EgressProxy{}, fmt.Errorf("不支持的 vless 传输层 %q（tcp/ws/grpc/http/httpupgrade）", vt.Transport)
	}
	if vt.Transport == "grpc" && vt.GRPCService == "" {
		return EgressProxy{}, fmt.Errorf("grpc 传输层缺少 serviceName")
	}
	if vt.Security == "reality" && (vt.RealityPBK == "" || vt.SNI == "") {
		return EgressProxy{}, fmt.Errorf("reality 需要 pbk 与 sni")
	}

	transportJSON, err := json.Marshal(vt)
	if err != nil {
		return EgressProxy{}, err
	}
	return EgressProxy{
		Scheme:    "vless",
		Host:      host,
		Port:      port,
		Transport: transportJSON,
		Enabled:   true,
		State:     "ok",
	}, nil
}
