package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	badoption "github.com/sagernet/sing/common/json/badoption"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

// egressEngine 把 vless 池条目翻译成本地 socks 出口：内嵌一个 sing-box 实例，
// 每个启用的 vless 条目 = 一个 vless outbound + 一个 127.0.0.1 随机端口的
// socks inbound，路由规则一对一（in-<id> → out-<id>）。
//
// 重建时机：只在 vless 条目集合（增删/transport 字段变化）变化时整体重建；
// 状态翻转（banned/down）不重建——down 由选路器跳过，入站保持。这样
// go-mitmproxy 拨号失败 → socks 出站错误 → 归因回写池条目的既有链路不变。
//
// 测试覆盖见 server/egress_engine_test.go（起停、端口监听、socks 直连路径）。

// egressEngine 是 Manager 持有的 vless 引擎；零 vless 条目时不启动实例。
type egressEngine struct {
	mu      sync.Mutex
	box     *box.Box
	mapping map[int64]string // poolID -> socks5://127.0.0.1:<port>
	digest  map[int64]string // poolID -> transport JSON（重建判定用）
}

func newEgressEngine() *egressEngine {
	return &egressEngine{mapping: map[int64]string{}}
}

// Sync 把引擎对齐到给定的 vless 条目集合（只处理 enabled 的 vless 条目），
// 返回新的 poolID → 本地 socks URL 映射。集合不变时直接返回现有映射。
func (e *egressEngine) Sync(entries []db.ProxyEntry) (map[int64]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	desired := map[int64]string{}
	var wanted []db.ProxyEntry
	for _, entry := range entries {
		if entry.Scheme != "vless" || !entry.IsEnabled() {
			continue
		}
		wanted = append(wanted, entry)
		desired[entry.ID] = ""
	}

	// 集合未变（id 集合相同且 transport 未变）→ 复用现有实例。
	if e.sameSet(wanted) {
		out := make(map[int64]string, len(e.mapping))
		for id, u := range e.mapping {
			out[id] = u
		}
		return out, nil
	}

	if e.box != nil {
		e.box.Close()
		e.box = nil
	}
	e.mapping = map[int64]string{}
	e.digest = map[int64]string{}

	if len(wanted) == 0 {
		return map[int64]string{}, nil
	}
	for _, entry := range wanted {
		e.digest[entry.ID] = string(entry.Transport)
	}

	opts, mapping, err := buildBoxOptions(wanted)
	if err != nil {
		return nil, err
	}
	instance, err := box.New(box.Options{Context: include.Context(context.Background()), Options: opts})
	if err != nil {
		return nil, fmt.Errorf("启动 vless 引擎: %w", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, fmt.Errorf("启动 vless 引擎: %w", err)
	}
	e.box = instance
	e.mapping = mapping
	return mapping, nil
}

// Resolve 返回某池条目当前的本地 socks URL；非 vless 或未映射返回空。
func (e *egressEngine) Resolve(poolID int64) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mapping[poolID]
}

func (e *egressEngine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box != nil {
		e.box.Close()
		e.box = nil
	}
	e.mapping = map[int64]string{}
	e.digest = map[int64]string{}
}

// sameSet 判断当前实例是否已覆盖 wanted（id 集合 + transport 配置一致）。
func (e *egressEngine) sameSet(wanted []db.ProxyEntry) bool {
	if e.box == nil {
		return false
	}
	if len(wanted) != len(e.mapping) {
		return false
	}
	for _, entry := range wanted {
		if _, ok := e.mapping[entry.ID]; !ok {
			return false
		}
		if string(entry.Transport) != e.digest[entry.ID] {
			return false
		}
	}
	return true
}

// buildBoxOptions 为一组 vless 条目构造 sing-box 配置与端口映射。
func buildBoxOptions(entries []db.ProxyEntry) (option.Options, map[int64]string, error) {
	var inbounds []option.Inbound
	var outbounds []option.Outbound
	var rules []option.Rule
	mapping := map[int64]string{}

	// 兜底直连：路由 Final 指向它，理论上不会被命中（每条 inbound 都有专属规则），
	// 但 sing-box 要求路由可达。
	outbounds = append(outbounds, option.Outbound{
		Type: "direct", Tag: "egress-direct", Options: &option.DirectOutboundOptions{},
	})

	for _, entry := range entries {
		var vt traffic.VLESSTransport
		if err := json.Unmarshal(entry.Transport, &vt); err != nil {
			return option.Options{}, nil, fmt.Errorf("解析条目 #%d transport: %w", entry.ID, err)
		}
		outTag := fmt.Sprintf("egress-out-%d", entry.ID)
		inTag := fmt.Sprintf("egress-in-%d", entry.ID)

		port, err := freePort()
		if err != nil {
			return option.Options{}, nil, err
		}

		vlessOpts, err := buildVLESSOutbound(entry, vt, outTag)
		if err != nil {
			return option.Options{}, nil, err
		}
		outbounds = append(outbounds, option.Outbound{Type: "vless", Tag: outTag, Options: vlessOpts})

		loopback := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
		inbounds = append(inbounds, option.Inbound{
			Type: "socks", Tag: inTag,
			Options: &option.SocksInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     &loopback,
					ListenPort: uint16(port),
				},
			},
		})
		rules = append(rules, option.Rule{
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{Inbound: []string{inTag}},
				RuleAction:     option.RuleAction{Action: "route", RouteOptions: option.RouteActionOptions{Outbound: outTag}},
			},
		})
		mapping[entry.ID] = fmt.Sprintf("socks5://127.0.0.1:%d", port)
	}

	return option.Options{
		Log: &option.LogOptions{Level: "error"},
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{{Type: "local", Tag: "egress-dns"}},
			},
		},
		Inbounds:  inbounds,
		Outbounds: outbounds,
		Route: &option.RouteOptions{
			Rules:                 rules,
			Final:                 "egress-direct",
			DefaultDomainResolver: &option.DomainResolveOptions{Server: "egress-dns"},
		},
	}, mapping, nil
}

// buildVLESSOutbound 把池条目的 transport JSON 翻译成 sing-box vless outbound。
func buildVLESSOutbound(entry db.ProxyEntry, vt traffic.VLESSTransport, tag string) (*option.VLESSOutboundOptions, error) {
	if entry.Port <= 0 || entry.Port > 65535 {
		return nil, fmt.Errorf("条目 #%d 端口无效", entry.ID)
	}
	out := &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: entry.Host, ServerPort: uint16(entry.Port)},
		UUID:          vt.UUID,
		Flow:          vt.Flow,
	}
	if vt.Security == "tls" || vt.Security == "reality" {
		tls := &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: vt.SNI,
			UTLS: &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: firstNonEmpty(vt.FP, "chrome"),
			},
		}
		if vt.ALPN != "" {
			tls.ALPN = strings.Split(vt.ALPN, ",")
		}
		if vt.Security == "reality" {
			tls.Reality = &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: vt.RealityPBK,
				ShortID:   vt.RealitySID,
			}
		}
		out.TLS = tls
	}
	switch vt.Transport {
	case "ws":
		ws := &option.V2RayWebsocketOptions{Path: vt.WSPath}
		if vt.WSHost != "" {
			ws.Headers = badoption.HTTPHeader{"Host": []string{vt.WSHost}}
		}
		out.Transport = &option.V2RayTransportOptions{Type: "ws", WebsocketOptions: *ws}
	case "grpc":
		out.Transport = &option.V2RayTransportOptions{
			Type:        "grpc",
			GRPCOptions: option.V2RayGRPCOptions{ServiceName: vt.GRPCService},
		}
	}
	return out, nil
}

// freePort 抢占一个 127.0.0.1 随机端口后释放。存在极小竞态窗口（端口被
// 他人抢占），sing-box 起不来时 Sync 返回错误，由调用方记录——可接受。
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	return port, ln.Close()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
