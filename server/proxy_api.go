package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

// 出口代理池（阶段 1）的管理面：池 → traffic 选路器的装载、订阅拉取、
// REST API。选路本体在 traffic/selector.go；持久层在 db/proxy_pool.go。
//
// 不变量：任何池/订阅变更后都必须 refreshEgressPool()，否则选路器看到的是
// 旧池。选路器的状态回写（banned/down）也经这里落库并重推。

// subscriptionInterval 是订阅源的定时拉取周期。阶段 1 固定值，不暴露配置。
const subscriptionInterval = 10 * time.Minute

// refreshEgressPool 把 db 里的池快照推给 traffic 选路器。启动、CRUD、订阅
// 同步、状态回写后都会调用；traffic 层未启用时静默跳过。
func (m *Manager) refreshEgressPool() {
	if m.traffic == nil || m.pg == nil {
		return
	}
	entries, err := m.pg.ListProxyEntries()
	if err != nil {
		log.Printf("[egress] 读取代理池失败：%v", err)
		return
	}
	eps, err := m.resolveEgressEntries(entries)
	if err != nil {
		log.Printf("[egress] 解析代理池失败：%v", err)
		return
	}
	m.traffic.ReplaceEgressPool(eps, m.onEgressState)
	log.Printf("[egress] 代理池装载 %d 条（enabled %d）", len(eps), enabledCount(eps))
}

// resolveEgressEntries 把 db 条目翻译成选路器条目：vless 条目经引擎映射为
// 本地 socks 出口（scheme/host/port 替换，ID/状态保留），其余原样透传。
// 引擎仅在存在启用的 vless 条目时重建实例。
func (m *Manager) resolveEgressEntries(entries []db.ProxyEntry) ([]traffic.EgressProxy, error) {
	mapping, err := m.egressEngine.Sync(entries)
	if err != nil {
		return nil, err
	}
	eps := make([]traffic.EgressProxy, 0, len(entries))
	for _, e := range entries {
		ep := toEgressProxy(e)
		if e.Scheme == "vless" {
			local := mapping[e.ID]
			if local == "" {
				// 引擎里没有这条（未启用或启动失败）：跳过，不出现在选路池。
				continue
			}
			u, err := traffic.ValidateProxyURL(local)
			if err != nil {
				return nil, err
			}
			ep.Scheme = "socks5"
			ep.Host = u.Hostname()
			ep.Port, _ = strconv.Atoi(u.Port())
			ep.Username, ep.Password = "", ""
		}
		eps = append(eps, ep)
	}
	return eps, nil
}

// enabledCount 数池里启用的条目，仅供装载日志。
func enabledCount(entries []traffic.EgressProxy) int {
	n := 0
	for _, e := range entries {
		if e.Enabled {
			n++
		}
	}
	return n
}

// toEgressProxy 把 db 条目转成选路器条目。
func toEgressProxy(e db.ProxyEntry) traffic.EgressProxy {
	return traffic.EgressProxy{
		ID: e.ID, Scheme: e.Scheme, Host: e.Host, Port: e.Port,
		Username: e.Username, Password: e.Password,
		Enabled: e.IsEnabled(), State: e.State,
	}
}

// onEgressState 把选路器的封禁/故障判定持久化，然后异步重推池快照——
// 同步重推会在选路器回调路径里拿 selector 锁，异步隔开这个依赖。
func (m *Manager) onEgressState(proxyID int64, state, lastErr string) {
	if err := m.pg.MarkProxyState(proxyID, state, lastErr); err != nil {
		log.Printf("[egress] 回写出口 #%d 状态 %s 失败：%v", proxyID, state, err)
		return
	}
	go m.refreshEgressPool()
}

// startSubscriptionPoller 启动订阅定时拉取（每 subscriptionInterval 一轮，
// 只拉 enabled 源）。失败只记 last_error，不影响现有出口。
func (m *Manager) startSubscriptionPoller() {
	if m.pg == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(subscriptionInterval)
		defer ticker.Stop()
		for range ticker.C {
			m.syncEnabledSources(context.Background())
		}
	}()
}

// syncEnabledSources 同步全部启用的订阅源，返回成功条数。
func (m *Manager) syncEnabledSources(ctx context.Context) int {
	if m.pg == nil {
		return 0
	}
	sources, err := m.pg.ListProxySources()
	if err != nil {
		log.Printf("[egress] 读取订阅源失败：%v", err)
		return 0
	}
	ok := 0
	for _, src := range sources {
		if !src.IsEnabled() {
			continue
		}
		if _, err := m.SyncProxySource(ctx, src.ID); err != nil {
			log.Printf("[egress] 订阅源 %q 同步失败：%v", src.Name, err)
			continue
		}
		ok++
	}
	return ok
}

// SyncProxySource 拉取一个订阅源并 diff 进池：新 URI 插入、消失的旧同步产物
// 停用、manual 条目与其他来源不受影响。返回本源同步后的条目数。
func (m *Manager) SyncProxySource(ctx context.Context, sourceID int64) (int, error) {
	src, err := m.pg.GetProxySource(sourceID)
	if err != nil {
		return 0, err
	}
	parsed, err := fetchSubscription(ctx, src.URL)
	if err != nil {
		_ = m.pg.MarkProxySourceSynced(sourceID, src.LastCount, err.Error())
		return 0, err
	}

	existing, err := m.pg.ListProxyEntries()
	if err != nil {
		return 0, err
	}
	// seen 记录本次订阅仍提供的条目键，用于停用消失条目。
	seen := map[string]bool{}
	seq := 0
	for _, p := range parsed {
		key := p.Scheme + "|" + p.Host + "|" + strconv.Itoa(p.Port) + "|" + p.Username
		seen[key] = true
		dup := false
		for _, e := range existing {
			if e.Scheme == p.Scheme && e.Host == p.Host && e.Port == p.Port && e.Username == p.Username {
				dup = true
				// 同源已停用条目重新启用；跨源/手填条目不动。
				if e.SourceID == sourceID && !e.IsEnabled() {
					enabled := true
					_, _ = m.pg.UpdateProxyEntry(e.ID, db.ProxyEntryPatch{Enabled: &enabled})
				}
				break
			}
		}
		if !dup {
			seq++
			if _, err := m.pg.CreateProxyEntry(db.ProxyEntry{
				Name:   fmt.Sprintf("%s #%d", src.Name, seq),
				Scheme: p.Scheme, Host: p.Host, Port: p.Port,
				Username: p.Username, Password: p.Password,
				Transport: p.Transport,
				Source:    db.ProxySourceSubscription, SourceID: sourceID,
			}); err != nil {
				return 0, fmt.Errorf("写入订阅条目 %s: %w", key, err)
			}
		}
	}
	// 消失的旧同步产物停用（不删，保留状态历史）。
	disabled := 0
	for _, e := range existing {
		if e.SourceID != sourceID {
			continue
		}
		key := e.Scheme + "|" + e.Host + "|" + strconv.Itoa(e.Port) + "|" + e.Username
		if !seen[key] && e.IsEnabled() {
			off := false
			_, _ = m.pg.UpdateProxyEntry(e.ID, db.ProxyEntryPatch{Enabled: &off})
			disabled++
		}
	}
	count := len(parsed)
	_ = m.pg.MarkProxySourceSynced(sourceID, count, "")
	m.refreshEgressPool()
	log.Printf("[egress] 订阅源 %q 同步完成：%d 条（停用 %d 条）", src.Name, count, disabled)
	return count, nil
}

// fetchSubscription 拉取订阅 URL。解析交给 traffic.ParseSubscription；走直连
// ——订阅地址通常可直连，且经全局代理会与被测流量混在同一个出口。
func fetchSubscription(ctx context.Context, url string) ([]traffic.EgressProxy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("订阅响应 HTTP %d", resp.StatusCode)
	}
	body := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(tmp)
		body = append(body, tmp[:n]...)
		if len(body) > 8*1024*1024 {
			return nil, fmt.Errorf("订阅响应超过 8MB，疑似异常")
		}
		if rerr != nil {
			break
		}
	}
	return traffic.ParseSubscription(body)
}

// ---------- REST handlers ----------

type proxyEntryRequest struct {
	Name     *string `json:"name"`
	Scheme   *string `json:"scheme"`
	Host     *string `json:"host"`
	Port     *int    `json:"port"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	Enabled  *bool   `json:"enabled"`
	// URI 允许直接粘贴完整代理链接（vless://… / socks5://…），优先于零散字段。
	URI       *string         `json:"uri"`
	Transport json.RawMessage `json:"transport"`
}

func (s *Server) proxyListEntries(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	entries, err := pg.ListProxyEntries()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if entries == nil {
		entries = []db.ProxyEntry{}
	}
	writeJSON(w, 200, map[string]any{"entries": entries})
}

func (s *Server) proxyCreateEntry(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req proxyEntryRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON: "+err.Error())
		return
	}
	var parsed *traffic.EgressProxy
	if req.URI != nil && strings.TrimSpace(*req.URI) != "" {
		p, err := traffic.ParseProxyLine(*req.URI)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		parsed = &p
	}
	var scheme, host string
	var port int
	if parsed != nil {
		scheme, host, port = parsed.Scheme, parsed.Host, parsed.Port
	} else {
		if req.Scheme == nil || req.Host == nil || req.Port == nil {
			writeErr(w, 400, "scheme/host/port 必填（或直接提供 uri）")
			return
		}
		scheme, host, port = *req.Scheme, strings.TrimSpace(*req.Host), *req.Port
	}
	create := db.ProxyEntry{
		Name: strOr(req.Name), Scheme: scheme, Host: host, Port: port,
		Username: strOr(req.Username), Password: strOr(req.Password),
		Source: db.ProxySourceManual,
	}
	if parsed != nil && parsed.Scheme == "vless" {
		create.Transport = parsed.Transport
	} else if req.Scheme != nil && db.ValidProxyScheme(*req.Scheme) && strings.EqualFold(*req.Scheme, "vless") {
		// 零散字段 + transport JSON 的表单路径
		create.Transport = req.Transport
	}
	entry, err := pg.CreateProxyEntry(create)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.m.refreshEgressPool()
	writeJSON(w, 200, entry)
}

func (s *Server) proxyUpdateEntry(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 id")
		return
	}
	var req proxyEntryRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON: "+err.Error())
		return
	}
	if req.Scheme != nil && !db.ValidProxyScheme(*req.Scheme) {
		writeErr(w, 400, "不支持的代理协议: "+*req.Scheme)
		return
	}
	patch := db.ProxyEntryPatch{
		Name: req.Name, Scheme: req.Scheme, Host: req.Host, Port: req.Port,
		Username: req.Username, Password: req.Password, Enabled: req.Enabled,
		Transport: req.Transport,
	}
	entry, err := pg.UpdateProxyEntry(id, patch)
	if err != nil {
		writeErr(w, errStatus(err), err.Error())
		return
	}
	s.m.refreshEgressPool()
	writeJSON(w, 200, entry)
}

func (s *Server) proxyDeleteEntry(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 id")
		return
	}
	if err := pg.DeleteProxyEntry(id); err != nil {
		writeErr(w, errStatus(err), err.Error())
		return
	}
	s.m.refreshEgressPool()
	writeJSON(w, 200, map[string]any{"ok": true})
}

type proxySourceRequest struct {
	Name    *string `json:"name"`
	URL     *string `json:"url"`
	Enabled *bool   `json:"enabled"`
}

func (s *Server) proxyListSources(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sources, err := pg.ListProxySources()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if sources == nil {
		sources = []db.ProxySource{}
	}
	writeJSON(w, 200, map[string]any{"sources": sources})
}

func (s *Server) proxyCreateSource(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req proxySourceRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON: "+err.Error())
		return
	}
	src, err := pg.CreateProxySource(db.ProxySource{Name: strOr(req.Name), URL: strOr(req.URL), Enabled: req.Enabled})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, src)
}

func (s *Server) proxyUpdateSource(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 id")
		return
	}
	var req proxySourceRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON: "+err.Error())
		return
	}
	patch := db.ProxySourcePatch{Name: req.Name, URL: req.URL, Enabled: req.Enabled}
	src, err := pg.UpdateProxySource(id, patch)
	if err != nil {
		writeErr(w, errStatus(err), err.Error())
		return
	}
	writeJSON(w, 200, src)
}

func (s *Server) proxyDeleteSource(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 id")
		return
	}
	if err := pg.DeleteProxySource(id); err != nil {
		writeErr(w, errStatus(err), err.Error())
		return
	}
	s.m.refreshEgressPool()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) proxySyncSource(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 id")
		return
	}
	count, err := s.m.SyncProxySource(r.Context(), id)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "count": count})
}

// errStatus 把持久层 not-found 错误映射为 404，其余 400（校验类）。
func errStatus(err error) int {
	if err == db.ErrProxyNotFound || err == db.ErrProxySourceNotFound {
		return 404
	}
	return 400
}

func strOr(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}
