package traffic

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 出口选路器（阶段 1）：代理池 + 同站粘性 + 封禁/故障换出口。
//
// 设计边界：
//   - 粘性与封禁状态都在内存，重启即重置；代理的持久状态(ok/banned/down)由
//     OnEgressState 回调写回 db，下次启动时通过 ReplaceEgressPool 带回来。
//   - 选不出任何可用出口时返回 nil，由调用方降级到全局代理 → 直连，三层兜底。
//   - 封禁判定带 30 分钟冷却：误判(目标本身就返回 403)不会把 (代理,目标) 组合
//     永久打入冷宫，冷却过后允许重试。这是对 spec「接受误判」风险的防御性补充。

// banCooldown 是一条封禁标记的持续时间。
const banCooldown = 30 * time.Minute

// EgressProxy 是选路器视角的一条出口代理，由 server 层从 db.ProxyEntry 转换而来。
// vless 条目不经选路器直接拨号：server 引擎把它翻译成本地 socks 出口后再进池。
type EgressProxy struct {
	ID       int64
	Scheme   string
	Host     string
	Port     int
	Username string
	Password string
	Enabled  bool
	State    string // ok / banned / down（db 持久状态）
	// Transport 是 vless 条目的传输层参数（VLESSTransport 的 JSON），非 vless 为 nil。
	// 只用于 server 层构造 sing-box outbound，选路器本身不读它。
	Transport json.RawMessage
}

// URL 组装该代理的代理 URL，供 go-mitmproxy 拨号使用。
func (p EgressProxy) URL() *url.URL {
	if !p.Enabled || p.State != "ok" {
		return nil
	}
	u := &url.URL{Scheme: p.Scheme, Host: fmt.Sprintf("%s:%d", p.Host, p.Port)}
	if p.Username != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	return u
}

// egEntry 是选路器内存里的一条池条目（pool 快照 + 软状态）。
type egEntry struct {
	EgressProxy
	// downSince 非零表示本轮运行中已观测到拨号失败；恢复由 ReplaceEgressPool
	// 重新装载（server 在状态回写后重推池，或重启）。
	downSince time.Time
}

// banMark 是一条 (目标, 代理) 封禁记录。
type banMark struct {
	proxyID int64
	until   time.Time
}

type egressSelector struct {
	mu sync.RWMutex
	// pool 是 server 推来的整池快照（含未启用条目，选路时过滤）。
	pool []egEntry
	// sticky 是同站粘性表：目标 host → 上次选中并仍在服役的代理。
	sticky map[string]int64
	// bans 是封禁冷却表：目标 host → (代理, 冷却截止)。
	bans map[string][]banMark
	// rr 是轮换游标：粘性失效(封禁/故障/池变更)后按顺序取下一条，保证
	// 多个目标交替时不总落在同一条上。
	rr int
	// OnEgressState 由 server 注入，把封禁/故障持久化；nil 则只影响内存选路。
	OnEgressState func(proxyID int64, state, lastErr string)
}

func newEgressSelector() *egressSelector {
	return &egressSelector{sticky: map[string]int64{}, bans: map[string][]banMark{}}
}

// ReplaceEgressPool 原子替换整池快照（server 在启动、CRUD、订阅同步、状态回写
// 后调用）。粘性表中仍服役的条目保留，其余自然失效。
func (s *egressSelector) ReplaceEgressPool(entries []EgressProxy) {
	now := time.Now()
	pool := make([]egEntry, len(entries))
	for i, e := range entries {
		pool[i] = egEntry{EgressProxy: e}
		if e.State == "down" {
			pool[i].downSince = now
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pool = pool
	// 清掉指向已不存活条目的粘性映射。
	live := map[int64]bool{}
	for _, e := range pool {
		if e.eligible() {
			live[e.ID] = true
		}
	}
	for host, id := range s.sticky {
		if !live[id] {
			delete(s.sticky, host)
		}
	}
	// 清掉指向已消失条目的封禁记录。
	for host, marks := range s.bans {
		kept := marks[:0]
		for _, m := range marks {
			if live[m.proxyID] {
				kept = append(kept, m)
			}
		}
		if len(kept) == 0 {
			delete(s.bans, host)
		} else {
			s.bans[host] = kept
		}
	}
}

// eligible 报告该条目当前是否可作出口（未停用且未被标记 down）。
func (e *egEntry) eligible() bool { return e.Enabled && e.State == "ok" }

func (s *egressSelector) bannedFor(hostKey string, now time.Time) map[int64]bool {
	out := map[int64]bool{}
	marks := s.bans[hostKey]
	kept := marks[:0]
	for _, m := range marks {
		if now.Before(m.until) {
			out[m.proxyID] = true
			kept = append(kept, m)
		}
	}
	if len(kept) != len(marks) {
		s.bans[hostKey] = kept
	}
	return out
}

// Pick 为目标 host 选一条出口代理；无可选时返回 nil（调用方降级）。
func (s *egressSelector) Pick(hostKey string) *url.URL {
	if s == nil {
		return nil
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	banned := s.bannedFor(hostKey, now)

	// 粘性优先：上次选的仍服役且未被封禁 → 沿用。
	if id, ok := s.sticky[hostKey]; ok {
		for i := range s.pool {
			if s.pool[i].ID == id && s.pool[i].eligible() && !banned[id] {
				if u := s.pool[i].URL(); u != nil {
					return u
				}
			}
		}
		delete(s.sticky, hostKey)
	}

	// 轮换取下一条可用出口。
	if len(s.pool) == 0 {
		return nil
	}
	for i := 0; i < len(s.pool); i++ {
		e := &s.pool[(s.rr+i)%len(s.pool)]
		if !e.eligible() || banned[e.ID] {
			continue
		}
		s.rr = (s.rr + i + 1) % len(s.pool)
		s.sticky[hostKey] = e.ID
		return e.URL()
	}
	return nil
}

// NoteBanned 记录一次封禁信号：status 命中固定规则或响应体含关键词时，把
// (host, 粘性代理) 打入冷却，并回写持久状态。只影响后续选路，当前请求不重试。
func (s *egressSelector) NoteBanned(hostKey string, body []byte, status int) {
	if s == nil {
		return
	}
	if !banSignal(status, body) {
		return
	}
	s.mu.Lock()
	proxyID, ok := s.sticky[hostKey]
	if !ok {
		s.mu.Unlock()
		return
	}
	// 同一代理对同一目标重复命中只延长冷却。
	extended := false
	for i := range s.bans[hostKey] {
		if s.bans[hostKey][i].proxyID == proxyID {
			s.bans[hostKey][i].until = time.Now().Add(banCooldown)
			extended = true
			break
		}
	}
	if !extended {
		s.bans[hostKey] = append(s.bans[hostKey], banMark{proxyID: proxyID, until: time.Now().Add(banCooldown)})
	}
	cb := s.OnEgressState
	s.mu.Unlock()

	if !extended {
		log.Printf("[egress] %s 命中封禁信号(HTTP %d)，出口 #%d 进入 %v 冷却", hostKey, status, proxyID, banCooldown)
	}
	if cb != nil {
		cb(proxyID, "banned", fmt.Sprintf("HTTP %d 封禁信号 @ %s", status, hostKey))
	}
}

// NoteDialFailure 在出口代理自身拨号失败时把该代理标记 down 并清除相关粘性。
// 由 server/traffic 在 CONNECT/请求错误回调里调用，err 需已被调用方确认指向
// 代理本身（而非目标不可达）。
func (s *egressSelector) NoteDialFailure(proxyID int64, lastErr string) {
	if s == nil {
		return
	}
	now := time.Now()
	s.mu.Lock()
	for i := range s.pool {
		if s.pool[i].ID == proxyID {
			s.pool[i].State = "down"
			s.pool[i].downSince = now
			break
		}
	}
	for host, id := range s.sticky {
		if id == proxyID {
			delete(s.sticky, host)
		}
	}
	cb := s.OnEgressState
	s.mu.Unlock()

	log.Printf("[egress] 出口 #%d 拨号失败，标记 down：%v", proxyID, lastErr)
	if cb != nil {
		cb(proxyID, "down", lastErr)
	}
}

// StickyProxy 返回目标当前粘住的代理 ID（选路器内部视角，供错误归因）。
func (s *egressSelector) StickyProxy(hostKey string) (int64, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.sticky[hostKey]
	return id, ok
}

// banKeywords 是响应体封禁信号关键词（大小写不敏感，匹配前 banBodyLimit 字节）。
var banKeywords = []string{
	"captcha", "验证码", "rate limit", "too many requests", "访问频率",
	"请求过于频繁", "blocked", "forbidden", "fired wall", "防火墙",
}

// banBodyLimit 限制参与关键词匹配的响应体长度，避免大响应拖慢 record()。
const banBodyLimit = 8 * 1024

// banSignal 判定一次响应是否为封禁信号。
func banSignal(status int, body []byte) bool {
	switch status {
	case 403, 418, 429:
		return true
	}
	if len(body) == 0 {
		return false
	}
	snippet := body
	if len(snippet) > banBodyLimit {
		snippet = snippet[:banBodyLimit]
	}
	low := strings.ToLower(string(snippet))
	for _, kw := range banKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// ParseSubscription 解析订阅响应体为代理条目列表：每行一个代理 URI
// （socks5://user:pass@host:port 或 http://...）；响应体允许整体 base64
// 编码（Clash 等常见导出格式）。非法行跳过，全部非法时报错。
func ParseSubscription(data []byte) ([]EgressProxy, error) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, fmt.Errorf("订阅响应为空")
	}
	lines := strings.Split(text, "\n")
	// 不是 URI 行则尝试整体 base64 解码后再拆行。
	if !looksLikeURI(lines[0]) {
		if dec, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), "")); err == nil && looksLikeURI(firstLine(string(dec))) {
			lines = strings.Split(strings.TrimSpace(string(dec)), "\n")
		}
	}
	var out []EgressProxy
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := ParseProxyLine(line)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("订阅内容中没有可解析的代理 URI")
	}
	return out, nil
}

// ParseProxyLine 解析一行代理 URI（http/https/socks5/vless），手动录入与订阅
// 解析共用。http/https 缺省端口按协议补齐；vless 走 ParseVLESSURI。
func ParseProxyLine(line string) (EgressProxy, error) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(strings.ToLower(line), "vless://") {
		return ParseVLESSURI(line)
	}
	u, err := ValidateProxyURL(line)
	if err != nil {
		return EgressProxy{}, err
	}
	p := EgressProxy{Scheme: u.Scheme, Host: u.Hostname(), Enabled: true, State: "ok"}
	p.Port, _ = strconv.Atoi(u.Port())
	if p.Port == 0 {
		if u.Scheme == "https" {
			p.Port = 443
		} else if u.Scheme == "socks5" {
			p.Port = 1080
		} else {
			p.Port = 80
		}
	}
	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}
	return p, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func looksLikeURI(s string) bool {
	s = strings.TrimSpace(s)
	for _, scheme := range []string{"http://", "https://", "socks5://", "vless://"} {
		if strings.HasPrefix(strings.ToLower(s), scheme) {
			return true
		}
	}
	return false
}
