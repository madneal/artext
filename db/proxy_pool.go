package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// 出口代理池（阶段 1）的持久层。选路/粘性/封禁逻辑在 traffic/selector.go，
// 这里只做配置 CRUD 与运行时状态回写。schema 见 db/schema.sql 出口代理池一节。

// 代理出口协议白名单。与 traffic.ValidateProxyURL 的支持面保持一致。
var ProxySchemes = map[string]bool{"http": true, "https": true, "socks5": true}

// 代理条目来源。
const (
	ProxySourceManual       = "manual"
	ProxySourceSubscription = "subscription"
)

// 代理运行时状态。
const (
	ProxyStateOK     = "ok"
	ProxyStateBanned = "banned"
	ProxyStateDown   = "down"
)

var ErrProxyNotFound = errors.New("代理条目不存在")
var ErrProxySourceNotFound = errors.New("订阅源不存在")

// ProxyEntry 是池里的一条出口代理。Password 不脱敏返回——代理凭据与既有
// LLM profile 的 api_key 同级，本就属于管理员可配置项。
type ProxyEntry struct {
	ID       int64     `json:"id"`
	Name     string    `json:"name"`
	Scheme   string    `json:"scheme"`
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	Username string    `json:"username"`
	Password string    `json:"password"`
	Enabled  *bool     `json:"enabled,omitempty"`
	Source   string    `json:"source"`
	SourceID int64     `json:"source_id"`
	State    string    `json:"state"`
	LastError string   `json:"last_error"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsEnabled 返回代理是否启用；Enabled 为 nil（未加载）时按启用处理。
func (p *ProxyEntry) IsEnabled() bool { return p.Enabled == nil || *p.Enabled }

// ProxySource 是一个订阅源。
type ProxySource struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	URL        string     `json:"url"`
	Enabled    *bool      `json:"enabled,omitempty"`
	LastSyncAt *time.Time `json:"last_sync_at"`
	LastCount  int        `json:"last_count"`
	LastError  string     `json:"last_error"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func validScheme(s string) bool { return ProxySchemes[strings.ToLower(s)] }

const proxyEntryCols = `id, name, scheme, host, port, username, password, enabled, source, coalesce(source_id,0), state, last_error, last_used_at, created_at, updated_at`

func scanProxyEntry(s interface{ Scan(...any) error }) (ProxyEntry, error) {
	var p ProxyEntry
	err := s.Scan(&p.ID, &p.Name, &p.Scheme, &p.Host, &p.Port, &p.Username, &p.Password,
		&p.Enabled, &p.Source, &p.SourceID, &p.State, &p.LastError, &p.LastUsedAt,
		&p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// ValidProxyScheme 白名单校验代理协议。
func ValidProxyScheme(scheme string) bool { return validScheme(scheme) }

// CreateProxyEntry 新增一条出口代理。scheme 必须在白名单内，host/port 必填。
func (d *DB) CreateProxyEntry(p ProxyEntry) (ProxyEntry, error) {
	if !validScheme(p.Scheme) {
		return ProxyEntry{}, errors.New("不支持的代理协议: " + p.Scheme)
	}
	p.Scheme = strings.ToLower(p.Scheme)
	if strings.TrimSpace(p.Host) == "" || p.Port <= 0 || p.Port > 65535 {
		return ProxyEntry{}, errors.New("代理 host/port 无效")
	}
	if p.Source == "" {
		p.Source = ProxySourceManual
	}
	if p.State == "" {
		p.State = ProxyStateOK
	}
	var created ProxyEntry
	err := d.QueryRow(`
INSERT INTO proxy_pool(name, scheme, host, port, username, password, enabled, source, source_id, state)
VALUES ($1,$2,$3,$4,$5,$6,coalesce($7,true),$8,nullif($9,0),$10)
RETURNING `+proxyEntryCols,
		p.Name, p.Scheme, p.Host, p.Port, p.Username, p.Password, p.Enabled,
		p.Source, p.SourceID, p.State).Scan(
		&created.ID, &created.Name, &created.Scheme, &created.Host, &created.Port,
		&created.Username, &created.Password, &created.Enabled, &created.Source,
		&created.SourceID, &created.State, &created.LastError, &created.LastUsedAt,
		&created.CreatedAt, &created.UpdatedAt)
	return created, err
}

// ListProxyEntries 返回全部代理条目，enabled 优先、新条目在前。
func (d *DB) ListProxyEntries() ([]ProxyEntry, error) {
	rows, err := d.Query(`SELECT ` + proxyEntryCols + ` FROM proxy_pool ORDER BY enabled DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProxyEntry
	for rows.Next() {
		p, err := scanProxyEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProxyEntryPatch 是 UpdateProxyEntry 的局部更新载荷：仅非 nil 字段被覆盖。
type ProxyEntryPatch struct {
	Name     *string
	Scheme   *string
	Host     *string
	Port     *int
	Username *string
	Password *string
	Enabled  *bool
}

// UpdateProxyEntry 局部更新：仅覆盖调用方显式传入的指针字段；state/last_error
// 由选路器经 MarkProxyState 写，不走这里。
func (d *DB) UpdateProxyEntry(id int64, p ProxyEntryPatch) (ProxyEntry, error) {
	res, err := d.Exec(`
UPDATE proxy_pool SET
	name        = coalesce($2, name),
	scheme      = coalesce($3, scheme),
	host        = coalesce($4, host),
	port        = coalesce($5, port),
	username    = coalesce($6, username),
	password    = coalesce($7, password),
	enabled     = coalesce($8, enabled),
	updated_at  = now()
WHERE id = $1`, id, p.Name, p.Scheme, p.Host, p.Port, p.Username, p.Password, p.Enabled)
	if err != nil {
		return ProxyEntry{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ProxyEntry{}, ErrProxyNotFound
	}
	return d.GetProxyEntry(id)
}

// GetProxyEntry 按 id 取一条。
func (d *DB) GetProxyEntry(id int64) (ProxyEntry, error) {
	p, err := scanProxyEntry(d.QueryRow(`SELECT ` + proxyEntryCols + ` FROM proxy_pool WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return ProxyEntry{}, ErrProxyNotFound
	}
	return p, err
}

// DeleteProxyEntry 删除一条（订阅同步产物也可手动删；其源仍在，下轮拉取会重建）。
func (d *DB) DeleteProxyEntry(id int64) error {
	res, err := d.Exec(`DELETE FROM proxy_pool WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrProxyNotFound
	}
	return nil
}

// MarkProxyState 回写选路器的运行时状态（封禁/故障/恢复）。
func (d *DB) MarkProxyState(id int64, state, lastError string) error {
	res, err := d.Exec(`
UPDATE proxy_pool SET state=$2, last_error=$3, updated_at=now() WHERE id=$1`,
		id, state, lastError)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrProxyNotFound
	}
	return nil
}

// MarkProxyUsed 记录最近一次被选中的时间（池页展示活跃度）。
func (d *DB) MarkProxyUsed(id int64) error {
	_, err := d.Exec(`UPDATE proxy_pool SET last_used_at=now() WHERE id=$1`, id)
	return err
}

func (src *ProxySource) IsEnabled() bool { return src.Enabled == nil || *src.Enabled }

const proxySourceCols = `id, name, url, enabled, last_sync_at, last_count, last_error, created_at, updated_at`

func scanProxySource(s interface{ Scan(...any) error }) (ProxySource, error) {
	var src ProxySource
	err := s.Scan(&src.ID, &src.Name, &src.URL, &src.Enabled, &src.LastSyncAt,
		&src.LastCount, &src.LastError, &src.CreatedAt, &src.UpdatedAt)
	return src, err
}

// CreateProxySource 新增订阅源。
func (d *DB) CreateProxySource(src ProxySource) (ProxySource, error) {
	if strings.TrimSpace(src.Name) == "" || strings.TrimSpace(src.URL) == "" {
		return ProxySource{}, errors.New("订阅源 name/url 必填")
	}
	var created ProxySource
	err := d.QueryRow(`
INSERT INTO proxy_sources(name, url, enabled) VALUES ($1,$2,coalesce($3,true))
RETURNING `+proxySourceCols,
		src.Name, src.URL, src.Enabled).Scan(
		&created.ID, &created.Name, &created.URL, &created.Enabled, &created.LastSyncAt,
		&created.LastCount, &created.LastError, &created.CreatedAt, &created.UpdatedAt)
	return created, err
}

// ListProxySources 返回全部订阅源。
func (d *DB) ListProxySources() ([]ProxySource, error) {
	rows, err := d.Query(`SELECT ` + proxySourceCols + ` FROM proxy_sources ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProxySource
	for rows.Next() {
		src, err := scanProxySource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

// GetProxySource 按 id 取一条。
func (d *DB) GetProxySource(id int64) (ProxySource, error) {
	src, err := scanProxySource(d.QueryRow(`SELECT ` + proxySourceCols + ` FROM proxy_sources WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return ProxySource{}, ErrProxySourceNotFound
	}
	return src, err
}

// ProxySourcePatch 是 UpdateProxySource 的局部更新载荷。
type ProxySourcePatch struct {
	Name    *string
	URL     *string
	Enabled *bool
}

// UpdateProxySource 局部更新订阅源。
func (d *DB) UpdateProxySource(id int64, src ProxySourcePatch) (ProxySource, error) {
	res, err := d.Exec(`
UPDATE proxy_sources SET
	name    = coalesce($2, name),
	url     = coalesce($3, url),
	enabled = coalesce($4, enabled),
	updated_at = now()
WHERE id=$1`, id, src.Name, src.URL, src.Enabled)
	if err != nil {
		return ProxySource{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ProxySource{}, ErrProxySourceNotFound
	}
	return d.GetProxySource(id)
}

// DeleteProxySource 删除订阅源；其同步产物随 ON DELETE CASCADE 一并移除，
// manual 条目不受影响。
func (d *DB) DeleteProxySource(id int64) error {
	res, err := d.Exec(`DELETE FROM proxy_sources WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrProxySourceNotFound
	}
	return nil
}

// MarkProxySourceSynced 回写一次同步的结果。
func (d *DB) MarkProxySourceSynced(id int64, count int, lastErr string) error {
	_, err := d.Exec(`
UPDATE proxy_sources SET last_sync_at=now(), last_count=$2, last_error=$3, updated_at=now()
WHERE id=$1`, id, count, lastErr)
	return err
}
