package traffic

import (
	"net/url"
	"testing"
)

func mkProxy(id int64, scheme, host string, port int, state string, enabled bool) EgressProxy {
	return EgressProxy{ID: id, Scheme: scheme, Host: host, Port: port, State: state, Enabled: enabled}
}

func TestPickStickyPerHost(t *testing.T) {
	s := newEgressSelector()
	s.ReplaceEgressPool([]EgressProxy{mkProxy(1, "http", "p1", 1, "ok", true), mkProxy(2, "http", "p2", 2, "ok", true)})

	a := s.Pick("a.com")
	b := s.Pick("b.com")
	if a == nil || b == nil {
		t.Fatalf("两目标都应选到出口: a=%v b=%v", a, b)
	}
	// 同站粘性：重复选择必须拿到同一条。
	if got := s.Pick("a.com"); got.String() != a.String() {
		t.Fatalf("同站粘性失效: %v != %v", got, a)
	}
	// 不同站允许轮换到其他出口（这里断言至少记录了两个粘性目标）。
	if _, ok := s.StickyProxy("b.com"); !ok {
		t.Fatal("b.com 应有粘性记录")
	}
}

func TestPickFallsBackWhenPoolEmptyOrDown(t *testing.T) {
	s := newEgressSelector()
	if got := s.Pick("x.com"); got != nil {
		t.Fatalf("空池应返回 nil 交给上层降级，得 %v", got)
	}
	s.ReplaceEgressPool([]EgressProxy{mkProxy(1, "http", "p1", 1, "down", true)})
	if got := s.Pick("x.com"); got != nil {
		t.Fatalf("全部 down 应返回 nil，得 %v", got)
	}
	s.ReplaceEgressPool([]EgressProxy{mkProxy(1, "http", "p1", 1, "ok", false)})
	if got := s.Pick("x.com"); got != nil {
		t.Fatalf("停用条目不可选，得 %v", got)
	}
}

func TestBanCooldownSwitchesEgress(t *testing.T) {
	s := newEgressSelector()
	s.ReplaceEgressPool([]EgressProxy{mkProxy(1, "http", "p1", 1, "ok", true), mkProxy(2, "http", "p2", 2, "ok", true)})
	first := s.Pick("target.com")
	if first == nil {
		t.Fatal("应选到出口")
	}
	s.NoteBanned("target.com", []byte("please solve the captcha"), 200)
	second := s.Pick("target.com")
	if second == nil {
		t.Fatal("封禁后应换到另一条出口")
	}
	if second.String() == first.String() {
		t.Fatalf("封禁后仍粘在原出口 %v", first)
	}
	// 冷却期内不回到被封禁的出口。
	for i := 0; i < 5; i++ {
		if got := s.Pick("target.com"); got.String() == first.String() {
			t.Fatalf("第 %d 次选择回到被封禁出口", i)
		}
	}
	// 其他目标不受影响：轮换游标可能指向任一条，但不应因 target.com 的封禁而全池不可用。
	if got := s.Pick("other.com"); got == nil {
		t.Fatal("其他目标应仍可选到出口")
	}
}

func TestBanSignalRules(t *testing.T) {
	cases := []struct {
		status int
		body   []byte
		want   bool
	}{
		{200, []byte("ok"), false},
		{403, nil, true},
		{418, nil, true},
		{429, nil, true},
		{500, nil, false},
		{200, []byte("Too Many Requests"), true},
		{200, []byte("请输入验证码"), true},
		{200, []byte("访问频率过高"), true},
		{200, []byte("normal page"), false},
	}
	for i, c := range cases {
		if got := banSignal(c.status, c.body); got != c.want {
			t.Fatalf("case %d: banSignal(%d, %q)=%v, want %v", i, c.status, c.body, got, c.want)
		}
	}
}

func TestNoteDialFailureMarksDownAndStickyCleared(t *testing.T) {
	var states []string
	s := newEgressSelector()
	s.OnEgressState = func(id int64, state, _ string) { states = append(states, state) }
	s.ReplaceEgressPool([]EgressProxy{mkProxy(1, "socks5", "p1", 1080, "ok", true)})

	if got := s.Pick("h1.com"); got == nil {
		t.Fatal("应选到唯一出口")
	}
	s.NoteDialFailure(1, "dial tcp p1:1080: i/o timeout")

	if got := s.Pick("h1.com"); got != nil {
		t.Fatalf("down 后不应再选到出口，得 %v", got)
	}
	if len(states) != 1 || states[0] != "down" {
		t.Fatalf("状态回写错误: %v", states)
	}
	// 重推池（server 回写后刷新快照）也不复活 down 条目。
	s.ReplaceEgressPool([]EgressProxy{mkProxy(1, "socks5", "p1", 1080, "down", true)})
	if got := s.Pick("h1.com"); got != nil {
		t.Fatal("持久 down 状态重推后仍应不可选")
	}
}

func TestReplaceEgressPoolKeepsSticky(t *testing.T) {
	s := newEgressSelector()
	s.ReplaceEgressPool([]EgressProxy{mkProxy(1, "http", "p1", 1, "ok", true), mkProxy(2, "http", "p2", 2, "ok", true)})
	first := s.Pick("keep.com")
	// 状态回写后 server 重推同池：粘性不应丢。
	s.ReplaceEgressPool([]EgressProxy{mkProxy(1, "http", "p1", 1, "ok", true), mkProxy(2, "http", "p2", 2, "ok", true)})
	if got := s.Pick("keep.com"); got == nil || first == nil || got.String() != first.String() {
		t.Fatalf("重推池后粘性丢失: %v != %v", got, first)
	}
}

func TestProxyURLAuth(t *testing.T) {
	p := EgressProxy{ID: 1, Scheme: "socks5", Host: "1.2.3.4", Port: 1080, Username: "u", Password: "p", Enabled: true, State: "ok"}
	u := p.URL()
	if u == nil {
		t.Fatal("ok 条目应能组装 URL")
	}
	if u.User == nil || u.User.Username() != "u" {
		t.Fatalf("凭据丢失: %v", u)
	}
	p.State = "banned"
	if p.URL() != nil {
		t.Fatal("banned 条目不应给出 URL")
	}
}

func TestParseSubscription(t *testing.T) {
	raw := "# comment\nsocks5://u:p@1.2.3.4:1080\nhttp://5.6.7.8:8080\nnot-a-proxy\n\nhttps://9.9.9.9"
	got, err := ParseSubscription([]byte(raw))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("应解析出 3 条，得 %d: %+v", len(got), got)
	}
	if got[0].Host != "1.2.3.4" || got[0].Port != 1080 || got[0].Username != "u" || got[0].Password != "p" {
		t.Fatalf("带凭据解析错误: %+v", got[0])
	}
	if got[1].Scheme != "http" || got[1].Port != 8080 {
		t.Fatalf("http 条目错误: %+v", got[1])
	}
	if got[2].Port != 443 {
		t.Fatalf("https 默认端口错误: %+v", got[2])
	}
}

func TestParseSubscriptionBase64(t *testing.T) {
	enc := url.QueryEscape("")
	_ = enc
	b64 := "c29ja3M1Oi8vdTpwQDEuMi4zLjQ6MTA4MApodHRwOi8vNS42LjcuODo4MDgwCg==" // socks5://u:p@1.2.3.4:1080\nhttp://5.6.7.8:8080
	got, err := ParseSubscription([]byte(b64))
	if err != nil {
		t.Fatalf("base64 订阅解析失败: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("应解析出 2 条，得 %d", len(got))
	}
	if got[0].Port != 1080 || got[0].Password != "p" {
		t.Fatalf("base64 内容解析错误: %+v", got[0])
	}
}

func TestParseSubscriptionEmpty(t *testing.T) {
	if _, err := ParseSubscription([]byte("")); err == nil {
		t.Fatal("空响应应报错")
	}
	if _, err := ParseSubscription([]byte("aGVsbG8gd29ybGQK")); err == nil { // "hello world" 的 base64
		t.Fatal("无代理 URI 内容应报错")
	}
}
