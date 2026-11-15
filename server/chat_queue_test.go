package server

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// chatQueueFixture 在 sideHTTPFixture 基础上补齐 conversation turn 所需的
// chatAgent（真实 ChatAgent + 可控 fake provider），专门测 Codex 排队注入。
//
// gate 协议：fake provider 的 Stream 在发出首个事件后阻塞在 f.provider.release
// 上（closed = 放行）；每次 Stream 调用会把 CompletionRequest 发进 started
// channel——测试用它断言每回合的模型输入。
type chatQueueFixture struct {
	*sideHTTPFixture
}

func newChatQueueFixture(t *testing.T) *chatQueueFixture {
	t.Helper()
	f := newSideHTTPFixture(t)
	tx := transcript.NewStore(filepath.Join(f.m.dir, "transcripts"))
	ca := agent.NewChatAgent(f.s.llmDirect, f.s.llmCfg.Model, f.m.dir, tx, 0)
	f.s.cfgMu.Lock()
	f.s.chatAgent = ca
	f.s.cfgMu.Unlock()
	return &chatQueueFixture{f}
}

func (f *chatQueueFixture) convMsg(t *testing.T, convID int64, text string, want int) map[string]any {
	t.Helper()
	w := f.call(t, "POST", fmt.Sprintf("/api/conversations/%d/messages", convID), map[string]any{"message": text}, want)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

// waitStarted 读取 provider 的下一次 Stream 请求（带超时），返回其中的用户文本。
func (f *chatQueueFixture) waitStarted(t *testing.T) string {
	t.Helper()
	select {
	case req := <-f.provider.started:
		return lastUserText(req)
	case <-time.After(5 * time.Second):
		t.Fatal("等待 LLM 请求超时")
		return ""
	}
}

func waitBusyCleared(t *testing.T, s *Server, busyKey string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.chatMu.Lock()
		busy := s.chatBusy[busyKey]
		s.chatMu.Unlock()
		if !busy {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("busy 未清空")
}

func waitConvBubble(t *testing.T, f *chatQueueFixture, convID int64, needle string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := f.s.m.pg.QueryRow(
			`SELECT count(*) FROM conversation_activities WHERE conversation_id=$1 AND kind='user' AND detail LIKE $2`,
			convID, "%"+needle+"%").Scan(&n); err == nil && n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("用户气泡 %q 未落库", needle)
}

func TestConversationChatQueue(t *testing.T) {
	f := newChatQueueFixture(t)
	convID := mustCreateConv(t, f)

	// 回合一：Stream 阻塞在 release 上。
	release := make(chan struct{})
	f.provider.release = release

	f.convMsg(t, convID, "msg1", 202)
	if got := f.waitStarted(t); !strings.Contains(got, "msg1") {
		t.Fatalf("turn1 输入不含 msg1: %q", got)
	}

	// 运行中排队两条：202 queued，气泡即时落库。
	r2 := f.convMsg(t, convID, "msg2", 202)
	if r2["status"] != "queued" || r2["pending"] != float64(1) {
		t.Fatalf("msg2 应返回 queued/pending=1: %v", r2)
	}
	if got := f.s.pendingCount(f.s.convBusyKey(convID)); got != 1 {
		t.Fatalf("pendingCount=1, got %d", got)
	}
	f.convMsg(t, convID, "msg3", 202)
	waitConvBubble(t, f, convID, "msg3")

	// 放行回合一 → drain 队列 → msg2+msg3 合并为回合二输入。
	close(release)
	got := f.waitStarted(t)
	if !strings.Contains(got, "msg2") || !strings.Contains(got, "msg3") {
		t.Fatalf("turn2 应合并队列输入 msg2+msg3: %q", got)
	}
	// 回合二自然结束（release 已 closed）→ busy 清空、队列空。
	waitBusyCleared(t, f.s, f.s.convBusyKey(convID))
	if n := f.s.pendingCount(f.s.convBusyKey(convID)); n != 0 {
		t.Fatalf("队列应已清空, got %d", n)
	}
}

func TestConversationChatQueueStopKeepsQueue(t *testing.T) {
	f := newChatQueueFixture(t)
	convID := mustCreateConv(t, f)

	release := make(chan struct{})
	f.provider.release = release

	f.convMsg(t, convID, "msg1", 202)
	f.waitStarted(t)

	// 运行中排队一条，然后停止当前回合。
	f.convMsg(t, convID, "queued-msg", 202)
	f.call(t, "POST", fmt.Sprintf("/api/conversations/%d/stop", convID), nil, 200)
	close(release)
	waitBusyCleared(t, f.s, f.s.convBusyKey(convID))
	if n := f.s.pendingCount(f.s.convBusyKey(convID)); n != 1 {
		t.Fatalf("停止后队列应保留 1 条, got %d", n)
	}

	// 下次发送：残留队列并入输入（queued-msg + msg3 一起到模型）。
	f.provider.release = make(chan struct{})
	close(f.provider.release)
	f.convMsg(t, convID, "msg3", 202)
	sawCombined := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !sawCombined {
		select {
		case req := <-f.provider.started:
			if text := lastUserText(req); strings.Contains(text, "queued-msg") && strings.Contains(text, "msg3") {
				sawCombined = true
			}
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !sawCombined {
		t.Fatal("下次发送应并入残留队列（queued-msg + msg3）")
	}
	waitBusyCleared(t, f.s, f.s.convBusyKey(convID))
}

func TestConversationChatQueueStatusPending(t *testing.T) {
	f := newChatQueueFixture(t)
	convID := mustCreateConv(t, f)

	release := make(chan struct{})
	f.provider.release = release

	f.convMsg(t, convID, "msg1", 202)
	f.waitStarted(t)
	f.convMsg(t, convID, "msg2", 202)

	// chatStatus 端点（task 版）与 conversation 的行为一致性在这里只验证
	// pendingCount 的观察面——HTTP 层由 task 侧单测覆盖。
	if n := f.s.pendingCount(f.s.convBusyKey(convID)); n != 1 {
		t.Fatalf("pending 应为 1, got %d", n)
	}
	close(release)
	waitBusyCleared(t, f.s, f.s.convBusyKey(convID))
}

func lastUserText(req llm.CompletionRequest) string {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == llm.RoleUser {
			var sb strings.Builder
			for _, b := range req.Messages[i].Content {
				if b.Text != "" {
					sb.WriteString(b.Text)
				}
			}
			return sb.String()
		}
	}
	return ""
}

func mustCreateConv(t *testing.T, f *chatQueueFixture) int64 {
	t.Helper()
	c, err := f.s.m.pg.CreateConversation("mainagent", "queue test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.s.m.pg.DeleteConversation(c.ID) })
	return c.ID
}
