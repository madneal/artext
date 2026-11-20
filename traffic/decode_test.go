package traffic

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// compressWith 用指定编码压缩 data，构造测试用的响应体。
func compressWith(t *testing.T, kind string, data []byte) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	switch kind {
	case "gzip":
		w := gzip.NewWriter(buf)
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	case "zlib", "deflate-zlib":
		w := zlib.NewWriter(buf)
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	case "deflate-raw":
		w, _ := flate.NewWriter(buf, flate.DefaultCompression)
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	case "br":
		w := brotli.NewWriter(buf)
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	case "zstd":
		w, _ := zstd.NewWriter(buf)
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown kind %s", kind)
	}
	return buf.Bytes()
}

func TestDecodeContentBody(t *testing.T) {
	payload := []byte("hello world 你好 0123456789")
	cases := []struct {
		enc  string
		kind string
	}{
		{"gzip", "gzip"},
		{"deflate", "deflate-zlib"},
		{"deflate", "deflate-raw"},
		{"br", "br"},
		{"zstd", "zstd"},
	}
	for _, c := range cases {
		got := decodeContentBody(c.enc, compressWith(t, c.kind, payload))
		if string(got) != string(payload) {
			t.Fatalf("%s/%s 解压不匹配: %q", c.enc, c.kind, got)
		}
	}
}

func TestDecodeContentBodyPassthrough(t *testing.T) {
	// identity / 空 / 未知编码 / 解压失败 → 原样返回
	raw := []byte("plain text")
	if got := decodeContentBody("", raw); string(got) != string(raw) {
		t.Fatal("identity 应原样")
	}
	if got := decodeContentBody("unknown-enc", raw); string(got) != string(raw) {
		t.Fatal("未知编码应原样")
	}
	if got := decodeContentBody("gzip", []byte("\x1f\x8b garbage not gzip")); string(got) == "" {
		t.Fatal("解压失败应原样返回压缩字节")
	}
}

func TestDecodeContentBodyJSON(t *testing.T) {
	// 业务响应常见形态：gzip 的 JSON——解压后必须可解析（这正是乱码修复的目标场景）。
	payload := []byte(`{"code":0,"data":{"list":[1,2,3]},"msg":"ok"}`)
	got := decodeContentBody("gzip", compressWith(t, "gzip", payload))
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("解压后的 JSON 应可解析: %v", err)
	}
}

func TestDecodeContentBodyBombCap(t *testing.T) {
	// 压缩炸弹：32MiB 的零字节压缩后 <64KB，解压会超过 maxDecodedBody 上限，
	// 应回落原始压缩字节而不是分配 GB 级内存。
	bomb := compressWith(t, "gzip", bytes.Repeat([]byte{0}, 64<<20))
	got := decodeContentBody("gzip", bomb)
	if len(got) > maxDecodedBody+1 {
		t.Fatalf("炸弹解压未被限制: %d bytes", len(got))
	}
	if len(got) != len(bomb) {
		t.Fatalf("超限应回落原始压缩字节: got %d want %d", len(got), len(bomb))
	}
}
