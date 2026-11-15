package traffic

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// decodeContentBody 按 Content-Encoding 解压响应体副本，供录制存储与展示使用。
// 不修改流经客户端的字节——record() 只对存储副本解压。解压失败（截断/伪 gzip）
// 时原样返回压缩字节，保底可读性不变。
// 支持 gzip / br / deflate / zstd，与 go-mitmproxy 的 decode 白名单一致。
func decodeContentBody(contentEncoding string, body []byte) []byte {
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc == "" || enc == "identity" || len(body) == 0 {
		return body
	}

	var out []byte
	var err error
	switch enc {
	case "gzip":
		var r *gzip.Reader
		r, err = gzip.NewReader(bytes.NewReader(body))
		if err == nil {
			buf := &bytes.Buffer{}
			_, err = buf.ReadFrom(r)
			_ = r.Close()
			out = buf.Bytes()
		}
	case "br":
		buf := &bytes.Buffer{}
		_, err = buf.ReadFrom(brotli.NewReader(bytes.NewReader(body)))
		out = buf.Bytes()
	case "deflate":
		// deflate 有 zlib 头与裸 flate 两种封装，先按 zlib 试，失败再按裸 flate。
		out, err = inflateRaw(body, true)
		if err != nil {
			out, err = inflateRaw(body, false)
		}
	case "zstd":
		var r *zstd.Decoder
		r, err = zstd.NewReader(bytes.NewReader(body))
		if err == nil {
			buf := &bytes.Buffer{}
			_, err = io.Copy(buf, r)
			out = buf.Bytes()
			r.Close()
		}
	default:
		// 未知编码（如多段编码）原样保留。
		return body
	}
	if err != nil || len(out) == 0 {
		return body
	}
	return out
}

// inflateRaw 解压 deflate：zlib 封装或裸 flate 流。
func inflateRaw(body []byte, zlibWrapped bool) ([]byte, error) {
	var r io.ReadCloser
	var err error
	if zlibWrapped {
		r, err = zlib.NewReader(bytes.NewReader(body))
	} else {
		r = flate.NewReader(bytes.NewReader(body))
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	buf := &bytes.Buffer{}
	_, err = buf.ReadFrom(r)
	return buf.Bytes(), err
}
