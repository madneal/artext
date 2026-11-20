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

// maxDecodedBody 限制解压输出的最大体积。压缩炸弹（gzip 比例可达 1000×）在
// 录制路径同步解压会把多 MB 压缩体膨胀成 GB 级堆分配——超限即放弃解压，原样
// 保留压缩字节（展示为乱码但内存安全）。
const maxDecodedBody = 32 << 20 // 32 MiB

// decodeContentBody 按 Content-Encoding 解压响应体副本，供录制存储与展示使用。
// 不修改流经客户端的字节——record() 只对存储副本解压。解压失败（截断/伪 gzip）
// 或超过 maxDecodedBody 时原样返回压缩字节，保底可读性与内存安全。
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
			_, err = io.Copy(buf, io.LimitReader(r, maxDecodedBody+1))
			_ = r.Close()
			out = buf.Bytes()
		}
	case "br":
		buf := &bytes.Buffer{}
		_, err = buf.ReadFrom(io.LimitReader(brotli.NewReader(bytes.NewReader(body)), maxDecodedBody+1))
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
			_, err = io.Copy(buf, io.LimitReader(r, maxDecodedBody+1))
			out = buf.Bytes()
			r.Close()
		}
	default:
		// 未知编码（如多段编码）原样保留。
		return body
	}
	// 解压失败、空输出或超限（LimitReader 截断后可能以 ErrUnexpectedEOF 收尾，
	// 此时不判 err）一律回落原始压缩字节。
	if err != nil || len(out) == 0 || len(out) > maxDecodedBody {
		return body
	}
	return out
}

// inflateRaw 解压 deflate：zlib 封装或裸 flate 流（LimitReader 限长防炸弹）。
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
	_, err = buf.ReadFrom(io.LimitReader(r, maxDecodedBody+1))
	return buf.Bytes(), err
}
