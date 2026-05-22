package stdauth

import (
	"crypto/sha256"
	"fmt"
	"net/url"
)

// MakeSign 生成签名
// 规则说明：数据按照以键的字母顺序排列后进行url编码，然后拼接上`&secret=密钥`
// 等价的PHP代码：
// ```php
// <?php
//
//	function makeSign(array $data, string $secret): string{
//		ksort($data);
//		return hash('sha256',http_build_query($data).'&secret='.$secret);
//	}
//
// ```
func MakeSign(data url.Values, secret string) string {
	h := sha256.Sum256([]byte(data.Encode() + `&secret=` + secret))
	return fmt.Sprintf("%x", h)
}
