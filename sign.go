package stdauth

import (
	"crypto/sha256"
	"fmt"
	"net/url"
)

func MakeSign(data url.Values, secret string) string {
	h := sha256.Sum256([]byte(data.Encode() + `&secret=` + secret))
	return fmt.Sprintf("%x", h)
}
