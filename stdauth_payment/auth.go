// Package stdauth_payment implements HTTP request authentication via appID/sign/timestamp
// using only Go standard library. It is a stdlib-only equivalent of the
// github.com/coscms/webfront/middleware/mwapp package.
package stdauth_payment

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Pre-defined error sentinel values.
var (
	ErrSignatureExpired = fmt.Errorf("signature has expired")
)

// AuthConfig holds configuration for request signature authentication.
//
// The authentication works by requiring each request to carry:
//   - appID: identifies the application
//   - sign: HMAC-like signature over the request data
//   - timestamp: unix timestamp in seconds
//
// Values are read first from form data, then from HTTP headers as fallback.
// The signature is computed over the sorted form data plus the secret key.
type AuthConfig struct {
	// Header field names for reading appID, sign, and timestamp.
	HeaderAppIDKey string
	HeaderSignKey  string
	HeaderTimeKey  string

	// Form field names for reading appID, sign, and timestamp.
	FormAppIDKey string
	FormSignKey  string
	FormTimeKey  string

	// LifeSeconds limits how old a request's timestamp can be. 0 means no limit.
	LifeSeconds int64

	// IgnoreFieldsOnSign lists form field names (comma-separated) to exclude
	// from signature computation.
	IgnoreFieldsOnSign string

	secretGetter func(r *http.Request, appID string) (string, error)
	signMaker    func(data url.Values, secret string) string
}

// DefaultAuthConfig is the default configuration used as fallback.
var DefaultAuthConfig = AuthConfig{
	HeaderAppIDKey: `X-App-ID`,
	HeaderSignKey:  `X-App-Sign`,
	HeaderTimeKey:  `X-App-Timestamp`,
	FormAppIDKey:   `appID`,
	FormSignKey:    `sign`,
	FormTimeKey:    `timestamp`,
	LifeSeconds:    3600,
	secretGetter: func(r *http.Request, appID string) (string, error) {
		return "", fmt.Errorf("no secret getter configured for appID: %s", appID)
	},
	signMaker: func(data url.Values, secret string) string {
		h := sha256.Sum256([]byte(data.Encode() + `&secret=` + secret))
		return fmt.Sprintf("%x", h)
	},
}

// SetSecretGetter sets the function that retrieves the secret key for an appID.
func (a *AuthConfig) SetSecretGetter(getter func(r *http.Request, appID string) (string, error)) *AuthConfig {
	a.secretGetter = getter
	return a
}

// SecretGetter returns the current secret getter function.
func (a *AuthConfig) SecretGetter() func(r *http.Request, appID string) (string, error) {
	return a.secretGetter
}

// SetSignMaker sets the function that computes the signature over form data and secret.
func (a *AuthConfig) SetSignMaker(signMaker func(data url.Values, secret string) string) *AuthConfig {
	a.signMaker = signMaker
	return a
}

// SignMaker returns the current sign maker function.
func (a *AuthConfig) SignMaker() func(data url.Values, secret string) string {
	return a.signMaker
}

// SetDefaults fills unset fields with values from DefaultAuthConfig.
func (a *AuthConfig) SetDefaults() {
	if len(a.HeaderAppIDKey) == 0 {
		a.HeaderAppIDKey = DefaultAuthConfig.HeaderAppIDKey
	}
	if len(a.HeaderSignKey) == 0 {
		a.HeaderSignKey = DefaultAuthConfig.HeaderSignKey
	}
	if len(a.HeaderTimeKey) == 0 {
		a.HeaderTimeKey = DefaultAuthConfig.HeaderTimeKey
	}
	if len(a.FormAppIDKey) == 0 {
		a.FormAppIDKey = DefaultAuthConfig.FormAppIDKey
	}
	if len(a.FormSignKey) == 0 {
		a.FormSignKey = DefaultAuthConfig.FormSignKey
	}
	if len(a.FormTimeKey) == 0 {
		a.FormTimeKey = DefaultAuthConfig.FormTimeKey
	}
	if a.secretGetter == nil {
		a.secretGetter = DefaultAuthConfig.secretGetter
	}
	if a.signMaker == nil {
		a.signMaker = DefaultAuthConfig.signMaker
	}
}

// getFormOrHeader reads a value first from parsed form data, then from headers.
// Returns (value, true) if the value came from a header, (value, false) if from form.
func getFormOrHeader(r *http.Request, formKey, headerKey string) (string, bool) {
	v := r.FormValue(formKey)
	if len(v) > 0 {
		return strings.TrimSpace(v), false
	}
	v = r.Header.Get(headerKey)
	v = strings.TrimSpace(v)
	return v, v != "" // header-sourced
}

// getFormOrHeaderInt64 reads an int64 value from form or header.
func getFormOrHeaderInt64(r *http.Request, formKey, headerKey string) (int64, bool) {
	v := r.FormValue(formKey)
	if len(v) > 0 {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err == nil && n > 0 {
			return n, false
		}
	}
	hv := r.Header.Get(headerKey)
	if len(hv) > 0 {
		n, err := strconv.ParseInt(strings.TrimSpace(hv), 10, 64)
		if err == nil && n > 0 {
			return n, true
		}
	}
	return 0, false
}

// setFormKV sets a key-value pair on the request's parsed form.
// r.ParseForm must have been called before this.
func setFormKV(r *http.Request, key, value string) {
	if r.Form == nil {
		r.Form = make(url.Values)
	}
	r.Form.Set(key, value)
}

// Prepare extracts and validates appID, sign, and timestamp from the request.
// When the lifecycle check or timestamp validation fails, an error is returned.
func (a *AuthConfig) Prepare(r *http.Request) (appID string, sign string, err error) {
	appID, headerSourced := getFormOrHeader(r, a.FormAppIDKey, a.HeaderAppIDKey)
	if len(appID) == 0 {
		return "", "", fmt.Errorf("invalid parameter %s: empty", a.FormAppIDKey)
	}
	if headerSourced {
		setFormKV(r, a.FormAppIDKey, appID)
	}

	sign = r.FormValue(a.FormSignKey)
	if len(sign) == 0 {
		sign = strings.TrimSpace(r.Header.Get(a.HeaderSignKey))
		if len(sign) == 0 {
			return appID, "", nil
		}
		setFormKV(r, a.FormSignKey, sign)
	}

	timestamp, headerSourced := getFormOrHeaderInt64(r, a.FormTimeKey, a.HeaderTimeKey)
	if timestamp <= 0 {
		return appID, sign, fmt.Errorf("invalid parameter %s: missing or zero", a.FormTimeKey)
	}
	if headerSourced {
		setFormKV(r, a.FormTimeKey, strconv.FormatInt(timestamp, 10))
	}

	if len(sign) > 0 && a.LifeSeconds > 0 {
		if time.Now().Unix()-timestamp > a.LifeSeconds {
			return appID, sign, ErrSignatureExpired
		}
	}
	return appID, sign, nil
}

// SignRequest computes the expected signature for the request.
// It collects form data, handles JSON/XML body if applicable, removes the sign
// field from the data, and delegates to the configured signMaker.
func (a *AuthConfig) SignRequest(r *http.Request, appID string) (sign string, data url.Values, err error) {
	if a.secretGetter == nil {
		return "", nil, fmt.Errorf("secret getter not configured")
	}
	secret, err := a.secretGetter(r, appID)
	if err != nil {
		return "", nil, err
	}

	contentType := r.Header.Get("Content-Type")
	isJSON := strings.Contains(contentType, "application/json")
	isXML := strings.Contains(contentType, "application/xml")

	if isJSON || isXML {
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return "", nil, err
		}
		// Restore body so downstream handlers can read it.
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		data = r.Form
		if len(body) > 0 {
			data.Set("data", string(body))
		}
	} else {
		data = r.Form
		if len(a.IgnoreFieldsOnSign) > 0 {
			for field := range strings.SplitSeq(a.IgnoreFieldsOnSign, ",") {
				field = strings.TrimSpace(field)
				delete(data, field)
			}
		}
	}

	delete(data, a.FormSignKey)
	sign = a.signMaker(data, secret)
	return sign, data, nil
}

// Verify extracts and validates the request signature.
// It parses the form data, extracts parameters, computes the expected signature,
// and compares it against the provided one.
func (a *AuthConfig) Verify(r *http.Request) error {
	appID, sign, err := a.Prepare(r)
	if err != nil {
		return err
	}
	genSign, _, err := a.SignRequest(r, appID)
	if err != nil {
		return err
	}
	if sign != genSign {
		log.Printf("sign mismatch: got %s, expected %s", sign, genSign)
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// Middleware returns an http.Handler that verifies request signatures before
// delegating to the next handler. On verification failure it responds with
// HTTP 401 Unauthorized.
func (a *AuthConfig) Middleware(next http.Handler) http.Handler {
	cfg := *a
	cfg.SetDefaults()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := cfg.Verify(r); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewAuthConfig creates a new AuthConfig with zero values.
func NewAuthConfig() *AuthConfig {
	return &AuthConfig{}
}
