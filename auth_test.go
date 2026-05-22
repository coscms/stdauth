package stdauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestAuth(t *testing.T) {
	cfg := DefaultAuthConfig
	cfg.SetSecretGetter(func(r *http.Request, appID string) (string, error) {
		return "secret", nil
	})
	cfg.SetDefaults()

	nowTs := time.Now().Unix()
	sign := cfg.SignMaker()(url.Values{
		cfg.FormAppIDKey: {"test"},
		cfg.FormTimeKey:  {formatInt64(nowTs)},
	}, "secret")

	form := url.Values{
		cfg.FormAppIDKey: {"test"},
		cfg.FormSignKey:  {sign},
		cfg.FormTimeKey:  {formatInt64(nowTs)},
	}

	req := httptest.NewRequest(http.MethodPost, "/?"+form.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	err := cfg.Verify(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthMissingAppID(t *testing.T) {
	cfg := NewAuthConfig()
	cfg.SetDefaults()

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.ParseForm()

	err := cfg.Verify(req)
	if err == nil {
		t.Fatal("expected error for missing appID, got nil")
	}
}

func TestAuthExpired(t *testing.T) {
	cfg := DefaultAuthConfig
	cfg.SetSecretGetter(func(r *http.Request, appID string) (string, error) {
		return "secret", nil
	})
	cfg.LifeSeconds = 1
	cfg.SetDefaults()

	oldTs := time.Now().Unix() - 10 // 10 seconds ago, exceeds 1s life
	sign := cfg.SignMaker()(url.Values{
		cfg.FormAppIDKey: {"test"},
		cfg.FormTimeKey:  {formatInt64(oldTs)},
	}, "secret")

	form := url.Values{
		cfg.FormAppIDKey: {"test"},
		cfg.FormSignKey:  {sign},
		cfg.FormTimeKey:  {formatInt64(oldTs)},
	}

	req := httptest.NewRequest(http.MethodPost, "/?"+form.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	err := cfg.Verify(req)
	if err == nil {
		t.Fatal("expected expired signature error, got nil")
	}
}

func TestAuthHeaderFallback(t *testing.T) {
	cfg := DefaultAuthConfig
	cfg.SetSecretGetter(func(r *http.Request, appID string) (string, error) {
		return "secret", nil
	})
	cfg.SetDefaults()

	nowTs := time.Now().Unix()
	sign := cfg.SignMaker()(url.Values{
		cfg.FormAppIDKey: {"test"},
		cfg.FormTimeKey:  {formatInt64(nowTs)},
	}, "secret")

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(cfg.HeaderAppIDKey, "test")
	req.Header.Set(cfg.HeaderSignKey, sign)
	req.Header.Set(cfg.HeaderTimeKey, formatInt64(nowTs))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	err := cfg.Verify(req)
	if err != nil {
		t.Fatalf("unexpected error with header-based auth: %v", err)
	}
}

func TestAuthMiddleware(t *testing.T) {
	cfg := DefaultAuthConfig
	cfg.SetSecretGetter(func(r *http.Request, appID string) (string, error) {
		return "secret", nil
	})
	cfg.SetDefaults()

	nowTs := time.Now().Unix()
	sign := cfg.SignMaker()(url.Values{
		cfg.FormAppIDKey: {"test"},
		cfg.FormTimeKey:  {formatInt64(nowTs)},
	}, "secret")

	form := url.Values{
		cfg.FormAppIDKey: {"test"},
		cfg.FormSignKey:  {sign},
		cfg.FormTimeKey:  {formatInt64(nowTs)},
	}

	req := httptest.NewRequest(http.MethodPost, "/?"+form.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler := cfg.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func formatInt64(n int64) string {
	return strconv.FormatInt(n, 10)
}
