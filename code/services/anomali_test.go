package services

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
	"net/http"
	"testing"
	"time"
)

func TestAnomaliContracts(t *testing.T) {
	svcLookupContracts(t, func(c *gin.Context, h *http.Client, d time.Duration, u string, s *ssm.Client, k *kms.Client) (int, error) {
		return (&AnomaliClient{HTTP: h, Timeout: d, BaseURL: u + "?keep=yes"}).CheckIOC(c, "example.org &more", s, k, svcTestLogger())
	}, "anomali_api", `{"average_confidence":76}`, 76, func(t *testing.T, r *http.Request) {
		q := r.URL.Query()
		if r.Method != "GET" || r.URL.Host != "offline.invalid" || r.URL.Path != "/custom" || q.Get("value") != "example.org &more" || q.Get("type") != "confidence" || q.Get("keep") != "yes" || r.Header.Get("Authorization") != "apikey secret-anomali_user:secret-anomali_api" {
			t.Fatalf("request=%s %s headers=%v", r.Method, r.URL, r.Header)
		}
	})
}
func TestAnomaliUserSecretFailure(t *testing.T) {
	s, k := svcTestSecrets(t, "anomali_user")
	h := &http.Client{Transport: svcTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		t.Error("API called after user secret error")
		return svcTestJSONResponse(200, `{}`), nil
	})}
	_, err := (&AnomaliClient{HTTP: h, Timeout: time.Second}).CheckIOC(svcTestContext(context.Background()), "x.org", s, k, svcTestLogger())
	if err == nil {
		t.Fatal("missing secret error")
	}
}
func TestAnomaliConstructorAndBadURL(t *testing.T) {
	v := NewAnomaliClient()
	if v.HTTP == nil || v.Timeout != 5*time.Second || v.HTTP.Timeout != v.Timeout || v.BaseURL != "https://api.threatstream.com/api/v1/inteldetails/confidence_trend/?type=confidence" {
		t.Fatalf("constructor=%+v", v)
	}
	_, e := (&AnomaliClient{BaseURL: "%", Timeout: time.Second}).CheckIOC(svcTestContext(context.Background()), "ioc", nil, nil, svcTestLogger())
	if e == nil {
		t.Fatal("bad URL accepted")
	}
}
