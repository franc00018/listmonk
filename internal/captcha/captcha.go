package captcha

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type captchaResp struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error_codes"`
}

// Captcha is a simple Captcha client.
// It currently implements hcaptcha.com
type Captcha struct {
	o      Opt
	client *http.Client
}

type Opt struct {
	CaptchaSecret        string `json:"captcha_secret"`
	CaptchaResponseField string `json:"captcha_response_field"`
	VerifyURL            string `json:"captcha_verify_url"`
}

// New returns a new instance of the HTTP CAPTCHA client.
func New(o Opt) *Captcha {
	timeout := time.Second * 5
	verifyURL := o.VerifyURL
	if verifyURL == "" {
		verifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	}

	return &Captcha{
		o: o,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   10,
				MaxConnsPerHost:       100,
				ResponseHeaderTimeout: timeout,
				IdleConnTimeout:       timeout,
			},
		},
	}
}

// Verify verifies a CAPTCHA request.
func (c *Captcha) Verify(token string) (error, bool) {
	resp, err := c.client.PostForm(c.o.VerifyURL, url.Values{
		"secret":   {c.o.CaptchaSecret},
		"response": {token},
	})
	if err != nil {
		return err, false
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
		}
	}(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err, false
	}

	var r captchaResp
	if err := json.Unmarshal(body, &r); err != nil {
		return err, true
	}

	if !r.Success {
		return fmt.Errorf("captcha failed: %s", strings.Join(r.ErrorCodes, ",")), false
	}

	return nil, true
}
