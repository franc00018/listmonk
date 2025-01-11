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
	fmt.Printf("Verifying CAPTCHA token: %s\n", token)
	fmt.Printf("Using VerifyURL: %s\n", c.o.VerifyURL)

	resp, err := c.client.PostForm(c.o.VerifyURL, url.Values{
		"secret":   {c.o.CaptchaSecret},
		"response": {token},
	})
	if err != nil {
		fmt.Printf("Error posting to CAPTCHA verification URL: %v\n", err)
		return err, false
	}

	fmt.Printf("CAPTCHA verification response status: %s\n", resp.Status)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err, false
	}

	fmt.Printf("CAPTCHA verification response body: %s\n", string(body))

	var r captchaResp
	if err := json.Unmarshal(body, &r); err != nil {
		fmt.Printf("Error unmarshalling response JSON: %v\n", err)
		return err, true
	}

	fmt.Printf("CAPTCHA verification success: %v\n", r.Success)
	if !r.Success {
		fmt.Printf("CAPTCHA verification failed with error codes: %v\n", r.ErrorCodes)
		return fmt.Errorf("captcha failed: %s", strings.Join(r.ErrorCodes, ",")), false
	}

	fmt.Println("CAPTCHA verification successful")
	return nil, true
}
