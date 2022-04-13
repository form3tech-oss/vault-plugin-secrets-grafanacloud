package client

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	grafanaStarting       = "Your instance is starting"
	TempKeyDefaultExpires = 60
	TempKeyDefaultPrefix  = "terraform-provider-grafanacloud-tmp"
)

type CreateAPIKeyInput struct {
	Name         string `json:"name"`
	Role         string `json:"role"`
	Organisation string `json:"-"`
}

type APIKey struct {
	ID         int
	Name       string
	Role       string
	Token      string
	Expiration string
}

type Client struct {
	client *resty.Client

	// This client can generate temporary Grafana API admin tokens for the purpose
	// of reading resources from the Grafana API. Define a time after which these
	// tokens automatically expire. Note that we'll also try to delete them automatically
	// after use, but if that fails, this serves as a fallback mechanism to invalidate them.
	TempKeyExpires time.Duration

	// Temporarily created Grafana API admin tokens have a prefix so you can identify them
	// easily, which defaults to the value of constant constant `TempKeyPrefix`.
	TempKeyPrefix string
}

func (c *Client) DeleteAPIKey(ctx context.Context, org string, keyName string) error {
	url := fmt.Sprintf("orgs/%s/api-keys/%s", org, keyName)
	resp, err := c.client.R().
		SetContext(ctx).
		Delete(url)

	if err := HandleError(err, resp, "failed to delete Grafana Cloud Portal API key"); err != nil {
		return err
	}

	return nil
}

func (c *Client) CreateAPIKey(ctx context.Context, r *CreateAPIKeyInput) (*APIKey, error) {
	url := fmt.Sprintf("orgs/%s/api-keys", r.Organisation)

	resp, err := c.client.R().
		SetBody(r).
		SetResult(&APIKey{}).
		SetContext(ctx).
		Post(url)

	if err := HandleError(err, resp, "failed to create Grafana Cloud Portal API key"); err != nil {
		return nil, err
	}

	return resp.Result().(*APIKey), nil
}

func HandleError(err error, resp *resty.Response, msg string) error {
	if err != nil {
		return fmt.Errorf("%s: %v", msg, err)
	}

	if resp.IsError() {
		return HttpError(msg, resp)
	}

	return nil
}

func HttpError(message string, resp *resty.Response) error {
	return fmt.Errorf("%s. Status code %d, response: %s", message, resp.StatusCode(), resp.Body())
}

type ClientOpt func(*Client)

func NewClient(baseURL, apiKey string, opts ...ClientOpt) (*Client, error) {
	url := baseURL

	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}

	resty := resty.New().
		SetDebug(len(os.Getenv("HTTP_DEBUG")) != 0).
		SetAuthToken(apiKey).
		SetBaseURL(url).
		SetTimeout(10 * time.Second).
		SetRetryWaitTime(10 * time.Second).
		SetRetryCount(6).
		AddRetryCondition(canRetry).
		AddRetryHook(logRetry)

	c := &Client{
		client:         resty,
		TempKeyExpires: TempKeyDefaultExpires * time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

func WithUserAgent(userAgent string) ClientOpt {
	return func(c *Client) {
		c.client.SetHeader("User-Agent", userAgent)
	}
}

func WithTempKeyExpires(d time.Duration) ClientOpt {
	return func(c *Client) {
		c.TempKeyExpires = d
	}
}

func WithTempKeyPrefix(prefix string) ClientOpt {
	return func(c *Client) {
		c.TempKeyPrefix = prefix
	}
}

// We retry for two reasons:
// 1. Grafana Cloud APIs might apply rate limiting to API requests
// 2. Newly created Grafana Cloud Stacks don't accept requests to create Grafana API keys immediately
func canRetry(r *resty.Response, err error) bool {
	return r.StatusCode() == http.StatusTooManyRequests ||
		strings.Contains(r.String(), grafanaStarting)
}

func logRetry(r *resty.Response, err error) {
	if err != nil {
		log.Printf("[WARN] retrying %s to `%s` because of error: %v", r.Request.Method, r.Request.URL, err)
		return
	}

	log.Printf("[WARN] retrying %s to `%s` because of response: %s", r.Request.Method, r.Request.URL, r)
}
