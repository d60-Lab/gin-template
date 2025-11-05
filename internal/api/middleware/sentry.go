package middleware

import (
	"time"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
)

// SentryConfig Sentry 配置
type SentryConfig struct {
	DSN              string
	Environment      string
	TracesSampleRate float64
	Debug            bool
}

// InitSentry 初始化 Sentry
func InitSentry(config SentryConfig) error {
	return sentry.Init(sentry.ClientOptions{
		Dsn:              config.DSN,
		Environment:      config.Environment,
		TracesSampleRate: config.TracesSampleRate,
		Debug:            config.Debug,
	})
}

// Sentry 创建 Sentry 中间件
func Sentry() gin.HandlerFunc {
	return sentrygin.New(sentrygin.Options{
		Repanic:         true,
		WaitForDelivery: false,
		Timeout:         5 * time.Second,
	})
}
