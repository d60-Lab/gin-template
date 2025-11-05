package middleware

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/d60-Lab/gin-template/pkg/response"
)

// RateLimit 限流中间件
func RateLimit() gin.HandlerFunc {
	limiter := rate.NewLimiter(100, 200) // 每秒100个请求，突发200个

	return func(c *gin.Context) {
		if !limiter.Allow() {
			response.Error(c, 429, "rate limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}
