package middleware

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/d60-Lab/gin-template/pkg/logger"
	"github.com/d60-Lab/gin-template/pkg/response"
)

// Recovery 恢复中间件，捕获 panic
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error("panic recovered",
					zap.Any("error", err),
					zap.String("path", c.Request.URL.Path),
				)
				response.InternalError(c, nil)
				c.Abort()
			}
		}()
		c.Next()
	}
}
