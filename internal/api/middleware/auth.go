package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/d60-Lab/gin-template/config"
	"github.com/d60-Lab/gin-template/pkg/jwt"
	"github.com/d60-Lab/gin-template/pkg/response"
)

// Auth JWT 认证中间件
func Auth(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			response.Unauthorized(c)
			c.Abort()
			return
		}

		// 移除 "Bearer " 前缀
		token = strings.TrimPrefix(token, "Bearer ")

		claims, err := jwt.ParseToken(token, cfg.JWT.Secret)
		if err != nil {
			response.Unauthorized(c)
			c.Abort()
			return
		}

		// 将用户信息存入上下文
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Next()
	}
}

// AdminOnly 管理员权限中间件
func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 这里应该从数据库或缓存中检查用户角色
		// 示例代码仅作演示
		userID, exists := c.Get("userID")
		if !exists {
			response.Unauthorized(c)
			c.Abort()
			return
		}

		// TODO: 实际项目中应该查询用户角色
		_ = userID

		c.Next()
	}
}
