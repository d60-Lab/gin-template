package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/d60-Lab/gin-template/pkg/response"
)

// ValidateJSON 通用 JSON 参数验证中间件
// 用法示例：
//
//	router.POST("/users", middleware.ValidateJSON(&dto.CreateUserRequest{}), handler.CreateUser)
func ValidateJSON(obj interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := c.ShouldBindJSON(obj); err != nil {
			response.BadRequest(c, err.Error())
			c.Abort()
			return
		}
		// 将验证后的对象存入上下文，供 handler 使用
		c.Set("validatedRequest", obj)
		c.Next()
	}
}

// GetValidatedRequest 从上下文中获取已验证的请求对象
func GetValidatedRequest(c *gin.Context) (interface{}, bool) {
	return c.Get("validatedRequest")
}
