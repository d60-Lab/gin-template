package router

import (
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/d60-Lab/gin-template/config"
	_ "github.com/d60-Lab/gin-template/docs" // swagger docs
	"github.com/d60-Lab/gin-template/internal/api/handler"
	"github.com/d60-Lab/gin-template/internal/api/middleware"
)

// Setup 设置路由
func Setup(r *gin.Engine, h *handler.Handler, cfg *config.Config) {
	// 全局中间件
	r.Use(middleware.CORS())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.Logger())
	r.Use(middleware.Recovery())
	r.Use(gzip.Gzip(gzip.DefaultCompression))

	// 可选的 Sentry 中间件
	if cfg.Sentry.Enabled {
		r.Use(middleware.Sentry())
	}

	// 可选的 OpenTelemetry 中间件
	if cfg.Tracing.Enabled {
		r.Use(middleware.Tracing(cfg.Tracing.ServiceName))
	}

	// 可选的 Pprof 性能分析
	if cfg.Pprof.Enabled {
		middleware.Pprof(r)
	}

	// Swagger 文档
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// 健康检查
	r.GET("/health", h.HealthCheck)

	// API 版本分组
	v1 := r.Group("/api/v1")
	{
		// 认证相关
		auth := v1.Group("/auth")
		{
			auth.POST("/login", h.Login)
		}

		// 用户模块
		users := v1.Group("/users")
		{
			users.POST("", h.CreateUser)
			users.GET("", h.ListUsers)
			users.GET("/:id", h.GetUser)
			users.PUT("/:id", middleware.Auth(cfg), h.UpdateUser)
			users.DELETE("/:id", middleware.Auth(cfg), middleware.AdminOnly(), h.DeleteUser)
		}
	}
}
