package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/d60-Lab/gin-template/config"
	"github.com/d60-Lab/gin-template/internal/api/handler"
	"github.com/d60-Lab/gin-template/internal/api/middleware"
	"github.com/d60-Lab/gin-template/internal/api/router"
	"github.com/d60-Lab/gin-template/internal/repository"
	"github.com/d60-Lab/gin-template/internal/service"
	"github.com/d60-Lab/gin-template/pkg/database"
	"github.com/d60-Lab/gin-template/pkg/logger"
	"github.com/d60-Lab/gin-template/pkg/validator"
)

// @title Gin Template API
// @version 1.0
// @description 基于 Gin 框架的项目模板 API
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.email support@example.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// 加载配置
	cfg, err := config.Load()
	if err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}

	// 初始化日志
	if err := logger.Init(cfg.Server.Mode); err != nil {
		panic(fmt.Sprintf("Failed to init logger: %v", err))
	}
	defer logger.Sync()

	logger.Info("Starting application...",
		zap.String("mode", cfg.Server.Mode),
		zap.Int("port", cfg.Server.Port),
	)

	// 初始化 Sentry（如果启用）
	if cfg.Sentry.Enabled {
		err := middleware.InitSentry(middleware.SentryConfig{
			DSN:              cfg.Sentry.DSN,
			Environment:      cfg.Sentry.Environment,
			TracesSampleRate: cfg.Sentry.TracesSampleRate,
			Debug:            cfg.Sentry.Debug,
		})
		if err != nil {
			logger.Error("Failed to init Sentry", zap.Error(err))
		} else {
			logger.Info("Sentry initialized")
			defer sentry.Flush(2 * time.Second)
		}
	}

	// 初始化 OpenTelemetry（如果启用）
	if cfg.Tracing.Enabled {
		tp, err := middleware.InitTracing(middleware.TracingConfig{
			ServiceName:    cfg.Tracing.ServiceName,
			JaegerEndpoint: cfg.Tracing.JaegerEndpoint,
			Enabled:        cfg.Tracing.Enabled,
		})
		if err != nil {
			logger.Error("Failed to init tracing", zap.Error(err))
		} else if tp != nil {
			logger.Info("OpenTelemetry initialized")
			defer func() {
				if err := tp.Shutdown(context.Background()); err != nil {
					logger.Error("Error shutting down tracer provider", zap.Error(err))
				}
			}()
		}
	}

	// 初始化自定义验证器
	validator.Init()

	// 初始化数据库
	db, err := database.InitDB(cfg)
	if err != nil {
		logger.Fatal("Failed to init database", zap.Error(err))
	}

	// 初始化仓储层
	userRepo := repository.NewUserRepository(db)

	// 初始化服务层
	userService := service.NewUserService(userRepo, cfg)

	// 初始化处理器
	h := handler.NewHandler(userService)

	// 设置 Gin 模式
	gin.SetMode(cfg.Server.Mode)

	// 创建路由
	r := gin.New()
	router.Setup(r, h, cfg)

	// 创建 HTTP 服务器
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
	}

	// 在 goroutine 中启动服务
	go func() {
		logger.Info("Server is running",
			zap.String("addr", srv.Addr),
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// 等待中断信号以优雅地关闭服务器
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// 设置 5 秒的超时时间用于优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Server exited")
}
