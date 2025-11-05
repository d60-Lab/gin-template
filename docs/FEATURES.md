# 新增功能使用指南

本文档介绍项目中新增的高级功能及其使用方法。

## 📚 目录

1. [Swagger API 文档](#1-swagger-api-文档)
2. [Repository 单元测试](#2-repository-单元测试)
3. [通用验证中间件](#3-通用验证中间件)
4. [Pprof 性能分析](#4-pprof-性能分析)
5. [Sentry 错误追踪](#5-sentry-错误追踪)
6. [OpenTelemetry 分布式追踪](#6-opentelemetry-分布式追踪)

---

## 1. Swagger API 文档

### 功能说明

自动生成 RESTful API 文档，提供交互式 API 测试界面。

### 安装工具

```bash
# 安装 swag 命令行工具
go install github.com/swaggo/swag/cmd/swag@latest

# 或使用 Makefile
make install-tools
```

### 生成文档

```bash
# 生成 Swagger 文档
make swagger

# 或手动执行
swag init -g cmd/server/main.go -o docs --parseDependency --parseInternal
```

### 访问文档

启动项目后，访问：

```
http://localhost:8080/swagger/index.html
```

### 编写注释

在 Handler 方法上添加注释：

```go
// CreateUser 创建用户
// @Summary 创建用户
// @Description 注册新用户
// @Tags 用户管理
// @Accept json
// @Produce json
// @Param request body dto.CreateUserRequest true "用户信息"
// @Success 200 {object} response.Response{data=dto.UserResponse}
// @Failure 400 {object} response.Response
// @Router /api/v1/users [post]
func (h *Handler) CreateUser(c *gin.Context) {
    // ...
}
```

### 常用注释标签

| 标签 | 说明 | 示例 |
|------|------|------|
| @Summary | 接口摘要 | @Summary 创建用户 |
| @Description | 详细描述 | @Description 注册新用户 |
| @Tags | 分组标签 | @Tags 用户管理 |
| @Accept | 接受的内容类型 | @Accept json |
| @Produce | 返回的内容类型 | @Produce json |
| @Param | 参数说明 | @Param id path string true "用户ID" |
| @Success | 成功响应 | @Success 200 {object} Response |
| @Failure | 失败响应 | @Failure 400 {object} Response |
| @Router | 路由路径 | @Router /api/v1/users [post] |
| @Security | 安全认证 | @Security Bearer |

---

## 2. Repository 单元测试

### 功能说明

为数据访问层提供单元测试示例，使用 SQLite 内存数据库进行测试。

### 运行测试

```bash
# 运行所有测试
make test

# 运行特定包的测试
go test -v ./internal/repository/...

# 查看测试覆盖率
make test-coverage
```

### 测试示例

```go
func (suite *UserRepositoryTestSuite) TestCreate() {
    ctx := context.Background()
    user := &model.User{
        ID:       "test-id",
        Username: "testuser",
        Email:    "test@example.com",
        Password: "hashedpassword",
    }

    err := suite.repo.Create(ctx, user)
    assert.NoError(suite.T(), err)
}
```

### 最佳实践

1. **使用测试套件**：继承 `suite.Suite`，复用测试环境
2. **内存数据库**：使用 SQLite 内存数据库，速度快，无副作用
3. **数据清理**：每个测试后清理数据，保证测试独立性
4. **覆盖率**：确保关键路径有测试覆盖

---

## 3. 通用验证中间件

### 功能说明

简化 Handler 中的参数验证代码，避免重复的绑定和错误处理。

### 使用前（传统方式）

```go
func (h *Handler) CreateUser(c *gin.Context) {
    var req dto.CreateUserRequest
    
    if err := c.ShouldBindJSON(&req); err != nil {
        response.BadRequest(c, err.Error())
        return
    }
    
    // 业务逻辑...
}
```

### 使用后（中间件方式）

```go
// 在路由中使用
router.POST("/users", 
    middleware.ValidateJSON(&dto.CreateUserRequest{}), 
    handler.CreateUser)

// Handler 中获取已验证的对象
func (h *Handler) CreateUser(c *gin.Context) {
    req, _ := middleware.GetValidatedRequest(c)
    userReq := req.(*dto.CreateUserRequest)
    
    // 业务逻辑...
}
```

### 优势

- ✅ 减少重复代码
- ✅ 统一错误处理
- ✅ 验证逻辑集中管理
- ✅ 代码更简洁

---

## 4. Pprof 性能分析

### 功能说明

内置 Go 性能分析工具，可以分析 CPU、内存、goroutine 等性能指标。

### 配置开启

在 `config/config.yaml` 中配置：

```yaml
pprof:
  enabled: true  # 开启 pprof
```

**⚠️ 注意**：生产环境建议关闭，或通过环境变量动态控制。

### 访问 Pprof

启动项目后，可以访问以下端点：

```bash
# 主页面
http://localhost:8080/debug/pprof/

# CPU Profile（30秒采样）
http://localhost:8080/debug/pprof/profile?seconds=30

# 内存 Profile
http://localhost:8080/debug/pprof/heap

# Goroutine 信息
http://localhost:8080/debug/pprof/goroutine

# 所有 Block 信息
http://localhost:8080/debug/pprof/block
```

### 使用工具分析

```bash
# 分析 CPU（交互式）
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30

# 分析内存
go tool pprof http://localhost:8080/debug/pprof/heap

# 生成可视化图表（需要安装 graphviz）
go tool pprof -http=:8081 http://localhost:8080/debug/pprof/heap
```

### 常用命令

在 pprof 交互模式下：

```bash
top10          # 显示前10个占用最多的函数
list funcName  # 显示函数源码
web            # 生成调用图（需要 graphviz）
png            # 生成 PNG 图片
exit           # 退出
```

---

## 5. Sentry 错误追踪

### 功能说明

实时监控和追踪应用程序错误，提供详细的错误上下文和堆栈信息。

### 配置

1. 在 [sentry.io](https://sentry.io) 创建项目，获取 DSN

2. 在 `config/config.yaml` 中配置：

```yaml
sentry:
  enabled: true
  dsn: "https://your-dsn@sentry.io/project-id"
  environment: production
  traces_sample_rate: 1.0  # 采样率 0.0-1.0
  debug: false
```

3. 或使用环境变量：

```bash
export SENTRY_DSN="https://your-dsn@sentry.io/project-id"
export SENTRY_ENVIRONMENT="production"
```

### 自动错误捕获

Sentry 中间件会自动捕获：

- ✅ Panic 错误
- ✅ HTTP 错误响应
- ✅ 请求上下文信息

### 手动发送错误

```go
import "github.com/getsentry/sentry-go"

// 捕获异常
if err != nil {
    sentry.CaptureException(err)
}

// 发送消息
sentry.CaptureMessage("Something went wrong")

// 添加上下文
sentry.WithScope(func(scope *sentry.Scope) {
    scope.SetTag("user_id", userID)
    scope.SetContext("user", map[string]interface{}{
        "username": username,
        "email":    email,
    })
    sentry.CaptureException(err)
})
```

### 性能监控

```go
// 开始事务
span := sentry.StartSpan(ctx, "database.query")
defer span.Finish()

// 执行数据库查询
result := db.Query(...)
```

---

## 6. OpenTelemetry 分布式追踪

### 功能说明

实现分布式追踪，帮助理解请求在微服务架构中的流转路径和性能瓶颈。

### 配置 Jaeger

1. 启动 Jaeger（使用 Docker）：

```bash
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 14268:14268 \
  jaegertracing/all-in-one:latest
```

2. 在 `config/config.yaml` 中配置：

```yaml
tracing:
  enabled: true
  service_name: gin-template
  jaeger_endpoint: http://localhost:14268/api/traces
```

### 访问 Jaeger UI

```
http://localhost:16686
```

### 自定义 Span

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
)

func (s *Service) SomeMethod(ctx context.Context) error {
    // 创建 span
    tracer := otel.Tracer("service-name")
    ctx, span := tracer.Start(ctx, "SomeMethod")
    defer span.End()

    // 添加属性
    span.SetAttributes(
        attribute.String("user.id", userID),
        attribute.Int("item.count", count),
    )

    // 记录事件
    span.AddEvent("processing started")

    // 执行业务逻辑...

    return nil
}
```

### 数据库追踪

使用 GORM 插件自动追踪数据库操作：

```go
import (
    "gorm.io/plugin/opentelemetry/tracing"
)

// 注册插件
db.Use(tracing.NewPlugin())
```

### 查看追踪数据

在 Jaeger UI 中可以看到：

- 请求完整链路
- 每个服务的耗时
- Span 之间的依赖关系
- 性能瓶颈点

---

## 🎯 最佳实践建议

### 开发环境

```yaml
pprof:
  enabled: true   # 开启性能分析
sentry:
  enabled: false  # 关闭 Sentry
tracing:
  enabled: true   # 开启追踪，便于调试
```

### 测试环境

```yaml
pprof:
  enabled: true   # 性能测试时开启
sentry:
  enabled: true   # 收集测试错误
  environment: staging
tracing:
  enabled: true   # 追踪性能问题
```

### 生产环境

```yaml
pprof:
  enabled: false  # 默认关闭，需要时通过环境变量开启
sentry:
  enabled: true   # 必须开启
  environment: production
  traces_sample_rate: 0.1  # 降低采样率
tracing:
  enabled: true   # 建议开启
```

---

## 📊 性能影响

| 功能 | 性能影响 | 建议 |
|------|----------|------|
| Swagger | 无 | 生产环境可禁用路由 |
| Pprof | 低 | 按需开启 |
| Sentry | 低-中 | 调整采样率 |
| OpenTelemetry | 低-中 | 调整采样率 |

---

## 🔧 故障排查

### Swagger 文档不更新

```bash
# 重新生成文档
make swagger

# 清理缓存
go clean -cache
```

### Sentry 没有收到错误

1. 检查 DSN 是否正确
2. 检查网络连接
3. 查看应用日志
4. 确认 `enabled: true`

### Jaeger 没有追踪数据

1. 检查 Jaeger 是否运行
2. 检查 endpoint 配置
3. 确认 `enabled: true`
4. 查看应用日志

---

## 📚 参考资料

- [Swagger/OpenAPI 规范](https://swagger.io/specification/)
- [Go Pprof 使用指南](https://go.dev/blog/pprof)
- [Sentry Go SDK](https://docs.sentry.io/platforms/go/)
- [OpenTelemetry Go](https://opentelemetry.io/docs/instrumentation/go/)
- [Jaeger 文档](https://www.jaegertracing.io/docs/)
