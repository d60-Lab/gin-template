# 新功能快速使用指南

本指南帮助您快速上手使用项目中新增的 6 大高级功能。

## 🚀 5 分钟快速开始

### 1. 查看 Swagger API 文档

这是最简单且最推荐的第一步！

```bash
# 启动应用
make run

# 或使用热重载
make dev
```

然后在浏览器中打开：

```
http://localhost:8080/swagger/index.html
```

您将看到：

- 📖 所有 API 接口的详细文档
- 🧪 可以直接在线测试 API
- 📝 请求/响应的数据结构

**更新 Swagger 文档**（修改 API 注释后）：

```bash
make swagger
```

---

### 2. 运行 Repository 测试

验证数据访问层的测试：

```bash
# 运行所有测试
make test

# 只运行 Repository 测试
go test -v ./internal/repository/...

# 查看测试覆盖率
make test-coverage
```

测试使用 SQLite 内存数据库，无需配置 PostgreSQL。

---

### 3. 使用验证中间件

简化您的 Handler 代码！

**步骤 1**: 在路由中使用中间件

```go
// internal/api/router/router.go
import "github.com/d60-Lab/gin-template/internal/api/middleware"

router.POST("/users",
    middleware.ValidateJSON(&dto.CreateUserRequest{}),  // 添加验证中间件
    handler.CreateUser)
```

**步骤 2**: 在 Handler 中获取已验证的对象

```go
// internal/api/handler/user_handler.go
func (h *Handler) CreateUser(c *gin.Context) {
    // 不再需要手动验证！
    req, _ := middleware.GetValidatedRequest(c)
    userReq := req.(*dto.CreateUserRequest)

    // 直接使用已验证的数据
    user, err := h.service.Create(c.Request.Context(), userReq)
    // ...
}
```

**对比效果**：

- ❌ 之前：每个 Handler 都要写 `ShouldBindJSON` 和错误处理（5-8 行代码）
- ✅ 现在：在路由配置一次，Handler 直接获取（1 行代码）

---

### 4. 启用 Pprof 性能分析

**步骤 1**: 编辑 `config/config.yaml`

```yaml
pprof:
  enabled: true  # 改为 true
```

**步骤 2**: 启动应用

```bash
make run
```

**步骤 3**: 访问性能分析页面

```bash
# 浏览器访问
http://localhost:8080/debug/pprof/

# 或使用命令行工具
go tool pprof http://localhost:8080/debug/pprof/heap
```

**快速分析命令**：

```bash
# CPU 分析（30 秒）
go tool pprof -http=:8081 http://localhost:8080/debug/pprof/profile?seconds=30

# 内存分析
go tool pprof -http=:8081 http://localhost:8080/debug/pprof/heap

# Goroutine 分析
go tool pprof -http=:8081 http://localhost:8080/debug/pprof/goroutine
```

⚠️ **注意**：生产环境建议关闭或通过环境变量动态控制！

---

### 5. 配置 Sentry 错误追踪

**步骤 1**: 注册 Sentry 账号

访问 [sentry.io](https://sentry.io) 并创建项目，获取 DSN。

**步骤 2**: 配置 DSN

```yaml
# config/config.yaml
sentry:
  enabled: true
  dsn: "https://your-key@o123456.ingest.sentry.io/789"  # 替换为您的 DSN
  environment: development
  traces_sample_rate: 1.0
  debug: true
```

或使用环境变量：

```bash
export SENTRY_DSN="https://your-key@o123456.ingest.sentry.io/789"
export SENTRY_ENVIRONMENT="development"
```

**步骤 3**: 启动应用并测试

```bash
make run
```

触发一个错误（如访问不存在的接口），然后在 Sentry 控制台查看错误报告。

**手动发送错误**：

```go
import "github.com/getsentry/sentry-go"

if err != nil {
    sentry.CaptureException(err)
}
```

---

### 6. 启用 OpenTelemetry 追踪

**步骤 1**: 启动 Jaeger（使用 Docker）

```bash
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 14268:14268 \
  jaegertracing/all-in-one:latest
```

**步骤 2**: 配置追踪

```yaml
# config/config.yaml
tracing:
  enabled: true
  service_name: gin-template
  jaeger_endpoint: http://localhost:14268/api/traces
```

**步骤 3**: 启动应用

```bash
make run
```

**步骤 4**: 访问 Jaeger UI

```
http://localhost:16686
```

**步骤 5**: 测试追踪

发送几个 API 请求，然后在 Jaeger UI 中：

1. 选择 Service: `gin-template`
2. 点击 "Find Traces"
3. 查看请求的完整链路和耗时

---

## 📊 功能优先级建议

### 开发阶段（必用）

1. ✅ **Swagger 文档** - 必须使用，便于 API 开发和调试
2. ✅ **Repository 测试** - 必须使用，保证数据层质量
3. ✅ **验证中间件** - 推荐使用，减少重复代码

### 性能调优阶段

4. ✅ **Pprof** - 按需使用，发现性能瓶颈

### 生产环境

5. ✅ **Sentry** - 强烈推荐，监控线上错误
6. ✅ **OpenTelemetry** - 推荐使用，追踪分布式调用

---

## 🎯 常见场景

### 场景 1: 我只想看 API 文档

```bash
make run
# 访问 http://localhost:8080/swagger/index.html
```

### 场景 2: 我想测试数据库操作

```bash
go test -v ./internal/repository/...
```

### 场景 3: 我想分析程序性能

```yaml
# config/config.yaml
pprof:
  enabled: true
```

```bash
make run
go tool pprof -http=:8081 http://localhost:8080/debug/pprof/heap
```

### 场景 4: 我想监控生产环境错误

```yaml
# config/config.yaml
sentry:
  enabled: true
  dsn: "your-sentry-dsn"
  environment: production
  traces_sample_rate: 0.1  # 降低采样率
```

### 场景 5: 我想追踪微服务调用链

```bash
# 启动 Jaeger
docker run -d --name jaeger -p 16686:16686 -p 14268:14268 jaegertracing/all-in-one:latest
```

```yaml
# config/config.yaml
tracing:
  enabled: true
  service_name: my-service
```

---

## 🔧 故障排查

### Swagger 文档不显示

```bash
# 重新生成文档
make swagger

# 确保引入了 swagger 包
# cmd/server/main.go 应该有：
import _ "github.com/d60-Lab/gin-template/docs"
```

### 测试失败

```bash
# 清理缓存重试
go clean -testcache
go test -v ./internal/repository/...
```

### Pprof 访问 404

```yaml
# 确保 config/config.yaml 中启用了 pprof
pprof:
  enabled: true
```

### Sentry 不工作

1. 检查 DSN 是否正确
2. 检查网络连接
3. 启用 debug 模式：

```yaml
sentry:
  debug: true
```

### Jaeger 看不到追踪数据

1. 确保 Jaeger 已启动：`docker ps | grep jaeger`
2. 检查配置中的 endpoint 是否正确
3. 确保应用启动时没有错误日志

---

## 📖 深入学习

想了解更多？查看详细文档：

- **完整功能说明**: [docs/FEATURES.md](./FEATURES.md)
- **API 文档**: 启动应用后访问 `/swagger/index.html`
- **更新日志**: [CHANGELOG.md](../CHANGELOG.md)
- **项目主页**: [README.md](../README.md)

---

## 💡 提示

1. **开发时**：启用 Swagger + Pprof + OpenTelemetry
2. **测试时**：运行所有测试，启用 Sentry 收集测试环境错误
3. **生产时**：必须启用 Sentry，推荐启用 OpenTelemetry，Pprof 按需启用

---

## ❓ 需要帮助？

- 📝 提交 Issue
- 💬 查看 FAQ
- 📚 阅读详细文档

祝您使用愉快！🎉
