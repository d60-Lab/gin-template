# 快速开始指南

本指南将帮助你快速启动和运行这个 Gin 项目模板。

## 准备工作

### 1. 安装 PostgreSQL

**macOS:**
```bash
brew install postgresql@15
brew services start postgresql@15
```

**Ubuntu/Debian:**
```bash
sudo apt install postgresql-15
sudo systemctl start postgresql
```

### 2. 创建数据库

```bash
# 使用 Makefile
make init-db

# 或手动创建
createdb gin_template
```

### 3. 配置项目

复制环境变量示例文件：
```bash
cp .env.example .env
```

修改 `config/config.yaml` 或设置环境变量。

## 启动项目

### 方式一：直接运行

```bash
# 下载依赖
go mod tidy

# 运行项目
make run
# 或
go run cmd/server/main.go
```

### 方式二：使用热重载（推荐开发使用）

```bash
# 安装 Air
go install github.com/cosmtrek/air@latest

# 运行
air
# 或
make dev
```

### 方式三：使用 Docker Compose（最简单）

```bash
docker-compose up
```

这将自动启动：
- Web 应用（http://localhost:8080）
- PostgreSQL 数据库
- Redis 缓存

## 测试 API

### 1. 健康检查

```bash
curl http://localhost:8080/health
```

### 2. 注册用户

```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "age": 25
  }'
```

### 3. 登录

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

保存返回的 token，后续请求需要使用。

### 4. 获取用户列表

```bash
curl http://localhost:8080/api/v1/users?page=1&page_size=10
```

### 5. 获取用户详情

```bash
curl http://localhost:8080/api/v1/users/{user_id}
```

### 6. 更新用户（需要认证）

```bash
curl -X PUT http://localhost:8080/api/v1/users/{user_id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {your_token}" \
  -d '{
    "username": "newusername"
  }'
```

## 开发建议

### 添加新功能

1. **定义模型** - 在 `internal/model` 中创建数据模型
2. **定义 DTO** - 在 `internal/dto` 中创建请求/响应 DTO
3. **实现 Repository** - 在 `internal/repository` 中实现数据访问
4. **实现 Service** - 在 `internal/service` 中实现业务逻辑
5. **实现 Handler** - 在 `internal/api/handler` 中实现 HTTP 处理器
6. **注册路由** - 在 `internal/api/router` 中注册路由

### 代码质量

```bash
# 格式化代码
make fmt

# 运行测试
make test

# 生成测试覆盖率
make test-coverage

# 代码检查（需要先安装 golangci-lint）
make install-tools
make lint
```

### 构建部署

```bash
# 本地构建
make build

# 构建 Docker 镜像
make docker-build

# 运行 Docker 容器
make docker-run
```

## 常见问题

### Q: 如何修改端口？

A: 修改 `config/config.yaml` 中的 `server.port` 配置。

### Q: 如何切换到生产模式？

A: 修改 `config/config.yaml` 中的 `server.mode` 为 `release`。

### Q: 如何添加更多中间件？

A: 在 `internal/api/router/router.go` 中使用 `r.Use()` 添加全局中间件，或在路由组中添加特定中间件。

### Q: 数据库连接失败？

A: 检查 `config/config.yaml` 中的数据库配置是否正确，确保 PostgreSQL 服务正在运行。

## 下一步

- 查看 [README.md](README.md) 了解完整文档
- 查看 [blog.md](blog.md) 了解最佳实践详解
- 开始基于此模板构建你的应用！

## 需要帮助？

如果遇到问题，请：
1. 检查日志输出
2. 查看 [Gin 文档](https://gin-gonic.com/)
3. 提交 Issue
