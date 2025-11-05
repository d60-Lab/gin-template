# 项目概览

## 📁 项目结构

```
gin-template/
├── 📁 cmd/                          # 应用程序入口
│   └── 📁 server/
│       └── main.go                  # 主程序入口，依赖注入和优雅关闭
│
├── 📁 internal/                     # 私有应用代码
│   ├── 📁 api/                      # API 层
│   │   ├── 📁 handler/              # HTTP 请求处理器
│   │   │   ├── user_handler.go      # 用户相关接口实现
│   │   │   └── user_handler_test.go # 单元测试示例
│   │   ├── 📁 middleware/           # 中间件
│   │   │   ├── auth.go              # JWT 认证中间件
│   │   │   ├── cors.go              # CORS 和安全头中间件
│   │   │   ├── logger.go            # 请求日志中间件
│   │   │   ├── ratelimit.go         # 限流中间件
│   │   │   └── recovery.go          # Panic 恢复中间件
│   │   └── 📁 router/               # 路由配置
│   │       └── router.go            # 路由注册和分组
│   │
│   ├── 📁 service/                  # 业务逻辑层
│   │   └── user_service.go          # 用户业务逻辑
│   │
│   ├── 📁 repository/               # 数据访问层
│   │   └── user_repository.go       # 用户数据访问
│   │
│   ├── 📁 model/                    # 数据模型
│   │   └── user.go                  # 用户实体模型
│   │
│   └── 📁 dto/                      # 数据传输对象
│       └── user.go                  # 用户 DTO（请求/响应）
│
├── 📁 pkg/                          # 可复用的公共库
│   ├── 📁 database/                 # 数据库工具
│   │   └── database.go              # 数据库初始化和连接池
│   ├── 📁 jwt/                      # JWT 工具
│   │   └── jwt.go                   # Token 生成和解析
│   ├── 📁 logger/                   # 日志工具
│   │   └── logger.go                # 结构化日志（zap）
│   ├── 📁 response/                 # 响应工具
│   │   └── response.go              # 统一响应格式
│   └── 📁 validator/                # 验证器
│       └── validator.go             # 自定义验证规则
│
├── 📁 config/                       # 配置文件
│   ├── config.go                    # 配置结构和加载
│   └── config.yaml                  # 配置文件（YAML）
│
├── 📁 migrations/                   # 数据库迁移
│   └── init.sql                     # 初始化 SQL
│
├── 📁 docs/                         # 文档
│   ├── API.md                       # API 接口文档
│   └── QUICKSTART.md                # 快速开始指南
│
├── 📄 .air.toml                     # Air 热重载配置
├── 📄 .env.example                  # 环境变量示例
├── 📄 .gitignore                    # Git 忽略文件
├── 📄 Dockerfile                    # Docker 镜像构建
├── 📄 docker-compose.yml            # Docker Compose 配置
├── 📄 go.mod                        # Go 模块依赖
├── 📄 go.sum                        # 依赖校验
├── 📄 LICENSE                       # MIT 许可证
├── 📄 Makefile                      # Make 命令
├── 📄 README.md                     # 项目说明
└── 📄 blog.md                       # 最佳实践博客

```

## 🎯 核心功能

### 1. 分层架构 (DDD)

```
请求流程: HTTP Request → Handler → Service → Repository → Database
响应流程: Database → Repository → Service → Handler → HTTP Response
```

- **Handler 层**: 处理 HTTP 请求，参数验证，调用 Service
- **Service 层**: 业务逻辑，事务处理，调用 Repository
- **Repository 层**: 数据访问，数据库操作
- **Model 层**: 数据实体定义
- **DTO 层**: 请求/响应数据传输对象

### 2. 中间件栈

```
请求 → CORS → 安全头 → 日志 → 恢复 → Gzip → [认证] → [限流] → 处理器
```

### 3. 认证流程

```
1. 用户注册 → 密码加密（bcrypt）→ 存储
2. 用户登录 → 验证密码 → 生成 JWT Token
3. 访问受保护资源 → 验证 Token → 获取用户信息 → 授权检查
```

## 🛠️ 技术栈

| 类别 | 技术 | 用途 |
|------|------|------|
| Web 框架 | Gin | HTTP 路由和中间件 |
| ORM | GORM | 数据库操作 |
| 日志 | Zap | 结构化日志 |
| 配置 | Viper | 配置管理 |
| 认证 | golang-jwt | JWT Token |
| 验证 | validator | 参数验证 |
| 压缩 | gzip | HTTP 响应压缩 |
| 限流 | golang.org/x/time/rate | 请求限流 |
| 加密 | bcrypt | 密码加密 |
| 数据库 | PostgreSQL | 主数据库 |
| 缓存 | Redis | 可选缓存 |
| 容器 | Docker | 容器化部署 |

## 📊 数据流图

### 用户注册流程

```
Client → POST /api/v1/users
  ↓
Handler.CreateUser (参数验证)
  ↓
Service.Create (业务逻辑，检查重复，加密密码)
  ↓
Repository.Create (数据库插入)
  ↓
Response (返回用户信息)
```

### 用户认证流程

```
Client → POST /api/v1/auth/login
  ↓
Handler.Login (参数验证)
  ↓
Service.Login (验证密码，生成 Token)
  ↓
Repository.GetByUsername (查询用户)
  ↓
Response (返回 Token)
```

### 受保护资源访问流程

```
Client → PUT /api/v1/users/:id (带 Token)
  ↓
Middleware.Auth (验证 Token，提取用户信息)
  ↓
Handler.UpdateUser (处理更新)
  ↓
Service.Update (业务逻辑)
  ↓
Repository.Update (数据库更新)
  ↓
Response (返回更新后的用户信息)
```

## 🔧 配置项

### 服务器配置

```yaml
server:
  port: 8080              # 监听端口
  mode: debug             # 运行模式: debug/release/test
  read_timeout: 60        # 读超时（秒）
  write_timeout: 60       # 写超时（秒）
```

### 数据库配置

```yaml
database:
  driver: postgres        # 数据库驱动
  host: localhost         # 主机
  port: 5432             # 端口
  database: gin_template  # 数据库名
  username: postgres      # 用户名
  password: postgres      # 密码
  max_open_conns: 25     # 最大连接数
  max_idle_conns: 10     # 最大空闲连接
  conn_max_lifetime: 300 # 连接最大生命周期（秒）
```

### JWT 配置

```yaml
jwt:
  secret: your-secret-key # JWT 密钥
  expire: 86400          # 过期时间（秒）
```

## 🚀 部署方式

### 1. 本地开发

```bash
# 安装依赖
go mod tidy

# 运行项目
make run

# 或使用热重载
air
```

### 2. Docker 部署

```bash
# 构建镜像
docker build -t gin-template:latest .

# 运行容器
docker run -p 8080:8080 gin-template:latest
```

### 3. Docker Compose 部署

```bash
# 启动所有服务
docker-compose up -d

# 包括：
# - Web 应用（端口 8080）
# - PostgreSQL（端口 5432）
# - Redis（端口 6379）
```

## 📝 开发规范

### 命名规范

- **包名**: 小写，简短，无下划线
- **文件名**: 小写，下划线分隔
- **变量名**: 驼峰命名
- **常量名**: 大写，下划线分隔
- **接口名**: 名词，大写开头
- **函数名**: 动词开头，大写开头

### 错误处理

```go
// 定义业务错误
var (
    ErrUserExists = errors.New("user already exists")
    ErrUserNotFound = errors.New("user not found")
)

// 在 Service 层返回业务错误
if user != nil {
    return nil, ErrUserExists
}

// 在 Handler 层处理错误
if err == service.ErrUserExists {
    response.BadRequest(c, "user already exists")
    return
}
```

### 日志记录

```go
// 使用结构化日志
logger.Info("user created",
    zap.String("userID", user.ID),
    zap.String("username", user.Username),
)

logger.Error("failed to create user",
    zap.Error(err),
    zap.String("username", req.Username),
)
```

## 🧪 测试

### 单元测试

```bash
# 运行所有测试
make test

# 生成覆盖率报告
make test-coverage
```

### API 测试

```bash
# 使用 cURL
curl http://localhost:8080/health

# 使用 Postman 或其他工具
# 参考 docs/API.md
```

## 📈 性能优化

1. **数据库连接池**: 合理配置 max_open_conns 和 max_idle_conns
2. **Gzip 压缩**: 启用 HTTP 响应压缩
3. **请求限流**: 防止过载
4. **缓存**: 可选的 Redis 缓存支持
5. **索引优化**: 数据库表添加适当索引

## 🔒 安全实践

1. **密码加密**: 使用 bcrypt 加密存储
2. **JWT 认证**: 无状态认证
3. **CORS 配置**: 跨域资源共享
4. **安全响应头**: X-Frame-Options, X-XSS-Protection 等
5. **SQL 注入防护**: 使用参数化查询
6. **限流保护**: 防止 DDoS 攻击

## 📚 延伸阅读

- [Gin 官方文档](https://gin-gonic.com/)
- [GORM 官方文档](https://gorm.io/)
- [Go 语言最佳实践](https://golang.org/doc/effective_go.html)
- [12-Factor App](https://12factor.net/)
- [RESTful API 设计指南](https://restfulapi.net/)

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件
