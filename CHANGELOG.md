# Changelog

所有重要的项目更改都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
并且此项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增功能 (2024-11-05)

#### 🎯 第一批：核心功能（上午）

#### 📚 Swagger API 文档

- ✅ 为所有 API 端点添加 Swagger 注释
- ✅ 自动生成交互式 API 文档界面
- ✅ 访问地址：`http://localhost:8080/swagger/index.html`
- ✅ 添加 `make swagger` 命令用于生成文档
- 相关文件：`docs/docs.go`, `docs/swagger.json`, `internal/api/handler/user_handler.go`

#### 🧪 Repository 单元测试

- ✅ 为 Repository 层添加完整的单元测试
- ✅ 使用 SQLite 内存数据库进行测试
- ✅ 采用 testify/suite 测试框架
- ✅ 测试覆盖所有 CRUD 操作和边界情况（8 个测试用例）
- 相关文件：`internal/repository/user_repository_test.go`

#### 🧹 通用验证中间件

- ✅ 实现通用的 JSON 验证中间件
- ✅ 简化 Handler 中的参数验证代码
- ✅ 统一错误处理和响应格式
- ✅ 提供 `ValidateJSON()` 和 `GetValidatedRequest()` 辅助函数
- 相关文件：`internal/api/middleware/validate.go`

#### 📈 Pprof 性能分析

- ✅ 集成 Go pprof 性能分析工具
- ✅ 支持 CPU、内存、Goroutine 等性能分析
- ✅ 通过配置文件控制开启/关闭
- ✅ 提供 11 个标准分析端点（/debug/pprof/*）
- 相关文件：`internal/api/middleware/pprof.go`

#### 🔍 Sentry 错误追踪

- ✅ 集成 Sentry 错误监控服务
- ✅ 自动捕获 Panic 和错误
- ✅ 记录请求上下文信息
- ✅ 支持性能追踪和采样率配置
- 相关文件：`internal/api/middleware/sentry.go`, `cmd/server/main.go`

#### 🔗 OpenTelemetry 分布式追踪

- ✅ 集成 OpenTelemetry 分布式追踪
- ✅ 支持 Jaeger 作为后端
- ✅ 自动追踪 HTTP 请求
- ✅ 可自定义 Span 和属性
- 相关文件：`internal/api/middleware/tracing.go`, `cmd/server/main.go`

#### 🎯 第二批：开发工具（下午）

#### 🧪 REST Client API 测试

- ✅ 添加 `api-tests.http` 文件
- ✅ 包含所有 API 端点的测试用例
- ✅ 支持变量定义和响应数据提取
- ✅ 覆盖正常流程和错误场景
- ✅ 可在 VS Code 中直接运行

#### 🎣 Pre-commit Hooks

- ✅ 配置 `.pre-commit-config.yaml`
- ✅ 集成多种代码检查工具：
  - Go fmt, imports, vet
  - golangci-lint
  - YAML/JSON/TOML 语法检查
  - Markdown lint
  - Conventional Commits 检查
  - 密钥检测
- ✅ 提交前自动运行所有检查

#### 📏 golangci-lint 配置

- ✅ 完善的 `.golangci.yml` 配置
- ✅ 启用 20+ 个 linters
- ✅ 自定义规则和排除项
- ✅ 针对测试文件的特殊配置

#### ⚙️ EditorConfig

- ✅ 添加 `.editorconfig` 文件
- ✅ 统一不同编辑器的代码风格
- ✅ 覆盖 Go, YAML, JSON, Markdown 等文件

#### 💻 VS Code 配置

- ✅ Workspace 设置（`.vscode/settings.json`）
- ✅ 推荐扩展列表（`.vscode/extensions.json`）
- ✅ 自动格式化和 lint 配置
- ✅ Go 开发最佳配置

#### 🤖 GitHub Actions CI/CD

- ✅ CI 工作流（`.github/workflows/ci.yml`）
  - 代码检查（golangci-lint）
  - 单元测试和覆盖率
  - 编译构建
  - Docker 镜像构建
  - 安全扫描（Gosec + Trivy）
- ✅ Release 工作流（`.github/workflows/release.yml`）
  - 多平台二进制构建
  - GitHub Release 创建
  - Docker 多架构镜像推送

### 变更

- **README.md**: 添加开发工具部分，新增文档链接
- **Makefile**: 新增命令：
  - `make lint-fix` - 自动修复 lint 问题
  - `make pre-commit` - 运行 pre-commit 检查
  - `make pre-commit-install` - 安装 pre-commit hooks
  - `make ci` - 运行完整 CI 流程
  - `make verify` - 提交前验证
- **internal/api/router/router.go**: 添加 Swagger UI 路由，条件性启用高级中间件
- **cmd/server/main.go**: 添加 Sentry 和 OpenTelemetry 初始化逻辑
- **config/config.go**: 新增 `PprofConfig`、`SentryConfig`、`TracingConfig` 结构

### 文档

- ✅ 新增 `docs/FEATURES.md` - 高级功能使用指南（6 大功能详细说明）
- ✅ 新增 `docs/DEV_TOOLS.md` - 开发工具配置指南
- ✅ 更新 `README.md` - 添加开发工具部分
- ✅ 更新 `CHANGELOG.md` - 详细记录所有变更

### 新增依赖

```go
// 高级功能
github.com/getsentry/sentry-go v0.27.0
github.com/swaggo/swag v1.16.3
github.com/swaggo/gin-swagger v1.6.0
go.opentelemetry.io/otel v1.24.0
go.opentelemetry.io/otel/exporters/jaeger v1.17.0
go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin v0.49.0
gorm.io/driver/sqlite v1.5.4
github.com/stretchr/testify v1.8.4
```

### 计划添加

- [ ] Redis 缓存集成示例
- [ ] 更多示例模块（文章、评论等）
- [ ] GraphQL 支持
- [ ] WebSocket 支持
- [ ] 国际化 (i18n) 支持
- [ ] Swagger 文档自动生成
- [ ] 集成测试框架
- [ ] CI/CD 配置示例

## [1.0.0] - 2024-01-01

### 新增

#### 项目结构

- ✅ 创建 DDD 风格的项目结构
- ✅ 命令行入口 (cmd/server)
- ✅ 内部应用代码 (internal)
- ✅ 可复用公共库 (pkg)
- ✅ 配置管理 (config)
- ✅ 文档目录 (docs)

#### 核心功能

- ✅ 统一的响应格式处理
- ✅ 结构化日志 (Zap)
- ✅ JWT 认证和授权
- ✅ 自定义验证器
- ✅ 数据库集成 (GORM + PostgreSQL)

#### 中间件

- ✅ CORS 中间件
- ✅ 安全响应头中间件
- ✅ 请求日志中间件
- ✅ Panic 恢复中间件
- ✅ JWT 认证中间件
- ✅ 限流中间件
- ✅ Gzip 压缩中间件

#### 示例模块

- ✅ 用户模块完整实现
  - 用户注册
  - 用户登录
  - 获取用户信息
  - 更新用户信息
  - 删除用户
  - 用户列表（分页）

#### 开发工具

- ✅ Makefile 命令集
- ✅ Docker 支持
- ✅ Docker Compose 配置
- ✅ Air 热重载配置
- ✅ 环境变量示例

#### 测试

- ✅ Handler 层单元测试示例
- ✅ Mock 服务示例

#### 文档

- ✅ README 完整说明
- ✅ API 接口文档
- ✅ 快速开始指南
- ✅ 架构设计文档
- ✅ 最佳实践博客

#### 配置

- ✅ YAML 配置文件
- ✅ 环境变量支持
- ✅ Viper 配置管理

#### 数据库

- ✅ 连接池配置
- ✅ 自动迁移
- ✅ 初始化 SQL 脚本

#### 安全

- ✅ 密码加密 (bcrypt)
- ✅ JWT Token 生成和验证
- ✅ CORS 配置
- ✅ 安全响应头
- ✅ 参数验证

#### 性能优化

- ✅ HTTP 压缩 (Gzip)
- ✅ 数据库连接池
- ✅ 请求限流

### 技术栈

| 技术 | 版本 |
|------|------|
| Go | 1.21+ |
| Gin | 1.9.1 |
| GORM | 1.25.5 |
| Zap | 1.26.0 |
| Viper | 1.18.2 |
| golang-jwt | 5.2.0 |
| validator | 10.16.0 |
| PostgreSQL | 15+ |

### 文件统计

- Go 文件: 19 个
- 中间件: 5 个
- Handler: 1 个
- Service: 1 个
- Repository: 1 个
- 工具包: 5 个
- 文档: 4 个

### 代码行数

```bash
# 统计 Go 代码行数
find . -name "*.go" -not -path "./vendor/*" | xargs wc -l
```

### 特性亮点

🎯 **分层清晰** - 采用 DDD 分层架构，职责明确
🔐 **安全可靠** - JWT 认证、密码加密、安全中间件
📝 **文档完善** - 包含 API 文档、快速开始、架构设计
🧪 **可测试性** - 依赖注入、接口抽象、测试示例
🐳 **容器化** - 完整的 Docker 支持
🔥 **开发友好** - 热重载、Makefile、详细注释
⚡ **性能优化** - 压缩、连接池、限流
🛡️ **生产就绪** - 优雅关闭、错误处理、日志记录

## 维护者

- [@bjmayor](https://github.com/bjmayor)

## 贡献者

感谢所有为此项目做出贡献的开发者！

## 版本说明

- **主版本号 (Major)**: 不兼容的 API 变更
- **次版本号 (Minor)**: 向下兼容的功能新增
- **修订号 (Patch)**: 向下兼容的问题修正

## 获取更新

```bash
# 查看所有标签
git tag

# 切换到特定版本
git checkout v1.0.0

# 拉取最新代码
git pull origin main
```

## 反馈

如有问题或建议，请：

1. 提交 [Issue](https://github.com/d60-Lab/gin-template/issues)
2. 发起 [Pull Request](https://github.com/d60-Lab/gin-template/pulls)
3. 参与 [Discussions](https://github.com/d60-Lab/gin-template/discussions)

---

**说明**:

- 日期格式: YYYY-MM-DD
- 类型: 新增 (Added) | 变更 (Changed) | 废弃 (Deprecated) | 移除 (Removed) | 修复 (Fixed) | 安全 (Security)
