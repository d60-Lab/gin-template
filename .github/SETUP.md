# 🚀 使用此模板创建新项目

## 方式一：GitHub 网页操作（推荐）

### 1. 点击 "Use this template" 按钮

在 GitHub 仓库页面右上角，点击绿色的 **"Use this template"** 按钮，然后选择 **"Create a new repository"**。

### 2. 填写新项目信息

- **Repository name**: 你的新项目名称
- **Description**: 项目描述（可选）
- **Public/Private**: 选择公开或私有
- 点击 **"Create repository"**

### 3. 克隆新项目到本地

```bash
git clone https://github.com/your-username/your-new-project.git
cd your-new-project
```

### 4. 运行初始化脚本

```bash
# 自动替换项目信息
./scripts/init-project.sh your-new-project github.com/your-username/your-new-project

# 或者手动替换
go mod init github.com/your-username/your-new-project
# 然后批量替换代码中的导入路径
```

### 5. 安装依赖

```bash
go mod tidy
make install-tools
```

### 6. 生成 Swagger 文档

```bash
make swagger
```

### 7. 配置数据库

编辑 `config/config.yaml`，配置数据库连接信息。

### 8. 运行项目

```bash
make run
# 访问 http://localhost:8080/swagger/index.html
```

完成！🎉

---

## 方式二：命令行操作

### 使用 gh CLI（GitHub 官方命令行工具）

```bash
# 1. 从模板创建新仓库
gh repo create your-new-project --template d60-Lab/gin-template --public

# 2. 克隆到本地
gh repo clone your-username/your-new-project
cd your-new-project

# 3. 初始化项目
./scripts/init-project.sh your-new-project github.com/your-username/your-new-project

# 4. 安装依赖并运行
go mod tidy
make install-tools
make swagger
make run
```

---

## 初始化脚本说明

`scripts/init-project.sh` 脚本会自动完成以下操作：

1. ✅ 替换 `go.mod` 中的模块路径
2. ✅ 更新所有 Go 文件中的导入路径
3. ✅ 更新 Swagger 文档中的包路径
4. ✅ 更新 README.md 中的项目信息
5. ✅ 删除模板相关的文件（如本文件）
6. ✅ 初始化 Git 提交

### 脚本用法

```bash
./scripts/init-project.sh <project-name> <module-path>
```

**参数说明：**

- `<project-name>`: 你的项目名称（用于文档）
- `<module-path>`: Go 模块路径（如 `github.com/username/project`）

**示例：**

```bash
./scripts/init-project.sh my-api github.com/mycompany/my-api
```

---

## 配置检查清单

完成初始化后，检查以下配置：

- [ ] 数据库连接信息（`config/config.yaml`）
- [ ] JWT 密钥（建议使用环境变量）
- [ ] Redis 配置（如果使用）
- [ ] Sentry DSN（如果启用错误追踪）
- [ ] Jaeger endpoint（如果启用分布式追踪）

---

## 可选功能配置

### Swagger 文档

- 访问地址：`http://localhost:8080/swagger/index.html`
- 更新文档：`make swagger`

### Pprof 性能分析

```yaml
# config/config.yaml
pprof:
  enabled: true
```

访问：`http://localhost:8080/debug/pprof/`

### Sentry 错误追踪

```yaml
# config/config.yaml
sentry:
  enabled: true
  dsn: "your-sentry-dsn"
  environment: production
```

### OpenTelemetry 追踪

```bash
# 启动 Jaeger
docker run -d -p 16686:16686 -p 14268:14268 jaegertracing/all-in-one:latest
```

```yaml
# config/config.yaml
tracing:
  enabled: true
  service_name: your-service-name
  jaeger_endpoint: http://localhost:14268/api/traces
```

---

## 需要帮助？

- 📖 [完整文档](../README.md)
- 🚀 [快速开始](../docs/QUICKSTART_FEATURES.md)
- 📚 [功能指南](../docs/FEATURES.md)
- 📝 [更新日志](../CHANGELOG.md)

---

## 下一步

1. 阅读 [docs/FEATURES.md](../docs/FEATURES.md) 了解所有功能
2. 根据需求启用/禁用可选功能
3. 添加你的业务逻辑
4. 编写测试用例
5. 配置 CI/CD

祝开发顺利！🚀
