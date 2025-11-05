# 开发工具配置指南

本文档介绍项目中各种开发工具的配置和使用方法。

## 📋 目录

1. [REST Client 测试](#1-rest-client-测试)
2. [Pre-commit Hooks](#2-pre-commit-hooks)
3. [golangci-lint 代码检查](#3-golangci-lint-代码检查)
4. [EditorConfig 编辑器配置](#4-editorconfig-编辑器配置)
5. [VS Code 配置](#5-vs-code-配置)
6. [GitHub Actions CI/CD](#6-github-actions-cicd)

---

## 1. REST Client 测试

### 安装 VS Code 扩展

在 VS Code 中安装 **REST Client** 扩展：

```
扩展 ID: humao.rest-client
```

或者打开 VS Code，按 `Cmd+Shift+P`，输入 "Extensions: Install Extensions"，搜索 "REST Client"。

### 使用方法

1. 打开 `api-tests.http` 文件
2. 点击请求上方的 **"Send Request"** 按钮
3. 查看右侧面板的响应结果

### 功能特性

- ✅ 支持变量定义和引用
- ✅ 自动从响应中提取数据
- ✅ 支持环境变量
- ✅ 语法高亮
- ✅ 响应格式化

### 示例

```http
### 定义变量
@baseUrl = http://localhost:8080

### 发送请求
GET {{baseUrl}}/api/v1/users
Accept: application/json

### 使用上一个请求的响应
# @name login
POST {{baseUrl}}/api/v1/auth/login

### 引用响应数据
@token = {{login.response.body.data.token}}

GET {{baseUrl}}/api/v1/users/1
Authorization: Bearer {{token}}
```

---

## 2. Pre-commit Hooks

### 安装

```bash
# 使用 pip 安装
pip install pre-commit

# 或使用 brew（macOS）
brew install pre-commit

# 或使用 apt（Ubuntu/Debian）
sudo apt-get install pre-commit
```

### 初始化

在项目根目录运行：

```bash
pre-commit install
```

这会在 `.git/hooks/` 目录下创建 pre-commit hook。

### 使用

配置完成后，每次提交代码时都会自动运行检查：

```bash
git commit -m "your commit message"
```

### 手动运行

```bash
# 检查所有文件
pre-commit run --all-files

# 只检查暂存的文件
pre-commit run

# 跳过 pre-commit 检查（不推荐）
git commit --no-verify -m "message"
```

### 包含的检查项

1. **Go 检查**
   - `go fmt` - 代码格式化
   - `go imports` - import 整理
   - `go vet` - 静态分析
   - `go test` - 单元测试
   - `go build` - 编译检查
   - `go mod tidy` - 依赖整理

2. **golangci-lint** - 全面的 lint 检查

3. **通用检查**
   - 文件尾部空行
   - 删除尾部空格
   - 检查合并冲突
   - 检查大文件
   - YAML/JSON/TOML 语法检查

4. **Markdown 检查** - Markdown 格式检查

5. **Commit 消息检查** - 遵循 Conventional Commits 规范

6. **密钥检测** - 防止密钥泄露

### 更新 hooks

```bash
pre-commit autoupdate
```

---

## 3. golangci-lint 代码检查

### 安装

```bash
# 使用 brew（macOS）
brew install golangci-lint

# 使用脚本（Linux/macOS）
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

# 或使用 Makefile
make install-tools
```

### 使用

```bash
# 运行 lint
golangci-lint run

# 自动修复问题
golangci-lint run --fix

# 只检查新代码
golangci-lint run --new

# 使用 Makefile
make lint
```

### 启用的 Linters

配置文件 `.golangci.yml` 启用了以下检查：

- **错误检查**: errcheck, gosec
- **代码质量**: gocyclo, revive, misspell
- **性能**: prealloc
- **风格**: stylecheck, whitespace
- **Bug 检测**: bodyclose, noctx, rowserrcheck

### 自定义配置

编辑 `.golangci.yml` 文件来调整规则。

---

## 4. EditorConfig 编辑器配置

### 自动支持

大多数现代编辑器都内置支持 EditorConfig：

- VS Code（需要安装扩展）
- JetBrains IDEs（IntelliJ, GoLand）
- Sublime Text
- Atom

### VS Code 安装

安装 **EditorConfig for VS Code** 扩展：

```
扩展 ID: editorconfig.editorconfig
```

### 配置说明

`.editorconfig` 文件定义了：

- **字符编码**: UTF-8
- **换行符**: LF
- **Go 文件**: Tab 缩进，宽度 4
- **YAML/JSON**: 空格缩进，宽度 2
- **自动处理**: 删除尾部空格，添加文件尾空行

---

## 5. VS Code 配置

### 推荐扩展

打开项目后，VS Code 会自动提示安装推荐的扩展（定义在 `.vscode/extensions.json`）：

#### 必备扩展

- **Go** (golang.go) - Go 语言支持
- **REST Client** (humao.rest-client) - API 测试
- **Docker** (ms-azuretools.vscode-docker) - Docker 支持

#### 推荐扩展

- **GitLens** - Git 增强
- **YAML** - YAML 语法支持
- **Markdown All in One** - Markdown 增强
- **EditorConfig** - 编辑器配置

### Workspace 设置

`.vscode/settings.json` 配置了：

1. **Go 开发**
   - 使用 golangci-lint 进行检查
   - 保存时自动格式化
   - 自动整理 imports
   - 启用测试覆盖率

2. **编辑器**
   - 显示标尺线（80, 120）
   - 自动删除尾部空格
   - 保存时格式化

3. **REST Client**
   - 在新标签页预览响应
   - 自动跟随重定向

### 快捷键

- `Cmd+Shift+P` - 命令面板
- `Cmd+P` - 快速打开文件
- `Cmd+Shift+T` - 重新打开关闭的文件
- `F5` - 调试
- `Ctrl+`` ` - 切换终端

---

## 6. GitHub Actions CI/CD

### CI 工作流

`.github/workflows/ci.yml` 定义了持续集成流程：

#### 触发条件

- Push 到 main 或 develop 分支
- 提交 Pull Request

#### Jobs

1. **Lint** - 代码检查
   - 运行 golangci-lint

2. **Test** - 单元测试
   - 运行所有测试
   - 生成覆盖率报告
   - 上传到 Codecov

3. **Build** - 编译
   - 构建可执行文件
   - 上传 artifact

4. **Docker** - Docker 镜像
   - 构建 Docker 镜像
   - 推送到 Docker Hub（仅 main 分支）

5. **Security** - 安全扫描
   - Gosec 安全扫描
   - Trivy 漏洞扫描

### Release 工作流

`.github/workflows/release.yml` 定义了发布流程：

#### 触发条件

- 推送版本标签（如 v1.0.0）

#### 流程

1. 运行测试
2. 构建多平台二进制文件
3. 生成 changelog
4. 创建 GitHub Release
5. 构建并推送 Docker 镜像

### 配置 Secrets

在 GitHub 仓库设置中添加以下 Secrets：

- `DOCKER_USERNAME` - Docker Hub 用户名
- `DOCKER_PASSWORD` - Docker Hub 密码或访问令牌
- `CODECOV_TOKEN` - Codecov 令牌（可选）

### 创建 Release

```bash
# 创建标签
git tag -a v1.0.0 -m "Release version 1.0.0"

# 推送标签
git push origin v1.0.0
```

GitHub Actions 会自动：
- 构建多平台二进制文件
- 创建 GitHub Release
- 构建并推送 Docker 镜像

---

## 🎯 最佳实践

### 开发流程

1. **开始开发**
   ```bash
   git checkout -b feature/new-feature
   ```

2. **编写代码**
   - VS Code 会自动格式化和检查
   - 使用 REST Client 测试 API

3. **提交前检查**
   ```bash
   # 运行测试
   make test

   # 运行 lint
   make lint

   # 或者 pre-commit 会自动检查
   git commit -m "feat: add new feature"
   ```

4. **推送代码**
   ```bash
   git push origin feature/new-feature
   ```

5. **创建 Pull Request**
   - GitHub Actions 会自动运行 CI
   - 检查所有测试是否通过

### Commit 消息规范

遵循 [Conventional Commits](https://www.conventionalcommits.org/)：

```
<type>(<scope>): <subject>

<body>

<footer>
```

**类型（type）**:
- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更新
- `style`: 代码格式调整
- `refactor`: 重构
- `test`: 测试相关
- `chore`: 构建/工具链相关

**示例**:
```bash
git commit -m "feat(user): add user registration endpoint"
git commit -m "fix(auth): fix JWT token expiration issue"
git commit -m "docs: update API documentation"
```

---

## 🔧 故障排查

### Pre-commit 检查失败

```bash
# 查看详细错误
pre-commit run --all-files --verbose

# 跳过特定 hook
SKIP=golangci-lint git commit -m "message"
```

### golangci-lint 误报

在 `.golangci.yml` 中添加排除规则：

```yaml
issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - funlen
```

### GitHub Actions 失败

1. 查看 Actions 日志
2. 本地重现问题：
   ```bash
   make test
   make lint
   make build
   ```

---

## 📚 参考资料

- [REST Client 文档](https://marketplace.visualstudio.com/items?itemName=humao.rest-client)
- [Pre-commit 文档](https://pre-commit.com/)
- [golangci-lint 文档](https://golangci-lint.run/)
- [EditorConfig 文档](https://editorconfig.org/)
- [GitHub Actions 文档](https://docs.github.com/en/actions)
- [Conventional Commits](https://www.conventionalcommits.org/)
