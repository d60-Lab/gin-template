.PHONY: help run build test clean tidy install-tools swagger lint fmt pre-commit

help: ## 显示帮助信息
	@echo "可用命令:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

run: ## 运行应用
	go run cmd/server/main.go

build: ## 编译应用
	go build -o bin/server cmd/server/main.go

test: ## 运行测试
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...

test-coverage: test ## 运行测试并生成覆盖率报告
	go tool cover -html=coverage.txt -o coverage.html

clean: ## 清理构建产物
	rm -rf bin/
	rm -f coverage.txt coverage.html

tidy: ## 整理依赖
	go mod tidy

install-tools: ## 安装开发工具
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	go install github.com/air-verse/air@v1.52.3

swagger: ## 生成 Swagger 文档
	swag init -g cmd/server/main.go -o docs --parseDependency --parseInternal

lint: ## 运行代码检查
	golangci-lint run ./...

lint-fix: ## 运行代码检查并自动修复
	golangci-lint run --fix ./...

fmt: ## 格式化代码
	go fmt ./...
	goimports -w -local github.com/d60-Lab/gin-template .

pre-commit: ## 运行 pre-commit 检查所有文件
	pre-commit run --all-files

pre-commit-install: ## 安装 pre-commit hooks
	pre-commit install
	pre-commit install --hook-type commit-msg

docker-build: ## 构建 Docker 镜像
	docker build -t gin-template:latest .

docker-run: ## 运行 Docker 容器
	docker run -p 8080:8080 gin-template:latest

dev: ## 开发模式运行（使用 air 热重载）
	air

init-db: ## 初始化数据库
	createdb gin_template || true

ci: lint test build ## 运行 CI 流程（lint + test + build）

verify: fmt lint test ## 提交前验证（格式化 + lint + 测试）
