.PHONY: help run build test clean tidy install-tools swagger

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
	go install github.com/cosmtrek/air@latest

swagger: ## 生成 Swagger 文档
	swag init -g cmd/server/main.go -o docs --parseDependency --parseInternal

lint: ## 运行代码检查
	golangci-lint run ./...

fmt: ## 格式化代码
	go fmt ./...

docker-build: ## 构建 Docker 镜像
	docker build -t gin-template:latest .

docker-run: ## 运行 Docker 容器
	docker run -p 8080:8080 gin-template:latest

dev: ## 开发模式运行（使用 air 热重载）
	air

init-db: ## 初始化数据库
	createdb gin_template || true
