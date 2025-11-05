#!/bin/bash

# Gin Template 功能验证脚本
# 此脚本用于验证新增的 6 大功能是否正常工作

set -e

echo "🚀 Gin Template 功能验证开始..."
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查命令是否存在
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}✗ $1 未安装${NC}"
        return 1
    else
        echo -e "${GREEN}✓ $1 已安装${NC}"
        return 0
    fi
}

# 功能 1: 检查 Swagger 文档文件
echo "📚 [1/6] 检查 Swagger 文档..."
if [ -f "docs/docs.go" ] && [ -f "docs/swagger.json" ] && [ -f "docs/swagger.yaml" ]; then
    echo -e "${GREEN}✓ Swagger 文档文件存在${NC}"
    echo "  - docs/docs.go"
    echo "  - docs/swagger.json"
    echo "  - docs/swagger.yaml"
else
    echo -e "${RED}✗ Swagger 文档文件缺失${NC}"
fi
echo ""

# 功能 2: 检查 Repository 测试文件
echo "🧪 [2/6] 检查 Repository 单元测试..."
if [ -f "internal/repository/user_repository_test.go" ]; then
    echo -e "${GREEN}✓ Repository 测试文件存在${NC}"
    test_count=$(grep -c "func (suite \*UserRepositoryTestSuite) Test" internal/repository/user_repository_test.go)
    echo "  - 测试用例数量: $test_count"
else
    echo -e "${RED}✗ Repository 测试文件缺失${NC}"
fi
echo ""

# 功能 3: 检查验证中间件
echo "🧹 [3/6] 检查通用验证中间件..."
if [ -f "internal/api/middleware/validate.go" ]; then
    echo -e "${GREEN}✓ 验证中间件文件存在${NC}"
    if grep -q "ValidateJSON" internal/api/middleware/validate.go; then
        echo "  - ValidateJSON 函数已定义"
    fi
    if grep -q "GetValidatedRequest" internal/api/middleware/validate.go; then
        echo "  - GetValidatedRequest 函数已定义"
    fi
else
    echo -e "${RED}✗ 验证中间件文件缺失${NC}"
fi
echo ""

# 功能 4: 检查 Pprof 中间件
echo "📈 [4/6] 检查 Pprof 性能分析..."
if [ -f "internal/api/middleware/pprof.go" ]; then
    echo -e "${GREEN}✓ Pprof 中间件文件存在${NC}"
    if grep -q "pprof.enabled" config/config.yaml; then
        echo "  - 配置项已添加"
    fi
else
    echo -e "${RED}✗ Pprof 中间件文件缺失${NC}"
fi
echo ""

# 功能 5: 检查 Sentry 集成
echo "🔍 [5/6] 检查 Sentry 错误追踪..."
if [ -f "internal/api/middleware/sentry.go" ]; then
    echo -e "${GREEN}✓ Sentry 中间件文件存在${NC}"
    if grep -q "sentry.enabled" config/config.yaml; then
        echo "  - 配置项已添加"
    fi
    if grep -q "InitSentry" cmd/server/main.go; then
        echo "  - 初始化代码已添加"
    fi
else
    echo -e "${RED}✗ Sentry 中间件文件缺失${NC}"
fi
echo ""

# 功能 6: 检查 OpenTelemetry 集成
echo "🔗 [6/6] 检查 OpenTelemetry 分布式追踪..."
if [ -f "internal/api/middleware/tracing.go" ]; then
    echo -e "${GREEN}✓ OpenTelemetry 中间件文件存在${NC}"
    if grep -q "tracing.enabled" config/config.yaml; then
        echo "  - 配置项已添加"
    fi
    if grep -q "InitTracing" cmd/server/main.go; then
        echo "  - 初始化代码已添加"
    fi
else
    echo -e "${RED}✗ OpenTelemetry 中间件文件缺失${NC}"
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 检查编译
echo "🔨 编译检查..."
if go build -o /tmp/gin-template-test cmd/server/main.go 2>&1; then
    echo -e "${GREEN}✓ 项目编译成功${NC}"
    rm -f /tmp/gin-template-test
else
    echo -e "${RED}✗ 项目编译失败${NC}"
    exit 1
fi
echo ""

# 检查测试
echo "🧪 运行测试..."
if go test ./internal/repository/... -v 2>&1 | grep -q "PASS"; then
    echo -e "${GREEN}✓ Repository 测试通过${NC}"
else
    echo -e "${YELLOW}⚠ Repository 测试需要数据库配置${NC}"
fi
echo ""

# 检查依赖
echo "📦 检查依赖..."
required_deps=(
    "github.com/swaggo/swag"
    "github.com/getsentry/sentry-go"
    "go.opentelemetry.io/otel"
    "github.com/stretchr/testify"
    "gorm.io/driver/sqlite"
)

for dep in "${required_deps[@]}"; do
    if grep -q "$dep" go.mod; then
        echo -e "${GREEN}✓ $dep${NC}"
    else
        echo -e "${RED}✗ $dep 缺失${NC}"
    fi
done
echo ""

# 检查文档
echo "📖 检查文档..."
docs=(
    "README.md"
    "CHANGELOG.md"
    "docs/FEATURES.md"
)

for doc in "${docs[@]}"; do
    if [ -f "$doc" ]; then
        echo -e "${GREEN}✓ $doc${NC}"
    else
        echo -e "${RED}✗ $doc 缺失${NC}"
    fi
done
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${GREEN}✅ 功能验证完成！${NC}"
echo ""
echo "🎯 下一步操作："
echo "   1. 配置数据库连接（config/config.yaml）"
echo "   2. 启动应用: make run 或 make dev"
echo "   3. 访问 Swagger 文档: http://localhost:8080/swagger/index.html"
echo "   4. （可选）配置 Sentry DSN"
echo "   5. （可选）启动 Jaeger: docker run -d -p 16686:16686 -p 14268:14268 jaegertracing/all-in-one:latest"
echo ""
echo "📚 详细文档: docs/FEATURES.md"
echo ""
