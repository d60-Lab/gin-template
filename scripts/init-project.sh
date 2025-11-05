#!/bin/bash

# Gin Template 项目初始化脚本
# 用于从模板创建新项目时初始化配置

set -e

# 颜色定义
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                                   ║${NC}"
echo -e "${BLUE}║          🚀 Gin Template 项目初始化                                ║${NC}"
echo -e "${BLUE}║                                                                   ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 检测当前 module 名称
CURRENT_MODULE=$(go list -m 2>/dev/null || echo "")
if [ -z "$CURRENT_MODULE" ]; then
    CURRENT_MODULE="github.com/d60-Lab/gin-template"
fi

echo -e "${YELLOW}当前模块名称: ${CURRENT_MODULE}${NC}"
echo ""

# 询问新的项目信息
read -p "📦 请输入新的模块名称 (例如: github.com/yourusername/yourproject): " NEW_MODULE

if [ -z "$NEW_MODULE" ]; then
    echo -e "${RED}❌ 模块名称不能为空${NC}"
    exit 1
fi

read -p "📝 请输入项目显示名称 (例如: My Awesome Project) [默认: ${NEW_MODULE##*/}]: " PROJECT_NAME
if [ -z "$PROJECT_NAME" ]; then
    PROJECT_NAME="${NEW_MODULE##*/}"
fi

read -p "👤 请输入作者名称 [默认: $(git config user.name 2>/dev/null || echo 'Unknown')]: " AUTHOR
if [ -z "$AUTHOR" ]; then
    AUTHOR=$(git config user.name 2>/dev/null || echo "Unknown")
fi

read -p "📧 请输入作者邮箱 [默认: $(git config user.email 2>/dev/null || echo 'unknown@example.com')]: " EMAIL
if [ -z "$EMAIL" ]; then
    EMAIL=$(git config user.email 2>/dev/null || echo "unknown@example.com")
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}配置信息确认:${NC}"
echo -e "  模块名称: ${NEW_MODULE}"
echo -e "  项目名称: ${PROJECT_NAME}"
echo -e "  作者:     ${AUTHOR}"
echo -e "  邮箱:     ${EMAIL}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -p "确认以上信息正确？(y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}已取消${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}🔧 开始初始化项目...${NC}"
echo ""

# 1. 更新 go.mod
echo -e "${BLUE}[1/9]${NC} 更新 go.mod..."
if [ "$CURRENT_MODULE" != "$NEW_MODULE" ]; then
    sed -i.bak "s|module $CURRENT_MODULE|module $NEW_MODULE|g" go.mod
    rm -f go.mod.bak
    echo -e "${GREEN}✓${NC} go.mod 已更新"
else
    echo -e "${YELLOW}⊙${NC} go.mod 无需更新"
fi

# 2. 更新所有 Go 文件中的 import 路径
echo -e "${BLUE}[2/9]${NC} 更新导入路径..."
if [ "$CURRENT_MODULE" != "$NEW_MODULE" ]; then
    # macOS 和 Linux 兼容的 sed 命令
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        find . -type f -name "*.go" -not -path "*/vendor/*" -not -path "*/.git/*" -exec sed -i '' "s|$CURRENT_MODULE|$NEW_MODULE|g" {} +
    else
        # Linux
        find . -type f -name "*.go" -not -path "*/vendor/*" -not -path "*/.git/*" -exec sed -i "s|$CURRENT_MODULE|$NEW_MODULE|g" {} +
    fi
    echo -e "${GREEN}✓${NC} 导入路径已更新"
else
    echo -e "${YELLOW}⊙${NC} 导入路径无需更新"
fi

# 3. 更新 README.md
echo -e "${BLUE}[3/9]${NC} 更新 README.md..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s|gin-template|$PROJECT_NAME|g" README.md
    sed -i '' "s|d60-Lab/gin-template|$NEW_MODULE|g" README.md
else
    sed -i "s|gin-template|$PROJECT_NAME|g" README.md
    sed -i "s|d60-Lab/gin-template|$NEW_MODULE|g" README.md
fi
echo -e "${GREEN}✓${NC} README.md 已更新"

# 4. 更新 Swagger 文档
echo -e "${BLUE}[4/9]${NC} 更新 Swagger 配置..."
if [ -f "cmd/server/main.go" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|@title.*|@title $PROJECT_NAME API|g" cmd/server/main.go
        sed -i '' "s|@contact.name.*|@contact.name $AUTHOR|g" cmd/server/main.go
        sed -i '' "s|@contact.email.*|@contact.email $EMAIL|g" cmd/server/main.go
    else
        sed -i "s|@title.*|@title $PROJECT_NAME API|g" cmd/server/main.go
        sed -i "s|@contact.name.*|@contact.name $AUTHOR|g" cmd/server/main.go
        sed -i "s|@contact.email.*|@contact.email $EMAIL|g" cmd/server/main.go
    fi
    echo -e "${GREEN}✓${NC} Swagger 配置已更新"
fi

# 5. 创建 .env 文件
echo -e "${BLUE}[5/9]${NC} 创建环境变量文件..."
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
    echo -e "${GREEN}✓${NC} .env 文件已创建"
    echo -e "${YELLOW}⚠${NC}  请编辑 .env 文件配置数据库连接等信息"
else
    echo -e "${YELLOW}⊙${NC} .env 文件已存在"
fi

# 6. 下载依赖
echo -e "${BLUE}[6/9]${NC} 下载 Go 依赖..."
go mod tidy
echo -e "${GREEN}✓${NC} 依赖下载完成"

# 7. 安装开发工具
echo -e "${BLUE}[7/9]${NC} 安装开发工具..."
read -p "是否安装开发工具 (swag, air)? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v make &> /dev/null; then
        make install-tools
        echo -e "${GREEN}✓${NC} 开发工具安装完成"
    else
        echo -e "${YELLOW}⚠${NC}  make 命令不存在，手动安装:"
        echo "    go install github.com/swaggo/swag/cmd/swag@latest"
        echo "    go install github.com/cosmtrek/air@latest"
    fi
else
    echo -e "${YELLOW}⊙${NC} 跳过工具安装"
fi

# 8. 生成 Swagger 文档
echo -e "${BLUE}[8/9]${NC} 生成 Swagger 文档..."
if command -v swag &> /dev/null; then
    make swagger
    echo -e "${GREEN}✓${NC} Swagger 文档已生成"
else
    echo -e "${YELLOW}⚠${NC}  swag 未安装，跳过文档生成"
    echo "    安装: go install github.com/swaggo/swag/cmd/swag@latest"
fi

# 9. 初始化数据库（可选）
echo -e "${BLUE}[9/9]${NC} 初始化数据库..."
read -p "是否立即初始化数据库? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}选择数据库初始化方式:${NC}"
    echo "  1) 使用 Docker Compose (推荐)"
    echo "  2) 使用现有数据库"
    echo "  3) 跳过"
    read -p "请选择 (1-3): " -n 1 -r DB_CHOICE
    echo ""

    case $DB_CHOICE in
        1)
            if command -v docker-compose &> /dev/null || command -v docker &> /dev/null; then
                echo -e "${BLUE}启动 Docker 服务...${NC}"
                if command -v docker-compose &> /dev/null; then
                    docker-compose up -d postgres redis
                else
                    docker compose up -d postgres redis
                fi
                echo -e "${GREEN}✓${NC} 数据库服务已启动"
                echo -e "${YELLOW}⚠${NC}  等待数据库启动完成..."
                sleep 5
            else
                echo -e "${RED}❌ Docker 未安装${NC}"
            fi
            ;;
        2)
            echo -e "${YELLOW}⚠${NC}  请确保已正确配置 .env 中的数据库连接信息"
            ;;
        3)
            echo -e "${YELLOW}⊙${NC} 跳过数据库初始化"
            ;;
    esac
else
    echo -e "${YELLOW}⊙${NC} 跳过数据库初始化"
fi

# 完成
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}✅ 项目初始化完成！${NC}"
echo ""
echo -e "${BLUE}🎯 下一步操作:${NC}"
echo ""
echo -e "  1. 配置环境变量:"
echo -e "     ${YELLOW}vim .env${NC}"
echo ""
echo -e "  2. 启动开发服务器:"
echo -e "     ${YELLOW}make dev${NC}     # 热重载模式"
echo -e "     ${YELLOW}make run${NC}     # 普通模式"
echo ""
echo -e "  3. 访问应用:"
echo -e "     应用地址:    ${YELLOW}http://localhost:8080${NC}"
echo -e "     Swagger UI:  ${YELLOW}http://localhost:8080/swagger/index.html${NC}"
echo -e "     健康检查:    ${YELLOW}http://localhost:8080/health${NC}"
echo ""
echo -e "  4. 查看文档:"
echo -e "     快速开始:    ${YELLOW}docs/QUICKSTART_FEATURES.md${NC}"
echo -e "     高级功能:    ${YELLOW}docs/FEATURES.md${NC}"
echo ""
echo -e "${BLUE}📚 更多帮助:${NC}"
echo -e "     ${YELLOW}make help${NC}    # 查看所有可用命令"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}祝开发愉快！ 🎉${NC}"
echo ""
