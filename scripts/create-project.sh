#!/bin/bash

# Gin Template 项目创建脚本
# 直接从 GitHub 下载模板并创建新项目
#
# 用法:
#   curl -fsSL https://raw.githubusercontent.com/d60-Lab/gin-template/main/scripts/create-project.sh | bash -s -- my-project
#   或
#   ./create-project.sh my-project

set -e

# 颜色定义
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

TEMPLATE_REPO="https://github.com/d60-Lab/gin-template"
TEMPLATE_NAME="gin-template"

# 检查参数
if [ -z "$1" ]; then
    echo -e "${RED}❌ 错误: 请提供项目名称${NC}"
    echo ""
    echo "用法:"
    echo "  $0 <project-name>"
    echo ""
    echo "示例:"
    echo "  $0 my-awesome-project"
    exit 1
fi

PROJECT_NAME=$1
PROJECT_DIR="${PROJECT_NAME}"

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                                   ║${NC}"
echo -e "${BLUE}║          🚀 从 Gin Template 创建新项目                             ║${NC}"
echo -e "${BLUE}║                                                                   ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}项目名称: ${PROJECT_NAME}${NC}"
echo ""

# 检查目录是否已存在
if [ -d "$PROJECT_DIR" ]; then
    echo -e "${RED}❌ 错误: 目录 ${PROJECT_DIR} 已存在${NC}"
    exit 1
fi

# 检查依赖
echo -e "${BLUE}检查依赖...${NC}"

if ! command -v git &> /dev/null; then
    echo -e "${RED}❌ git 未安装${NC}"
    exit 1
fi

if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go 未安装${NC}"
    exit 1
fi

echo -e "${GREEN}✓ 依赖检查通过${NC}"
echo ""

# 下载模板
echo -e "${BLUE}📥 下载模板...${NC}"

# 方法 1: 使用 degit (如果安装了)
if command -v degit &> /dev/null; then
    degit d60-Lab/gin-template "$PROJECT_DIR"
    echo -e "${GREEN}✓ 使用 degit 下载完成${NC}"
else
    # 方法 2: 使用 git clone
    git clone --depth 1 "$TEMPLATE_REPO" "$PROJECT_DIR"
    rm -rf "$PROJECT_DIR/.git"
    echo -e "${GREEN}✓ 使用 git clone 下载完成${NC}"
fi

cd "$PROJECT_DIR"

# 初始化 git
echo ""
echo -e "${BLUE}🔧 初始化 Git 仓库...${NC}"
git init
git add .
git commit -m "Initial commit from gin-template" > /dev/null 2>&1
echo -e "${GREEN}✓ Git 仓库已初始化${NC}"

# 运行初始化脚本
echo ""
echo -e "${BLUE}🎨 配置项目...${NC}"
echo ""

if [ -f "scripts/init-project.sh" ]; then
    chmod +x scripts/init-project.sh
    ./scripts/init-project.sh
else
    echo -e "${YELLOW}⚠ 初始化脚本不存在，跳过配置${NC}"

    # 基本配置
    echo -e "${BLUE}执行基本配置...${NC}"

    # 创建 .env
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${GREEN}✓ .env 文件已创建${NC}"
    fi

    # 下载依赖
    go mod tidy
    echo -e "${GREEN}✓ 依赖下载完成${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}✅ 项目 ${PROJECT_NAME} 创建成功！${NC}"
echo ""
echo -e "${BLUE}📂 项目位置:${NC} $(pwd)"
echo ""
echo -e "${BLUE}🎯 下一步:${NC}"
echo ""
echo -e "  cd ${PROJECT_NAME}"
echo -e "  make dev          ${YELLOW}# 启动开发服务器${NC}"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
