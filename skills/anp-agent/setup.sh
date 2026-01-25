#!/bin/bash
#
# ANP Agent Skill 一键安装脚本
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/config"

echo "=========================================="
echo "  ANP Agent Skill 安装程序"
echo "=========================================="
echo ""

# 1. 检查 Python
echo "[1/4] 检查 Python 环境..."
if ! command -v python3 &> /dev/null; then
    echo "❌ 未找到 Python3，请先安装 Python 3.8+"
    exit 1
fi
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "✅ Python $PYTHON_VERSION"

# 2. 安装依赖
echo ""
echo "[2/4] 安装 Python 依赖..."
pip3 install -q anp aiohttp
echo "✅ 依赖安装完成"

# 3. 检查/生成 DID 身份
echo ""
echo "[3/4] 配置 DID 身份..."

if [ -f "$CONFIG_DIR/did.json" ] && [ -f "$CONFIG_DIR/private-key.pem" ]; then
    echo "✅ 已存在 DID 身份，跳过生成"
    DID_ID=$(python3 -c "import json; print(json.load(open('$CONFIG_DIR/did.json'))['id'])" 2>/dev/null || echo "unknown")
    echo "   DID: $DID_ID"
else
    echo "⚙️  生成本地临时身份..."
    
    # 生成 secp256k1 私钥
    openssl ecparam -name secp256k1 -genkey -noout -out "$CONFIG_DIR/private-key.pem" 2>/dev/null
    
    # 导出公钥参数用于 DID
    PUB_X=$(openssl ec -in "$CONFIG_DIR/private-key.pem" -pubout -outform DER 2>/dev/null | tail -c 64 | head -c 32 | base64 | tr '+/' '-_' | tr -d '=')
    PUB_Y=$(openssl ec -in "$CONFIG_DIR/private-key.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=')
    
    # 生成随机 ID
    RANDOM_ID=$(openssl rand -hex 8)
    
    # 创建 DID 文档
    cat > "$CONFIG_DIR/did.json" << EOF
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/secp256k1-2019/v1"
  ],
  "id": "did:wba:local:user:$RANDOM_ID",
  "verificationMethod": [
    {
      "id": "did:wba:local:user:$RANDOM_ID#key-1",
      "type": "EcdsaSecp256k1VerificationKey2019",
      "controller": "did:wba:local:user:$RANDOM_ID",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "$PUB_X",
        "y": "$PUB_Y"
      }
    }
  ],
  "authentication": [
    "did:wba:local:user:$RANDOM_ID#key-1"
  ]
}
EOF
    
    echo "✅ 本地身份生成完成"
    echo "   DID: did:wba:local:user:$RANDOM_ID"
    echo ""
    echo "   提示：如需正式 DID，请访问 https://didhost.cc 注册"
    echo "   然后将 did.json 和 private-key.pem 替换到 config/ 目录"
fi

# 4. 验证安装
echo ""
echo "[4/4] 验证安装..."
cd "$SCRIPT_DIR"
if python3 scripts/anp_cli.py list &> /dev/null; then
    echo "✅ 安装成功！"
else
    echo "⚠️  安装可能有问题，请检查错误信息"
fi

echo ""
echo "=========================================="
echo "  安装完成！"
echo "=========================================="
echo ""
echo "快速开始："
echo ""
echo "  # 查看已注册的 Agent"
echo "  python scripts/anp_cli.py list"
echo ""
echo "  # 搜索北京咖啡厅"
echo "  python scripts/anp_cli.py call amap maps_text_search '{\"keywords\":\"咖啡厅\",\"city\":\"北京\"}'"
echo ""
echo "  # 查询上海天气"
echo "  python scripts/anp_cli.py call amap maps_weather '{\"city\":\"上海\"}'"
echo ""
