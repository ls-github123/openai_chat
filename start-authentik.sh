#!/bin/bash

set -e # 遇到错误即退出脚本执行
echo "使用系统托管身份登录Azure"
az login --identity > /dev/null

echo "从Azure Key Vault中获取机密"

PG_PASS=$(az keyvault secret show \
  --vault-name openai-chat-key \
  --name PG-PASS \
  --query value -o tsv)

AUTHENTIK_SECRET_KEY=$(az keyvault secret show \
  --vault-name openai-chat-key \
  --name AUTHENTIK-SECRET-KEY \
  --query value -o tsv)

# 检查机密数据及变量是否成功获取
if [[ -z "PG_PASS" || -z "AUTHENTIK_SECRET_KEY" ]]; then
  echo "获取机密数据失败,PG_PASS 或 AUTHENTIK_SECRET_KEY 为空！"
  exit 1
fi

echo "密钥(机密)已成功获取,写入.env文件"
cat > .env <<EOF
PG_USER=authentik
PG_DB=authentik
PG_PASS=$PG_PASS
AUTHENTIK_SECRET_KEY=$AUTHENTIK_SECRET_KEY
EOF

chmod 600 .env

echo "启动Authentik服务···"
docker compose -f authentik_server_dockercompose.yml --env-file .env --compatibility up -d

echo "Authentik服务已启动"
docker compose -f authentik_server_dockercompose.yml ps