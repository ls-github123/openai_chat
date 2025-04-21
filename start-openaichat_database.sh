#!/bin/bash

VAULT_NAME="openai-chat-key" # Azure Key Vault名称
ENV_FILE=".env" # 环境变量文件名
COMPOSE_FILE="openai_database_dockercompose.yml" # Docker Compose文件名

echo "从Azure Key Vault加载数据库密码..."

# 获取密码
MYSQL_ROOT_PWD=$(az keyvault secret show --vault-name "$VAULT_NAME" --name openai-mysql-root --query value -o tsv)
REDIS_PWD=$(az keyvault secret show --vault-name "$VAULT_NAME" --name openai-redis-pd --query value -o tsv)
MONGODB_PWD=$(az keyvault secret show --vault-name "$VAULT_NAME" --name openai-mongodb-pd --query value -o tsv)

# 检查密码是否成功获取
if [[ -z "MYSQL_ROOT_PWD" || -z "REDIS_PWD" || -z "MONGODB_PWD" ]]; then
  echo "获取密码失败,MYSQL_ROOT_PWD 或 REDIS_PWD 或 MONGODB_PWD 为空！"
  exit 1
fi

# 生成.env文件(覆盖旧文件)
echo "将密码写入.env文件"
cat <<EOF > $ENV_FILE
# Mysql数据库
MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PWD
MYSQL_DATABASE=openai_chat_db
MYSQL_USER=chat_user
MYSQL_USER_PASSWORD=$MYSQL_ROOT_PWD

# Redis数据库
REDIS_PASSWORD=$REDIS_PWD

# MongoDB数据库
MONGO_ROOT_USERNAME=chat_mongo_user
MONGO_ROOT_PASSWORD=$MONGODB_PWD
MONGO_DB=openai_chat_mongo
EOF

chmod 600 $ENV_FILE
echo ".env文件已生成"

# 启动数据库服务
echo "启动Docker Compose服务..."
docker compose -f $COMPOSE_FILE up -d