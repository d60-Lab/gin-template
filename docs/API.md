# API 接口文档

本文档描述了 Gin Template 项目的所有 API 接口。

## 基础信息

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **API Prefix**: `/api/v1`

## 通用响应格式

所有接口返回统一的 JSON 格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

- `code`: 状态码，0 表示成功，其他值表示错误
- `message`: 响应消息
- `data`: 响应数据，可选

## 错误码说明

| Code | 含义 |
|------|------|
| 0 | 成功 |
| 400 | 请求参数错误 |
| 401 | 未授权 |
| 403 | 禁止访问 |
| 404 | 资源未找到 |
| 429 | 请求过于频繁 |
| 500 | 服务器内部错误 |

## 接口列表

### 1. 健康检查

检查服务是否正常运行。

**请求:**

```
GET /health
```

**响应:**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "status": "ok"
  }
}
```

---

### 2. 用户注册

创建新用户。

**请求:**

```
POST /api/v1/users
Content-Type: application/json
```

**请求体:**

```json
{
  "username": "string (required, min=3, max=20)",
  "email": "string (required, email format)",
  "password": "string (required, min=6)",
  "age": "integer (optional, 0-130)"
}
```

**响应:**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": "uuid",
    "username": "testuser",
    "email": "test@example.com",
    "age": 25,
    "created_at": "2023-01-01 12:00:00",
    "updated_at": "2023-01-01 12:00:00"
  }
}
```

**错误响应:**

```json
{
  "code": 400,
  "message": "user already exists"
}
```

---

### 3. 用户登录

用户登录并获取 JWT token。

**请求:**

```
POST /api/v1/auth/login
Content-Type: application/json
```

**请求体:**

```json
{
  "username": "string (required)",
  "password": "string (required)"
}
```

**响应:**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user_id": "uuid",
    "username": "testuser"
  }
}
```

**错误响应:**

```json
{
  "code": 400,
  "message": "invalid username or password"
}
```

---

### 4. 获取用户列表

获取用户列表（分页）。

**请求:**

```
GET /api/v1/users?page=1&page_size=10
```

**查询参数:**

- `page`: 页码，默认 1
- `page_size`: 每页数量，默认 10，最大 100

**响应:**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "page": 1,
    "page_size": 10,
    "list": [
      {
        "id": "uuid",
        "username": "user1",
        "email": "user1@example.com",
        "age": 25,
        "created_at": "2023-01-01 12:00:00",
        "updated_at": "2023-01-01 12:00:00"
      }
    ]
  }
}
```

---

### 5. 获取用户详情

根据用户 ID 获取用户信息。

**请求:**

```
GET /api/v1/users/:id
```

**路径参数:**

- `id`: 用户 ID (uuid)

**响应:**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": "uuid",
    "username": "testuser",
    "email": "test@example.com",
    "age": 25,
    "created_at": "2023-01-01 12:00:00",
    "updated_at": "2023-01-01 12:00:00"
  }
}
```

**错误响应:**

```json
{
  "code": 404,
  "message": "user not found"
}
```

---

### 6. 更新用户信息

更新用户信息（需要认证）。

**请求:**

```
PUT /api/v1/users/:id
Authorization: Bearer <token>
Content-Type: application/json
```

**路径参数:**

- `id`: 用户 ID (uuid)

**请求头:**

- `Authorization`: Bearer token

**请求体:**

```json
{
  "username": "string (optional, min=3, max=20)",
  "email": "string (optional, email format)",
  "age": "integer (optional, 0-130)"
}
```

**响应:**

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": "uuid",
    "username": "newusername",
    "email": "newemail@example.com",
    "age": 26,
    "created_at": "2023-01-01 12:00:00",
    "updated_at": "2023-01-02 12:00:00"
  }
}
```

**错误响应:**

```json
{
  "code": 401,
  "message": "unauthorized"
}
```

---

### 7. 删除用户

删除用户（需要认证和管理员权限）。

**请求:**

```
DELETE /api/v1/users/:id
Authorization: Bearer <token>
```

**路径参数:**

- `id`: 用户 ID (uuid)

**请求头:**

- `Authorization`: Bearer token

**响应:**

```json
{
  "code": 0,
  "message": "success"
}
```

**错误响应:**

```json
{
  "code": 401,
  "message": "unauthorized"
}
```

```json
{
  "code": 403,
  "message": "forbidden"
}
```

---

## 认证说明

需要认证的接口需要在请求头中包含 JWT token：

```
Authorization: Bearer <your_token>
```

token 可以通过登录接口获取，有效期为 24 小时（可在配置文件中修改）。

## 限流说明

部分接口启用了限流保护：
- 限制：每秒 100 个请求
- 突发：200 个请求
- 超出限制将返回 429 状态码

## 使用示例

### cURL 示例

```bash
# 注册用户
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}'

# 登录
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'

# 获取用户列表
curl http://localhost:8080/api/v1/users

# 更新用户（需要替换 token 和 user_id）
curl -X PUT http://localhost:8080/api/v1/users/{user_id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {token}" \
  -d '{"username":"newusername"}'
```

### JavaScript 示例

```javascript
// 注册用户
const register = async () => {
  const response = await fetch('http://localhost:8080/api/v1/users', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username: 'testuser',
      email: 'test@example.com',
      password: 'password123',
      age: 25
    })
  });
  return await response.json();
};

// 登录
const login = async () => {
  const response = await fetch('http://localhost:8080/api/v1/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username: 'testuser',
      password: 'password123'
    })
  });
  const data = await response.json();
  return data.data.token;
};

// 获取用户信息（需要 token）
const getUser = async (userId, token) => {
  const response = await fetch(`http://localhost:8080/api/v1/users/${userId}`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  return await response.json();
};
```

## 更新日志

- **v1.0.0** (2024-01-01)
  - 初始版本
  - 用户注册、登录、CRUD 功能
  - JWT 认证
  - 基本中间件支持
