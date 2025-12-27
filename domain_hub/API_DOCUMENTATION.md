# API文档 - 阿里云DNS二级域名分发插件

## 基本信息

**API地址：** `https://您的域名/index.php?m=domain_hub`

**认证方式：** API Key + API Secret

**支持格式：** JSON

**速率限制：** 默认 60 请求/分钟（可在后台配置）

---

## 认证

### 获取API密钥

1. 登录WHMCS客户区
2. 进入"我的二级域名管理"页面
3. 在底部找到"API管理"卡片
4. 点击"创建API密钥"

### 认证方式

#### 方式1：HTTP Header（推荐）

```bash
curl -X GET "https://您的域名/index.php?m=domain_hub&endpoint=subdomains&action=list" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy"
```

#### 方式2：URL参数

```bash
curl -X GET "https://您的域名/index.php?m=domain_hub&endpoint=subdomains&action=list&api_key=cfsd_xxxxxxxxxx&api_secret=yyyyyyyyyyyy"
```

---

## API端点

### 1. 子域名管理

#### 1.1 列出子域名

**端点：** `subdomains`  
**操作：** `list`  
**方法：** `GET`

**请求示例：**
```bash
curl -X GET "https://您的域名/index.php?m=domain_hub&endpoint=subdomains&action=list" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy"
```

**响应示例：**
```json
{
  "success": true,
  "count": 2,
  "subdomains": [
    {
      "id": 1,
      "subdomain": "test",
      "rootdomain": "example.com",
      "full_domain": "test.example.com",
      "status": "active",
      "created_at": "2025-10-19 10:00:00",
      "updated_at": "2025-10-19 10:00:00"
    },
    {
      "id": 2,
      "subdomain": "api",
      "rootdomain": "example.com",
      "full_domain": "api.example.com",
      "status": "active",
      "created_at": "2025-10-19 11:00:00",
      "updated_at": "2025-10-19 11:00:00"
    }
  ]
}
```

---

#### 1.2 注册子域名

**端点：** `subdomains`  
**操作：** `register`  
**方法：** `POST`

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| subdomain | string | 是 | 子域名前缀 |
| rootdomain | string | 是 | 根域名 |

**请求示例：**
```bash
curl -X POST "https://您的域名/index.php?m=domain_hub&endpoint=subdomains&action=register" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "subdomain": "myapp",
    "rootdomain": "example.com"
  }'
```

**响应示例：**
```json
{
  "success": true,
  "message": "Subdomain registered successfully",
  "subdomain_id": 3,
  "full_domain": "myapp.example.com"
}
```

---

#### 1.3 获取子域名详情

**端点：** `subdomains`  
**操作：** `get`  
**方法：** `GET`

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| subdomain_id | integer | 是 | 子域名ID |

**请求示例：**
```bash
curl -X GET "https://您的域名/index.php?m=domain_hub&endpoint=subdomains&action=get&subdomain_id=1" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy"
```

**响应示例：**
```json
{
  "success": true,
  "subdomain": {
    "id": 1,
    "subdomain": "test",
    "rootdomain": "example.com",
    "full_domain": "test.example.com",
    "status": "active",
    "created_at": "2025-10-19 10:00:00",
    "updated_at": "2025-10-19 10:00:00"
  },
  "dns_records": [
    {
      "id": 1,
      "name": "test.example.com",
      "type": "A",
      "content": "192.168.1.1",
      "ttl": 600,
      "priority": null,
      "status": "active",
      "created_at": "2025-10-19 10:05:00"
    }
  ],
  "dns_count": 1
}
```

---

#### 1.4 删除子域名

**端点：** `subdomains`  
**操作：** `delete`  
**方法：** `POST` 或 `DELETE`

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| subdomain_id | integer | 是 | 子域名ID |

**请求示例：**
```bash
curl -X POST "https://您的域名/index.php?m=domain_hub&endpoint=subdomains&action=delete" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "subdomain_id": 1
  }'
```

**响应示例：**
```json
{
  "success": true,
  "message": "Subdomain deleted successfully"
}
```

---

#### 1.5 续期子域名
**端点：** `subdomains`
**操作：** `renew`
**方法：** `POST` 或 `PUT`
**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| subdomain_id | integer | 是 | 子域名ID |
**请求示例：**
```bash
curl -X POST "https://您的域名/index.php?m=domain_hub&endpoint=subdomains&action=renew" \
-H "X-API-Key: cfsd_xxxxxxxxxx" \
-H "X-API-Secret: yyyyyyyyyyyy" \
-H "Content-Type: application/json" \
-d '{
  "subdomain_id": 3
}'
```
**响应示例：**
```json
{
  "success": true,
  "message": "Subdomain renewed successfully (charged 9.90 credit)",
  "subdomain_id": 3,
  "subdomain": "myapp",
  "previous_expires_at": "2025-05-01 00:00:00",
  "new_expires_at": "2026-05-01 00:00:00",
  "renewed_at": "2025-04-10 12:34:56",
  "never_expires": 0,
  "status": "active",
  "remaining_days": 366,
  "charged_amount": 9.9
}
```
**说明：**
- `charged_amount` 表示本次续期从用户 WHMCS 账户余额中扣除的金额。免费续期或扣费金额为 0 时，该字段值为 `0`。

**可能的错误：**
- `403 renewal disabled`：后台未配置有效的注册年限。
- `403 renewal not yet available`：尚未进入免费续期窗口。
- `403 redemption period requires administrator`：域名处于赎回期且后台配置为人工处理。
- `403 renewal window expired`：已超过续期宽限期。
- `402 insufficient balance for redemption renewal`：赎回期设置为自动扣费，但账户余额不足。
- `404 subdomain not found`：找不到对应子域名或不属于当前 API Key。

---

### 2. DNS记录管理

#### 2.1 列出DNS记录

**端点：** `dns_records`  
**操作：** `list`  
**方法：** `GET`

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| subdomain_id | integer | 是 | 子域名ID |

**请求示例：**
```bash
curl -X GET "https://您的域名/index.php?m=domain_hub&endpoint=dns_records&action=list&subdomain_id=1" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy"
```

**响应示例：**
```json
{
  "success": true,
  "count": 2,
  "records": [
    {
      "id": 1,
      "name": "test.example.com",
      "type": "A",
      "content": "192.168.1.1",
      "ttl": 600,
      "priority": null,
      "proxied": false,
      "status": "active",
      "created_at": "2025-10-19 10:05:00"
    },
    {
      "id": 2,
      "name": "www.test.example.com",
      "type": "CNAME",
      "content": "test.example.com",
      "ttl": 600,
      "priority": null,
      "proxied": false,
      "status": "active",
      "created_at": "2025-10-19 10:10:00"
    }
  ]
}
```

> 提示：列表返回的 `id` 即模块内部记录ID，可直接用于 `update`/`delete` 操作；若需要云解析服务商 `record_id`，请在创建记录时自行保存或通过后台排查工具获取。

---

#### 2.2 创建DNS记录

**端点：** `dns_records`  
**操作：** `create`  
**方法：** `POST`

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| subdomain_id | integer | 是 | 子域名ID |
| type | string | 是 | 记录类型（A/AAAA/CNAME/MX/TXT） |
| name | string | 否 | 记录名称（留空则使用子域名） |
| content | string | 是 | 记录值 |
| ttl | integer | 否 | TTL值（默认600，且不可低于600） |
| priority | integer | 否 | 优先级（MX记录需要） |

**请求示例：**
```bash
curl -X POST "https://您的域名/index.php?m=domain_hub&endpoint=dns_records&action=create" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "subdomain_id": 1,
    "type": "A",
    "content": "192.168.1.100",
    "ttl": 600
  }'
```

**响应示例：**
```json
{
  "success": true,
  "message": "DNS record created successfully",
  "record_id": 3
}
```

---

#### 2.3 更新DNS记录

**端点：** `dns_records`  
**操作：** `update`  
**方法：** `POST` 或 `PUT`

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| record_id | integer | 是 | DNS记录ID |
| content | string | 否 | 新的记录值 |
| ttl | integer | 否 | 新的TTL值 |
| priority | integer | 否 | 新的优先级 |

**请求示例：**
```bash
curl -X POST "https://您的域名/index.php?m=domain_hub&endpoint=dns_records&action=update" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "record_id": 1,
    "content": "192.168.1.200",
    "ttl": 600
  }'
```

**响应示例：**
```json
{
  "success": true,
  "message": "DNS record updated successfully"
}
```

---

#### 2.4 删除DNS记录

**端点：** `dns_records`  
**操作：** `delete`  
**方法：** `POST` 或 `DELETE`

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| record_id | string | 否 | 云解析服务商返回的记录ID。若提供，将首先按该字段匹配。 |
| id | integer | 否 | 模块内部记录ID，可直接使用 `list` 接口返回的 `id` 值。 |

> 至少提供 `record_id` 或 `id` 其中之一。

**请求示例：**
```bash
curl -X POST "https://您的域名/index.php?m=domain_hub&endpoint=dns_records&action=delete" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "id": 1
  }'
```

```bash
curl -X POST "https://您的域名/index.php?m=domain_hub&endpoint=dns_records&action=delete" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "record_id": "5a0ce6c4d1d4c71bc5e60a2a2a0e4997"
  }'
```

**响应示例：**
```json
{
  "success": true,
  "message": "DNS record deleted successfully"
}
```

---

### 3. API密钥管理

#### 3.1 列出API密钥

**端点：** `keys`  
**操作：** `list`  
**方法：** `GET`

**请求示例：**
```bash
curl -X GET "https://您的域名/index.php?m=domain_hub&endpoint=keys&action=list" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy"
```

**响应示例：**
```json
{
  "success": true,
  "count": 2,
  "keys": [
    {
      "id": 1,
      "key_name": "生产环境密钥",
      "api_key": "cfsd_xxxxxxxxxx",
      "status": "active",
      "request_count": 1523,
      "last_used_at": "2025-10-19 15:30:00",
      "created_at": "2025-10-19 10:00:00"
    },
    {
      "id": 2,
      "key_name": "测试环境密钥",
      "api_key": "cfsd_yyyyyyyyyy",
      "status": "active",
      "request_count": 45,
      "last_used_at": "2025-10-19 14:00:00",
      "created_at": "2025-10-19 11:00:00"
    }
  ]
}
```

---

#### 3.2 创建API密钥

**端点：** `keys`  
**操作：** `create`  
**方法：** `POST`

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| key_name | string | 是 | 密钥名称 |
| ip_whitelist | string | 否 | IP白名单（逗号分隔） |

**请求示例：**
```bash
curl -X POST "https://您的域名/index.php?m=domain_hub&endpoint=keys&action=create" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "新密钥",
    "ip_whitelist": "192.168.1.1,192.168.1.2"
  }'
```

**响应示例：**
```json
{
  "success": true,
  "message": "API key created successfully",
  "api_key": "cfsd_zzzzzzzzzz",
  "api_secret": "aaaaaaaaaaaaaaaa",
  "warning": "Please save the api_secret, it will not be shown again"
}
```

⚠️ **重要：** `api_secret` 只显示一次，请妥善保存！

---

#### 3.3 删除API密钥

**端点：** `keys`  
**操作：** `delete`  
**方法：** `POST` 或 `DELETE`

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| key_id | integer | 是 | 密钥ID |

**请求示例：**
```bash
curl -X POST "https://您的域名/index.php?m=domain_hub&endpoint=keys&action=delete" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": 2
  }'
```

**响应示例：**
```json
{
  "success": true,
  "message": "API key deleted successfully"
}
```

---

#### 3.4 重新生成API密钥

**端点：** `keys`  
**操作：** `regenerate`  
**方法：** `POST`

**请求参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| key_id | integer | 是 | 密钥ID |

**请求示例：**
```bash
curl -X POST "https://您的域名/index.php?m=domain_hub&endpoint=keys&action=regenerate" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": 1
  }'
```

**响应示例：**
```json
{
  "success": true,
  "message": "API secret regenerated successfully",
  "api_key": "cfsd_xxxxxxxxxx",
  "api_secret": "new_secret_here",
  "warning": "Please save the new api_secret, it will not be shown again"
}
```

---

### 4. 配额查询

#### 4.1 查询配额

**端点：** `quota`  
**方法：** `GET`

**请求示例：**
```bash
curl -X GET "https://您的域名/index.php?m=domain_hub&endpoint=quota" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy"
```

**响应示例：**
```json
{
  "success": true,
  "quota": {
    "used": 3,
    "base": 5,
    "invite_bonus": 2,
    "total": 7,
    "available": 4
  }
}
```

---

## 错误代码

| HTTP状态码 | 说明 |
|-----------|------|
| 200 | 请求成功 |
| 400 | 请求参数错误 |
| 401 | 认证失败 |
| 403 | 权限不足或功能已禁用 |
| 404 | 资源不存在 |
| 429 | 请求频率超限 |
| 500 | 服务器内部错误 |

**错误响应示例：**
```json
{
  "error": "Invalid API key"
}
```

---

## 速率限制

**默认限制：** 60 请求/分钟

**响应头：**
- 请求响应中会包含速率限制信息

**超限响应示例：**
```json
{
  "error": "Rate limit exceeded",
  "limit": 60,
  "remaining": 0,
  "reset_at": "2025-10-19 15:31:00"
}
```

---

## SDK示例

### PHP示例

```php
<?php
class CloudflareSubdomainAPI {
    private $baseUrl;
    private $apiKey;
    private $apiSecret;
    
    public function __construct($baseUrl, $apiKey, $apiSecret) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->apiKey = $apiKey;
        $this->apiSecret = $apiSecret;
    }
    
    private function request($endpoint, $action, $method = 'GET', $data = []) {
        $url = $this->baseUrl . '?m=domain_hub&endpoint=' . $endpoint . '&action=' . $action;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'X-API-Key: ' . $this->apiKey,
            'X-API-Secret: ' . $this->apiSecret,
            'Content-Type: application/json'
        ]);
        
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return json_decode($response, true);
    }
    
    // 列出子域名
    public function listSubdomains() {
        return $this->request('subdomains', 'list', 'GET');
    }
    
    // 注册子域名
    public function registerSubdomain($subdomain, $rootdomain) {
        return $this->request('subdomains', 'register', 'POST', [
            'subdomain' => $subdomain,
            'rootdomain' => $rootdomain
        ]);
    }
    
    // 创建DNS记录
    public function createDnsRecord($subdomainId, $type, $content, $ttl = 600) {
        return $this->request('dns_records', 'create', 'POST', [
            'subdomain_id' => $subdomainId,
            'type' => $type,
            'content' => $content,
            'ttl' => $ttl
        ]);
    }
}

// 使用示例
$api = new CloudflareSubdomainAPI(
    'https://您的域名/index.php',
    'cfsd_xxxxxxxxxx',
    'yyyyyyyyyyyy'
);

// 列出子域名
$result = $api->listSubdomains();
print_r($result);

// 注册新子域名
$result = $api->registerSubdomain('myapp', 'example.com');
print_r($result);
```

### Python示例

```python
import requests
import json

class CloudflareSubdomainAPI:
    def __init__(self, base_url, api_key, api_secret):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.api_secret = api_secret
        self.headers = {
            'X-API-Key': api_key,
            'X-API-Secret': api_secret,
            'Content-Type': 'application/json'
        }
    
    def request(self, endpoint, action, method='GET', data=None):
        url = f"{self.base_url}?m=domain_hub&endpoint={endpoint}&action={action}"
        
        if method == 'GET':
            response = requests.get(url, headers=self.headers)
        else:
            response = requests.post(url, headers=self.headers, json=data)
        
        return response.json()
    
    def list_subdomains(self):
        return self.request('subdomains', 'list', 'GET')
    
    def register_subdomain(self, subdomain, rootdomain):
        return self.request('subdomains', 'register', 'POST', {
            'subdomain': subdomain,
            'rootdomain': rootdomain
        })
    
    def create_dns_record(self, subdomain_id, record_type, content, ttl=600):
        return self.request('dns_records', 'create', 'POST', {
            'subdomain_id': subdomain_id,
            'type': record_type,
            'content': content,
            'ttl': ttl
        })

# 使用示例
api = CloudflareSubdomainAPI(
    'https://您的域名/index.php',
    'cfsd_xxxxxxxxxx',
    'yyyyyyyyyyyy'
)

# 列出子域名
result = api.list_subdomains()
print(result)

# 注册新子域名
result = api.register_subdomain('myapp', 'example.com')
print(result)
```

### JavaScript示例

```javascript
class CloudflareSubdomainAPI {
    constructor(baseUrl, apiKey, apiSecret) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
    }
    
    async request(endpoint, action, method = 'GET', data = null) {
        const url = `${this.baseUrl}?m=domain_hub&endpoint=${endpoint}&action=${action}`;
        
        const options = {
            method: method,
            headers: {
                'X-API-Key': this.apiKey,
                'X-API-Secret': this.apiSecret,
                'Content-Type': 'application/json'
            }
        };
        
        if (method === 'POST' && data) {
            options.body = JSON.stringify(data);
        }
        
        const response = await fetch(url, options);
        return await response.json();
    }
    
    async listSubdomains() {
        return await this.request('subdomains', 'list', 'GET');
    }
    
    async registerSubdomain(subdomain, rootdomain) {
        return await this.request('subdomains', 'register', 'POST', {
            subdomain: subdomain,
            rootdomain: rootdomain
        });
    }
    
    async createDnsRecord(subdomainId, type, content, ttl = 600) {
        return await this.request('dns_records', 'create', 'POST', {
            subdomain_id: subdomainId,
            type: type,
            content: content,
            ttl: ttl
        });
    }
}

// 使用示例
const api = new CloudflareSubdomainAPI(
    'https://您的域名/index.php',
    'cfsd_xxxxxxxxxx',
    'yyyyyyyyyyyy'
);

// 列出子域名
api.listSubdomains().then(result => {
    console.log(result);
});

// 注册新子域名
api.registerSubdomain('myapp', 'example.com').then(result => {
    console.log(result);
});
```

---

## 6. WHOIS 查询（公开接口）

该接口用于对外查询已注册的二级域名基础信息。默认无需 API Key，系统会基于访问 IP 做速率限制（默认 2 次/分钟，可在后台“WHOIS 每分钟查询上限”中调整）。如需强制使用 API Key，可在后台开启“WHOIS 查询需要 API Key”开关。

- **端点：** `whois`
- **方法：** `GET`
- **参数：**
  | 参数 | 类型 | 必填 | 说明 |
  |------|------|------|------|
  | domain | string | 是 | 完整子域名，例如 `foo.example.com` |

**请求示例（公共模式）：**
```bash
curl -X GET "https://您的域名/index.php?m=domain_hub&endpoint=whois&domain=foo.example.com"
```

**请求示例（要求 API Key 时）：**
```bash
curl -X GET "https://您的域名/index.php?m=domain_hub&endpoint=whois&domain=foo.example.com" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy"
```

**响应示例（已注册）：**
```json
{
  "success": true,
  "domain": "foo.example.com",
  "status": "active",
  "registered_at": "2025-01-10 08:30:00",
  "expires_at": "2026-01-10 08:30:00",
  "registrant_email": "whois@example.com",
  "nameservers": [
    "ns1.example.net",
    "ns2.example.net"
  ],
  "rate_limit": {
    "limit": 2,
    "remaining": 1,
    "reset_at": "2025-01-10 08:31:00"
  }
}
```

**响应示例（未注册）：**
```json
{
  "success": true,
  "domain": "foo.example.com",
  "registered": false,
  "status": "unregistered",
  "message": "domain not registered"
}
```

> **说明：**
> - `registrant_email` 的内容取决于后台配置，可选择匿名邮箱、遮罩真实邮箱或显示真实邮箱。
> - `nameservers` 优先返回子域名实际的 NS 记录；若未设置 NS，则回退为后台配置的默认列表。
> - 永不过期的子域名会固定返回 `expires_at = 2099-12-31 23:59:59`，响应中不再包含 `never_expires` 字段。
> - 未注册域名会返回 `registered=false` 与 `status=unregistered`，同时附带查询的完整域名。
> - 当未启用 API Key 模式时，返回体中的 `rate_limit` 字段展示当前 IP 的剩余额度。

---

## 安全建议

1. **保护API密钥**
   - 不要在客户端代码中硬编码API密钥
   - 使用环境变量存储密钥
   - 定期轮换API密钥

2. **IP白名单**
   - 为生产环境密钥启用IP白名单
   - 只允许已知的服务器IP访问

3. **最小权限原则**
   - 为不同用途创建不同的API密钥
   - 及时删除不使用的密钥

4. **监控使用情况**
   - 定期检查API请求日志
   - 注意异常的请求模式

5. **HTTPS**
   - 始终使用HTTPS进行API调用
   - 避免在不安全的网络中传输密钥

---

## 常见问题

### Q1：API密钥丢失了怎么办？
A：可以使用 `regenerate` 操作重新生成密钥，旧密钥将失效。

### Q2：如何增加速率限制？
A：联系管理员在后台调整 "API请求速率限制" 设置。

### Q3：可以使用子账户的API密钥吗？
A：不可以，API密钥只能由主账户创建和使用。

### Q4：API支持批量操作吗？
A：目前不支持批量操作，需要逐个调用API。

### Q5：如何查看API使用统计？
A：在客户区的"API管理"卡片中可以查看每个密钥的使用次数和最后使用时间。

---

## 更新日志

### v1.0 (2025-10-19)
- 初始版本发布
- 支持子域名管理
- 支持DNS记录管理
- 支持API密钥管理
- 支持配额查询
- 支持速率限制

---

## 技术支持

如有问题，请联系系统管理员或查看插件文档。


