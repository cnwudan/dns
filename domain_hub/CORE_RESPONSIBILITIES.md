# Core Responsibilities Overview

| Responsibility | Description | Primary Locations (pre-refactor) |
| --- | --- | --- |
| Configuration load & cache | 负责从 `tbladdonmodules` 读取配置、处理默认值、同步/迁移旧配置 | `domain_hub.php` – `cf_get_module_settings_cached`, `cf_clear_settings_cache` |
| CSRF & security helpers | 生成/校验客户端与管理员 CSRF Token，提供基础安全工具 | `domain_hub.php` – `cfmod_is_valid_csrf_token`, `cfmod_ensure_client_csrf_seed`, `cfmod_validate_client_csrf`, `cfmod_ensure_admin_csrf_seed`, `cfmod_validate_admin_csrf` |
| Root Domain management | 维护根域列表、限制、同步 Cloudflare/AliDNS 信息 | `domain_hub.php` – root domain helper functions (e.g., `cfmod_get_known_rootdomains`) |
| Provider resolution | 解析/缓存 DNS 提供商账号、分配默认账号 | `lib/ProviderResolver.php`, `domain_hub.php` provider helper functions |
| Subdomain & quota logic | 子域注册、配额校验、赠送域名、前缀校验等 | `domain_hub.php`, `lib/AtomicOperations.php`, Templates (admin/client) |
| Logging & auditing | 插入操作日志、异常记录、调度结果 | `domain_hub.php` logging helpers, `hooks.php`, `worker.php` |
| API detection & dispatch | 判定是否为 API 请求并交由 `api_handler.php` 处理 | `domain_hub.php` – `cf_is_api_request`, `cf_dispatch_api_request` |
| Hook/queue & worker interaction | Cron Hook、队列任务 enqueue/执行、清理逻辑 | `hooks.php`, `worker.php`, `domain_hub.php` queue helpers |
