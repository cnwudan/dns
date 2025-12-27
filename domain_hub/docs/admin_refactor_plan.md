# Admin Template Refactor Plan

## 1. Functional Blocks & Dependencies

| Block | Purpose | Key Variables | Primary Tables / Helpers |
| --- | --- | --- | --- |
| CSRF bootstrap & globals | Generates/administers `CFMOD_SAFE_JSON_FLAGS`, injects admin CSRF token, aborts invalid POST | `$cfmodAdminCsrfToken`, `$_SERVER`, `$_SESSION['cfmod_admin_csrf']` | `cfmod_admin_current_url_without_action()` (indirect `$_SERVER`), session state |
| API key management | Handles `admin_create_api_key`, rate limit updates, quota changes, success/error flashes; UI end currently rendered via `partials/api_management.tpl` | `$apiSectionShouldExpand`, `$allApiKeysArray`, `$apiLogs`, `$apiPagination`, `$apiStats` | `tblclients`, `mod_cloudflare_api_keys`, `mod_cloudflare_api_logs`, `mod_cloudflare_subdomain_quotas` |
| Privileged users & quotas | Add/remove privileged users, adjust per-user quota/bonus, show latest operations | `$privilegedUsers`, `$userQuota`, `$banState`, `$quota` | `tblclients`, `mod_cloudflare_special_users`, `mod_cloudflare_subdomain_quotas` |
| Provider accounts | CRUD provider accounts, enable/disable, set default, test credentials | `$providers`, `$defaultProviderId`, `$providerTestResult` | `mod_cloudflare_provider_accounts`, `tbladdonmodules`, encryption helpers |
| Root domains & forbidden list | Manage allowed root domains, per-user limits, import/export, blacklist | `$rootdomains`, `$rootdomainLimits`, `$forbiddenDomains`, `$imports` | `mod_cloudflare_rootdomains`, `mod_cloudflare_subdomain`, `mod_cloudflare_forbidden_domains` |
| Domain gifts / locks | View/cancel pending domain gifts, manually unlock stuck locks | `$domainGifts`, `$giftLocks` | `mod_cloudflare_domain_gifts`, `mod_cloudflare_subdomain` |
| User bans & DNS enforcement | Create/list bans, enforce/undo DNS takedown, record operations | `$bannedUsers`, `$banStats`, `$enforceResults` | `mod_cloudflare_user_bans`, `mod_cloudflare_subdomain`, `mod_cloudflare_dns_records` |
| Invite leaderboard & rewards | Maintain leaderboard entries, reward definitions, rebuild/settle snapshots | `$leaderboard`, `$inviteRewards`, `$rewardSnapshots` | `mod_cloudflare_invite_leaderboard`, `mod_cloudflare_invite_rewards`, `mod_cloudflare_invitation_claims` |
| Job queue / runtime tools | View recent jobs, retry/cancel, enqueue calibration/risk/reconcile, run worker once, toggle runtime flags | `$recentJobs`, `$runtimeSwitches`, `$queueBacklog` | `mod_cloudflare_jobs`, queue helpers |
| Admin announcements | Read/write `admin_announce_*` settings and present modal | `$admin_announce_enabled`, `$admin_announce_title`, `$admin_announce_html` | `tbladdonmodules` |
| Risk monitor & suspicious domains | Trigger risk scans, show suspicious subdomains, toggle status | `$riskStats`, `$suspiciousSubdomains` | `mod_cloudflare_risk_events`, `mod_cloudflare_subdomain` |
| Misc maintenance | Reset module, purge local data, export/import | Buttons referencing helpers (`cloudflare_subdomain_log`, worker enqueue) | `cloudflare_subdomain_log`, `run_cf_queue_once`, etc. |

## 2. `$_POST['action']` Entry Points

- `admin_create_api_key`
- `admin_set_rate_limit`
- `admin_set_user_quota`
- `admin_add_privileged_user`
- `admin_remove_privileged_user`
- `admin_provider_create`
- `admin_provider_update`
- `admin_provider_toggle_status`
- `admin_provider_set_default`
- `admin_provider_test`
- `admin_provider_delete`
- `add_rootdomain`
- `admin_rootdomain_update`
- `delete_rootdomain`
- `set_rootdomain_status`
- `set_rootdomain_limit`
- `replace_rootdomain`
- `export_rootdomain`
- `import_rootdomain`
- `add_forbidden`
- `admin_cancel_domain_gift`
- `admin_unlock_domain_gift_lock`
- `ban_user`
- `unban_user`
- `enforce_ban_dns`
- `update_user_quota`
- `update_user_invite_limit`
- `admin_adjust_expiry`
- `admin_edit_leaderboard_user`
- `mark_reward_claimed`
- `remove_leaderboard_user`
- `admin_upsert_invite_reward`
- `admin_rebuild_invite_rewards`
- `admin_settle_last_period`
- `job_retry`
- `job_cancel`
- `run_queue_once`
- `enqueue_reconcile`
- `enqueue_calibration`
- `enqueue_risk_scan`
- `save_runtime_switches`
- `reset_module`
- `purge_rootdomain_local`
- `batch_delete`
- `delete` (per-row variants)
- `save_admin_announce`
- `toggle_subdomain_status`

(Plus older `admin_*` actions handled in `CfAdminController::handleAction()` switch cases; ensure parity.)

## 3. Session / Flash Usage

- Success messages stored in `$_SESSION['admin_api_success']`
- Error messages stored in `$_SESSION['admin_api_error']`
- Other temporary data pulled from session (e.g., `$_SESSION['adminid']` when logging operations)

**Plan:** Controller handles POST, sets flash values, and after building `$viewModel['alerts']`, clears the session keys so alerts render once. `partials/alerts.tpl` will read from `$cfAdminViewModel['alerts']` only.

## 4. Capsule/Table Touch Points (Grouped)

- **WHMCS core**: `tblclients`, `tbladdonmodules`, `tblcredit`
- **API**: `mod_cloudflare_api_keys`, `mod_cloudflare_api_logs`
- **Subdomain/Quota**: `mod_cloudflare_subdomain`, `mod_cloudflare_subdomain_quotas`, `mod_cloudflare_dns_records`
- **Providers**: `mod_cloudflare_provider_accounts`
- **Root domains & forbidden**: `mod_cloudflare_rootdomains`, `mod_cloudflare_forbidden_domains`
- **Domain gifts**: `mod_cloudflare_domain_gifts`
- **User bans**: `mod_cloudflare_user_bans`
- **Jobs/Queue**: `mod_cloudflare_jobs`
- **Invites**: `mod_cloudflare_invitation_codes`, `mod_cloudflare_invitation_claims`, `mod_cloudflare_invite_rewards`, `mod_cloudflare_invite_leaderboard`
- **Risk**: `mod_cloudflare_risk_events`, `mod_cloudflare_domain_risk`

Each grouping should be wrapped via controller/service before feeding to templates.

## 5. ViewModel Structure (Example)

```php
$cfAdminViewModel = [
    'alerts' => [
        'success' => $_SESSION['admin_api_success'] ?? null,
        'error'   => $_SESSION['admin_api_error'] ?? null,
    ],
    'stats' => [...],
    'providers' => [...],
    'rootdomains' => [...],
    'privileged' => [...],
    'quotas' => [...],
    'jobs' => [...],
    'announcements' => [...],
    'invites' => [...],
    'bans' => [...],
    'gifts' => [...],
    'risk' => [...],
    'api' => $this->buildApiViewModel(),
];
```

Populate each key via `CfAdminController::buildViewModel()` or auxiliary services, then clear the session flashes before rendering.

## 6. Partial Directory Layout
```
templates/admin/
partials/
alerts.tpl
stats_cards.tpl
announcements.tpl *(已拆分，依赖 ViewModel['announcements']，Lang 键: domainHub.announcement_*)*
provider_accounts.tpl
rootdomains/
list.tpl
form.tpl
forbidden.tpl
privileged_users.tpl
user_quotas.tpl
invite_rewards.tpl
job_queue.tpl
runtime_tools.tpl *(已拆分，使用 ViewModel['runtime'] + `$module_settings` 指示)*
banned_users.tpl *(已拆分，消费 ViewModel['bans']，表单统一走 CfAdminActionService)*
domain_gifts.tpl *(已拆分，使用 ViewModel['domainGifts']，保留原过滤/分页参数)*
risk_monitor.tpl *(已拆分，消费 ViewModel['risk']，触发按钮走 CfAdminActionService)*
logs.tpl
api_management.tpl   # existing
```
## 7. Include Order Inside `admin.tpl`
```php

<?php include __DIR__ . '/admin/partials/alerts.tpl'; ?>
<?php include __DIR__ . '/admin/partials/stats_cards.tpl'; ?>
<?php include __DIR__ . '/admin/partials/announcements.tpl'; ?>
<?php include __DIR__ . '/admin/partials/provider_accounts.tpl'; ?>
<?php include __DIR__ . '/admin/partials/rootdomains/list.tpl'; ?>
<?php include __DIR__ . '/admin/partials/rootdomains/form.tpl'; ?>
<?php include __DIR__ . '/admin/partials/rootdomains/forbidden.tpl'; ?>
<?php include __DIR__ . '/admin/partials/privileged_users.tpl'; ?>
<?php include __DIR__ . '/admin/partials/user_quotas.tpl'; ?>
<?php include __DIR__ . '/admin/partials/invite_rewards.tpl'; ?>
<?php include __DIR__ . '/admin/partials/job_queue.tpl'; ?>
<?php include __DIR__ . '/admin/partials/runtime_tools.tpl'; ?>
<?php include __DIR__ . '/admin/partials/banned_users.tpl'; ?>
<?php include __DIR__ . '/admin/partials/domain_gifts.tpl'; ?>
<?php include __DIR__ . '/admin/partials/risk_monitor.tpl'; ?>
<?php include __DIR__ . '/admin/partials/logs.tpl'; ?>
<?php include __DIR__ . '/admin/partials/api_management.tpl'; ?>
```

Adjust order to match UI priorities，并在新增区块前确认对应 ViewModel 数据结构已准备。当前已完成：公告、运行控制、封禁管理、域名转赠、风险监控。

### ViewModel 键值参考
- `announcements` => `['enabled','title','html']`
- `runtime` => `['rootdomains' => [...]]` + `$module_settings`
- `bans` => `['items' => [...]]`
- `domainGifts` => `['statusOptions','filters','pagination','rows','users']`
- `risk` => `['top','trend','list','events','log','filters']`


## 8. Implementation Checklist

1. **One block at a time** – move HTML to partial, load data via view model, and test before proceeding.
2. **Preserve form fields** – keep `name="action"` and related inputs intact so `handleAction()` continues to work.
3. **Consolidate JS** – relocate scattered `<script>` tags into either the relevant partial or a footer block.
4. **Bootstrap compatibility** – ensure whichever Bootstrap version is used is actually loaded.
5. **Language keys** – migrate literal strings to `$LANG['cfadmin'][...]` for future localization.

## 9. Deployment Notes
- 部署此版本需要与 `lib/Http` 与 `lib/Services` 中的控制器 / Service 更新保持同步（例如 `CfAdminController`、`CfAdminActionService`、`CfAdminViewModelBuilder`）。
- 依赖 PHP 7.4 及以上版本（闭包类型提示、`JSON_*` 常量、空合并运算符等），部署前确认运行环境满足要求。

This document captures everything needed to begin the refactor while maintaining backward compatibility.
