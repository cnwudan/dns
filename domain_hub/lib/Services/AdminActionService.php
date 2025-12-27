<?php
// phpcs:ignoreFile

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfAdminActionService
{
    private const HASH_PROVIDER = '#providerAccounts';
    private const ORPHAN_CURSOR_SETTING_KEY = 'orphan_scan_cursors';
    private const ORPHAN_CURSOR_DEFAULT_KEY = '__default__';

    private static $orphanCursorCache = null;
    private const HASH_ROOT_WHITELIST = '#rootdomainWhitelist';
    private const HASH_ROOT_REPLACE = '#rootdomainReplace';
    private const HASH_FORBIDDEN = '#forbiddenDomains';
    private const HASH_JOBS = '#queue-management';
    private const HASH_DOMAIN_GIFTS = '#domainGiftRecords';
    private const HASH_INVITE = '#invite_stats';
    private const HASH_SNAPSHOTS = '#snapshots';
    private const HASH_RUNTIME = '#runtime-control';
    private const HASH_ANNOUNCEMENTS = '#admin-announcements';
    private const HASH_BANS = '#ban-management';
    private const HASH_RISK_MONITOR = '#risk-monitor';
    private const HASH_PRIVILEGED = '#privileged';
    private const HASH_QUOTAS = '#quotas';
    private const HASH_SUBDOMAINS = '#subdomains';

    /**
     * @var array<string, callable>
     */
    private static array $handlers = [
        'admin_provider_create' => [self::class, 'handleProviderCreate'],
        'admin_provider_update' => [self::class, 'handleProviderUpdate'],
        'admin_provider_toggle_status' => [self::class, 'handleProviderToggleStatus'],
        'admin_provider_delete' => [self::class, 'handleProviderDelete'],
        'admin_provider_set_default' => [self::class, 'handleProviderSetDefault'],
        'admin_provider_test' => [self::class, 'handleProviderTest'],
        'add_rootdomain' => [self::class, 'handleRootdomainAdd'],
        'delete_rootdomain' => [self::class, 'handleRootdomainDelete'],
        'toggle_rootdomain' => [self::class, 'handleRootdomainToggle'],
        'set_rootdomain_status' => [self::class, 'handleRootdomainSetStatus'],
        'set_rootdomain_limit' => [self::class, 'handleRootdomainSetLimit'],
        'update_rootdomain_order' => [self::class, 'handleRootdomainOrderUpdate'],
        'admin_rootdomain_update' => [self::class, 'handleRootdomainUpdate'],
        'transfer_rootdomain_provider' => [self::class, 'handleRootdomainTransfer'],
        'replace_rootdomain' => [self::class, 'handleRootdomainReplace'],
        'export_rootdomain' => [self::class, 'handleRootdomainExport'],
        'import_rootdomain' => [self::class, 'handleRootdomainImport'],
        'purge_rootdomain_local' => [self::class, 'handleRootdomainPurgeLocal'],
        'add_forbidden' => [self::class, 'handleForbiddenAdd'],
        'delete_forbidden' => [self::class, 'handleForbiddenDelete'],
        'toggle_subdomain_status' => [self::class, 'handleToggleSubdomainStatus'],
        'admin_toggle_subdomain_status' => [self::class, 'handleToggleSubdomainStatus'],
        'admin_delete_subdomain' => [self::class, 'handleDeleteSubdomain'],
        'delete' => [self::class, 'handleDeleteSubdomain'],
        'admin_regen_subdomain' => [self::class, 'handleSubdomainRegenerate'],
        'regen' => [self::class, 'handleSubdomainRegenerate'],
        'admin_cancel_domain_gift' => [self::class, 'handleDomainGiftCancel'],
        'admin_unlock_domain_gift_lock' => [self::class, 'handleDomainGiftUnlock'],
        'save_runtime_switches' => [self::class, 'handleRuntimeSwitches'],
        'admin_toggle_quota_redeem' => [self::class, 'handleToggleQuotaRedeem'],
        'admin_create_redeem_code' => [self::class, 'handleCreateRedeemCode'],
        'admin_generate_redeem_codes' => [self::class, 'handleGenerateRedeemCodes'],
        'admin_toggle_redeem_code_status' => [self::class, 'handleToggleRedeemCodeStatus'],
        'admin_delete_redeem_code' => [self::class, 'handleDeleteRedeemCode'],
        'save_admin_announce' => [self::class, 'handleSaveAdminAnnounce'],
        'job_retry' => [self::class, 'handleJobRetry'],
        'job_cancel' => [self::class, 'handleJobCancel'],
        'enqueue_calibration' => [self::class, 'handleEnqueueCalibration'],
        'enqueue_root_calibration' => [self::class, 'handleEnqueueRootCalibration'],
        'enqueue_risk_scan' => [self::class, 'handleEnqueueRiskScan'],
        'enqueue_reconcile' => [self::class, 'handleEnqueueReconcile'],
        'run_queue_once' => [self::class, 'handleRunQueueOnce'],
        'run_migrations' => [self::class, 'handleRunMigrations'],
        'ban_user' => [self::class, 'handleBanUser'],
        'unban_user' => [self::class, 'handleUnbanUser'],
        'enforce_ban_dns' => [self::class, 'handleEnforceBanDns'],
        'save_invite_cycle_start' => [self::class, 'handleSaveInviteCycleStart'],
        'save_leaderboard_display' => [self::class, 'handleSaveLeaderboardDisplay'],
        'mark_reward_claimed' => [self::class, 'handleMarkRewardClaimed'],
        'admin_upsert_invite_reward' => [self::class, 'handleAdminUpsertInviteReward'],
        'admin_rebuild_invite_rewards' => [self::class, 'handleAdminRebuildInviteRewards'],
        'admin_settle_last_period' => [self::class, 'handleAdminSettleLastPeriod'],
        'generate_invite_snapshot' => [self::class, 'handleGenerateInviteSnapshot'],
        'remove_leaderboard_user' => [self::class, 'handleRemoveLeaderboardUser'],
        'admin_edit_leaderboard_user' => [self::class, 'handleAdminEditLeaderboardUser'],
        'update_user_invite_limit' => [self::class, 'handleUpdateUserInviteLimit'],
        'admin_add_privileged_user' => [self::class, 'handleAddPrivilegedUser'],
        'admin_remove_privileged_user' => [self::class, 'handleRemovePrivilegedUser'],
        'admin_set_user_quota' => [self::class, 'handleAdminSetUserQuota'],
        'update_user_quota' => [self::class, 'handleUpdateUserQuota'],
        'admin_adjust_expiry' => [self::class, 'handleAdminAdjustExpiry'],
        'reset_module' => [self::class, 'handleResetModule'],
        'batch_delete' => [self::class, 'handleBatchDelete'],
        'scan_orphan_records' => [self::class, 'handleScanOrphanRecords'],
    ];

    public static function supports(string $action): bool
    {
        return isset(self::$handlers[$action]);
    }

    public static function handle(string $action): void
    {
        $handler = self::$handlers[$action] ?? null;
        if ($handler === null) {
            return;
        }

        try {
            self::enforceRateLimitForAction($action);
        } catch (CfRateLimitExceededException $e) {
            self::flashError(self::formatRateLimitMessage($e->getRetryAfterSeconds()));
            self::redirect();
        }

        call_user_func($handler);
    }

    private static function triggerQueueInBackground(int $maxJobs = 1): void
    {
        $worker = __DIR__ . '/../worker.php';
        if (!file_exists($worker)) {
            return;
        }
        $phpBinary = defined('PHP_BINARY') ? PHP_BINARY : 'php';
        $maxJobs = max(1, (int) $maxJobs);
        $cmd = escapeshellarg($phpBinary) . ' ' . escapeshellarg($worker) . ' ' . $maxJobs . ' > /dev/null 2>&1 &';
        @exec($cmd);
    }

    private static function handleProviderCreate(): void
    {
        try {
            self::ensureProviderSchema();
            $name = trim($_POST['provider_name'] ?? '');
            if ($name === '') {
                throw new Exception('请输入账户名称');
            }
            $accessKeyId = trim($_POST['access_key_id'] ?? '');
            if ($accessKeyId === '') {
                throw new Exception('AccessKey ID 不能为空');
            }
            $accessKeySecret = trim($_POST['access_key_secret'] ?? '');
            if ($accessKeySecret === '') {
                throw new Exception('AccessKey Secret 不能为空');
            }
            $providerType = strtolower(trim($_POST['provider_type'] ?? 'alidns')) ?: 'alidns';
            $rateLimit = max(1, intval($_POST['provider_rate_limit'] ?? 60));
            $notes = trim($_POST['provider_notes'] ?? '');
            if ($notes !== '') {
                $notes = function_exists('mb_substr')
                    ? mb_substr($notes, 0, 500, 'UTF-8')
                    : substr($notes, 0, 500);
            } else {
                $notes = null;
            }
            $setAsDefault = ($_POST['set_as_default'] ?? '') === '1';
            $table = cfmod_get_provider_table_name();
            $now = date('Y-m-d H:i:s');
            $providerId = Capsule::table($table)->insertGetId([
                'name' => $name,
                'provider_type' => $providerType,
                'access_key_id' => $accessKeyId,
                'access_key_secret' => cfmod_encrypt_sensitive($accessKeySecret),
                'status' => 'active',
                'is_default' => $setAsDefault ? 1 : 0,
                'rate_limit' => $rateLimit,
                'notes' => $notes,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            if ($setAsDefault) {
                if (!cfmod_set_default_provider_account($providerId)) {
                    throw new Exception('账号已创建，但设置默认失败，请稍后重试');
                }
            } else {
                cf_clear_settings_cache();
            }
            self::flashSuccess('✅ 已新增供应商账号 <strong>' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</strong>');
        } catch (Exception $e) {
            self::flashError('❌ 新增供应商失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_PROVIDER);
    }

    private static function handleProviderUpdate(): void
    {
        try {
            self::ensureProviderSchema();
            $providerId = intval($_POST['provider_id'] ?? 0);
            if ($providerId <= 0) {
                throw new Exception('参数无效');
            }
            $table = cfmod_get_provider_table_name();
            $existingProvider = Capsule::table($table)->where('id', $providerId)->first();
            if (!$existingProvider) {
                throw new Exception('供应商不存在');
            }
            $name = trim($_POST['provider_name'] ?? '');
            if ($name === '') {
                throw new Exception('请输入账户名称');
            }
            $accessKeyId = trim($_POST['access_key_id'] ?? '');
            if ($accessKeyId === '') {
                throw new Exception('AccessKey ID 不能为空');
            }
            $providerType = strtolower(trim($_POST['provider_type'] ?? 'alidns')) ?: 'alidns';
            $rateLimit = max(1, intval($_POST['provider_rate_limit'] ?? 60));
            $notesUpdate = trim($_POST['provider_notes'] ?? '');
            if ($notesUpdate !== '') {
                $notesUpdate = function_exists('mb_substr')
                    ? mb_substr($notesUpdate, 0, 500, 'UTF-8')
                    : substr($notesUpdate, 0, 500);
            } else {
                $notesUpdate = null;
            }
            $updateData = [
                'name' => $name,
                'provider_type' => $providerType,
                'access_key_id' => $accessKeyId,
                'rate_limit' => $rateLimit,
                'notes' => $notesUpdate,
                'updated_at' => date('Y-m-d H:i:s'),
            ];
            $newSecret = trim($_POST['access_key_secret'] ?? '');
            if ($newSecret !== '') {
                $updateData['access_key_secret'] = cfmod_encrypt_sensitive($newSecret);
            }
            Capsule::table($table)->where('id', $providerId)->update($updateData);
            $setAsDefault = ($_POST['set_as_default'] ?? '') === '1';
            if ($setAsDefault) {
                if (!cfmod_set_default_provider_account($providerId)) {
                    throw new Exception('账号已更新，但设置默认失败，请稍后重试');
                }
            } else {
                cf_clear_settings_cache();
            }
            self::flashSuccess('✅ 已更新供应商账号 <strong>' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</strong>');
        } catch (Exception $e) {
            self::flashError('❌ 更新供应商失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_PROVIDER);
    }

    private static function handleProviderToggleStatus(): void
    {
        try {
            self::ensureProviderSchema();
            $providerId = intval($_POST['provider_id'] ?? 0);
            if ($providerId <= 0) {
                throw new Exception('参数无效');
            }
            $targetStatus = ($_POST['target_status'] ?? '') === 'active' ? 'active' : 'disabled';
            $table = cfmod_get_provider_table_name();
            $providerRow = Capsule::table($table)->where('id', $providerId)->first();
            if (!$providerRow) {
                throw new Exception('供应商不存在');
            }
            $isDefault = intval($providerRow->is_default ?? 0) === 1;
            if ($isDefault && $targetStatus !== 'active') {
                throw new Exception('请先设置其他账号为默认后再停用当前账号');
            }
            Capsule::table($table)->where('id', $providerId)->update([
                'status' => $targetStatus,
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            cf_clear_settings_cache();
            self::flashSuccess($targetStatus === 'active' ? '✅ 已启用该供应商账号' : '✅ 已停用该供应商账号');
        } catch (Exception $e) {
            self::flashError('❌ 更新状态失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_PROVIDER);
    }

    private static function handleProviderDelete(): void
    {
        try {
            self::ensureProviderSchema();
            $providerId = intval($_POST['provider_id'] ?? 0);
            if ($providerId <= 0) {
                throw new Exception('参数无效');
            }
            $table = cfmod_get_provider_table_name();
            $providerRow = Capsule::table($table)->where('id', $providerId)->first();
            if (!$providerRow) {
                throw new Exception('供应商不存在');
            }
            if (intval($providerRow->is_default ?? 0) === 1) {
                throw new Exception('无法删除默认账号，请先切换默认账号');
            }
            $boundRoots = Capsule::table('mod_cloudflare_rootdomains')->where('provider_account_id', $providerId)->count();
            if ($boundRoots > 0) {
                throw new Exception('仍有 ' . $boundRoots . ' 个根域名绑定该账号，请先迁移');
            }
            Capsule::table($table)->where('id', $providerId)->delete();
            $defaultProviderAccountId = self::getDefaultProviderAccountId();
            if ($defaultProviderAccountId === $providerId) {
                $newDefault = cfmod_get_active_provider_account(null, false, true);
                if ($newDefault) {
                    $defaultProviderAccountId = intval($newDefault['id']);
                    Capsule::table('tbladdonmodules')->updateOrInsert([
                        'module' => CF_MODULE_NAME,
                        'setting' => 'default_provider_account_id'
                    ], ['value' => $defaultProviderAccountId]);
                } else {
                    Capsule::table('tbladdonmodules')
                        ->where('module', CF_MODULE_NAME)
                        ->where('setting', 'default_provider_account_id')
                        ->delete();
                }
            }
            cf_clear_settings_cache();
            self::flashSuccess('✅ 已删除该供应商账号');
        } catch (Exception $e) {
            self::flashError('❌ 删除失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_PROVIDER);
    }

    private static function handleProviderSetDefault(): void
    {
        try {
            $providerId = intval($_POST['provider_id'] ?? 0);
            if ($providerId <= 0) {
                throw new Exception('参数无效');
            }
            if (!cfmod_set_default_provider_account($providerId)) {
                throw new Exception('设置默认失败，请稍后重试');
            }
            self::flashSuccess('✅ 默认供应商账户已更新');
        } catch (Exception $e) {
            self::flashError('❌ 设置默认失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_PROVIDER);
    }

    private static function handleProviderTest(): void
    {
        try {
            self::ensureProviderSchema();
            $providerId = intval($_POST['provider_id'] ?? 0);
            if ($providerId <= 0) {
                throw new Exception('参数无效');
            }
            $providerAccount = cfmod_get_provider_account($providerId, true);
            if (!$providerAccount) {
                throw new Exception('供应商不存在');
            }
            $accessKeyId = trim((string) ($providerAccount['access_key_id'] ?? ''));
            $accessKeySecret = trim((string) ($providerAccount['access_key_secret'] ?? ''));
            if ($accessKeyId === '' || $accessKeySecret === '') {
                throw new Exception('凭据不完整，无法测试');
            }
            $settingsSnapshot = function_exists('cf_get_module_settings_cached') ? cf_get_module_settings_cached() : [];
            $context = cfmod_make_provider_client($providerId, null, null, $settingsSnapshot);
            if (!$context || empty($context['client'])) {
                throw new Exception('无法初始化供应商客户端，请检查凭据是否正确');
            }
            $tester = $context['client'];
            if (!method_exists($tester, 'validateCredentials')) {
                throw new Exception('该供应商暂不支持连通性测试');
            }
            if ($tester->validateCredentials()) {
                $labels = self::providerTypeLabels();
                $typeKey = strtolower($providerAccount['provider_type'] ?? 'alidns');
                $label = $labels[$typeKey] ?? strtoupper($typeKey);
                self::flashSuccess('✅ 凭据验证通过，可以正常连接 ' . htmlspecialchars($label, ENT_QUOTES, 'UTF-8'));
            } else {
                throw new Exception('API 验证失败，请检查凭据');
            }
        } catch (Exception $e) {
            self::flashError('❌ 连通性测试失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_PROVIDER);
    }

    private static function handleRootdomainAdd(): void
    {
        try {
            $newDomain = strtolower(trim($_POST['domain'] ?? ''));
            $description = trim($_POST['description'] ?? '');
            $maxSubdomains = intval($_POST['max_subdomains'] ?? 1000);
            if ($maxSubdomains <= 0) {
                $maxSubdomains = 1000;
            }
            $defaultTermYears = intval($_POST['default_term_years'] ?? 0);
            if ($defaultTermYears < 0) {
                $defaultTermYears = 0;
            }
            if ($newDomain === '') {
                throw new Exception('请输入根域名');
            }
            $providerAccount = self::resolveProviderAccount(intval($_POST['provider_account_id'] ?? 0), true);
            if (!$providerAccount) {
                throw new Exception('请选择有效的 DNS 供应商账号');
            }
            $providerAccountId = intval($providerAccount['id']);
            $exists = Capsule::table('mod_cloudflare_rootdomains')->whereRaw('LOWER(domain)=?', [$newDomain])->count();
            if ($exists > 0) {
                throw new Exception('根域名已存在');
            }
            $zoneId = null;
            try {
                $cf = new CloudflareAPI($providerAccount['access_key_id'] ?? '', $providerAccount['access_key_secret'] ?? '');
                $zoneId = $cf->getZoneId($newDomain) ?: null;
            } catch (Exception $e) {
                $zoneId = null;
            }
            Capsule::table('mod_cloudflare_rootdomains')->insert([
                'domain' => $newDomain,
                'cloudflare_zone_id' => $zoneId,
                'status' => 'active',
                'display_order' => self::resolveNextRootdomainOrderValue(),
                'description' => $description,
                'max_subdomains' => $maxSubdomains,
                'per_user_limit' => 0,
                'default_term_years' => $defaultTermYears,
                'provider_account_id' => $providerAccountId,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ]);
            if (function_exists('cfmod_clear_rootdomain_limits_cache')) {
                cfmod_clear_rootdomain_limits_cache();
            }
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_add_rootdomain', [
                    'domain' => $newDomain,
                    'zone' => $zoneId,
                    'description' => $description,
                    'max_subdomains' => $maxSubdomains,
                    'default_term_years' => $defaultTermYears,
                    'provider_account_id' => $providerAccountId,
                ]);
            }
            self::flashSuccess('根域名已添加');
        } catch (Exception $e) {
            self::flashError('添加根域名失败：' . $e->getMessage());
        }
        self::redirect(self::HASH_ROOT_WHITELIST);
    }

    private static function handleRootdomainDelete(): void
    {
        $id = intval($_POST['id'] ?? ($_GET['id'] ?? 0));
        if ($id <= 0) {
            self::flashError('参数无效');
            self::redirect(self::HASH_ROOT_WHITELIST);
        }
        $row = Capsule::table('mod_cloudflare_rootdomains')->where('id', $id)->first();
        Capsule::table('mod_cloudflare_rootdomains')->where('id', $id)->delete();
        if (function_exists('cfmod_clear_rootdomain_limits_cache')) {
            cfmod_clear_rootdomain_limits_cache();
        }
        if ($row && function_exists('cloudflare_subdomain_log')) {
            cloudflare_subdomain_log('admin_delete_rootdomain', ['domain' => $row->domain ?? null]);
        }
        self::flashSuccess('根域名已删除');
        self::redirect(self::HASH_ROOT_WHITELIST);
    }

    private static function handleRootdomainToggle(): void
    {
        $id = intval($_POST['id'] ?? ($_GET['id'] ?? 0));
        if ($id <= 0) {
            self::flashError('参数无效');
            self::redirect(self::HASH_ROOT_WHITELIST);
        }
        $row = Capsule::table('mod_cloudflare_rootdomains')->where('id', $id)->first();
        if ($row) {
            $newStatus = $row->status === 'active' ? 'suspended' : 'active';
            Capsule::table('mod_cloudflare_rootdomains')->where('id', $id)->update([
                'status' => $newStatus,
                'updated_at' => date('Y-m-d H:i:s')
            ]);
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_toggle_rootdomain', ['domain' => $row->domain, 'status' => $newStatus]);
            }
            self::flashSuccess('根域名状态已更新');
        }
        self::redirect(self::HASH_ROOT_WHITELIST);
    }

    private static function handleRootdomainSetStatus(): void
    {
        $sel = trim($_POST['rootdomain_id'] ?? '');
        $newStatus = (($_POST['new_status'] ?? '') === 'active') ? 'active' : 'suspended';
        if ($sel === '') {
            self::flashError('参数无效：缺少根域名');
            self::redirect(self::HASH_ROOT_WHITELIST);
        }
        if (preg_match('/^id-(\d+)$/', $sel, $m)) {
            $rid = intval($m[1]);
            $row = Capsule::table('mod_cloudflare_rootdomains')->where('id', $rid)->first();
            if ($row) {
                Capsule::table('mod_cloudflare_rootdomains')->where('id', $rid)->update([
                    'status' => $newStatus,
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('admin_set_rootdomain_status', ['domain' => $row->domain, 'status' => $newStatus]);
                }
                self::flashSuccess('已更新根域名状态');
            } else {
                self::flashError('未找到该根域名');
            }
        } else {
            self::flashError('参数无效：未知选择器');
        }
        self::redirect(self::HASH_ROOT_WHITELIST);
    }

    private static function handleRootdomainSetLimit(): void
    {
        $sel = trim($_POST['rootdomain_id'] ?? '');
        $limitRaw = $_POST['per_user_limit'] ?? '0';
        $limitValue = is_numeric($limitRaw) ? intval($limitRaw) : 0;
        if ($limitValue < 0) {
            $limitValue = 0;
        }
        if ($sel === '') {
            self::flashError('参数无效：缺少根域名');
            self::redirect(self::HASH_ROOT_WHITELIST);
        }
        if (preg_match('/^id-(\d+)$/', $sel, $m)) {
            $rid = intval($m[1]);
            $row = Capsule::table('mod_cloudflare_rootdomains')->where('id', $rid)->first();
            if ($row) {
                Capsule::table('mod_cloudflare_rootdomains')->where('id', $rid)->update([
                    'per_user_limit' => $limitValue,
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                if (function_exists('cfmod_clear_rootdomain_limits_cache')) {
                    cfmod_clear_rootdomain_limits_cache();
                }
                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('admin_set_rootdomain_limit', ['domain' => $row->domain, 'per_user_limit' => $limitValue]);
                }
                if ($limitValue > 0) {
                    $message = cfmod_format_rootdomain_limit_message($row->domain, $limitValue);
                } else {
                    $message = '已取消 ' . $row->domain . ' 的单用户注册限制';
                }
                self::flash($message ?: '单用户上限已更新', 'success');
            } else {
                self::flashError('未找到该根域名');
            }
        } else {
            self::flashError('参数无效：未知选择器');
        }
        self::redirect(self::HASH_ROOT_WHITELIST);
    }

    private static function handleRootdomainOrderUpdate(): void
    {
        $orders = $_POST['display_order'] ?? [];
        if (!is_array($orders) || empty($orders)) {
            self::flashError('未提交排序数据');
            self::redirect(self::HASH_ROOT_WHITELIST);
        }
        $sanitized = [];
        foreach ($orders as $id => $value) {
            if (!is_numeric($id)) {
                continue;
            }
            $orderValue = is_numeric($value) ? (int) $value : 0;
            if ($orderValue < -1000000) {
                $orderValue = -1000000;
            } elseif ($orderValue > 1000000) {
                $orderValue = 1000000;
            }
            $sanitized[(int) $id] = $orderValue;
        }
        if (empty($sanitized)) {
            self::flashError('未找到有效的排序数据');
            self::redirect(self::HASH_ROOT_WHITELIST);
        }
        try {
            $now = date('Y-m-d H:i:s');
            $ids = array_keys($sanitized);
            $existingIds = Capsule::table('mod_cloudflare_rootdomains')
                ->whereIn('id', $ids)
                ->pluck('id')
                ->toArray();
            if (empty($existingIds)) {
                self::flashError('未找到对应的根域名');
                self::redirect(self::HASH_ROOT_WHITELIST);
            }
            foreach ($existingIds as $id) {
                $orderValue = $sanitized[(int) $id] ?? 0;
                Capsule::table('mod_cloudflare_rootdomains')->where('id', $id)->update([
                    'display_order' => $orderValue,
                    'updated_at' => $now,
                ]);
            }
            self::flashSuccess('根域名排序已更新');
        } catch (\Throwable $e) {
            self::flashError('更新排序失败：' . $e->getMessage());
        }
        self::redirect(self::HASH_ROOT_WHITELIST);
    }

    private static function handleRootdomainUpdate(): void
    {
        try {
            $rootId = intval($_POST['rootdomain_id'] ?? 0);
            if ($rootId <= 0) {
                throw new Exception('参数无效');
            }
            $rootRow = Capsule::table('mod_cloudflare_rootdomains')->where('id', $rootId)->first();
            if (!$rootRow) {
                throw new Exception('根域名不存在');
            }
            $providerSelection = intval($_POST['provider_account_id'] ?? 0);
            $providerAccount = self::resolveProviderAccount($providerSelection, false);
            if (!$providerAccount) {
                throw new Exception('请选择有效的 DNS 供应商账号');
            }
            $providerIdForUpdate = intval($providerAccount['id']);
            $maxSubdomainsInput = intval($_POST['max_subdomains'] ?? ($rootRow->max_subdomains ?? 1000));
            if ($maxSubdomainsInput <= 0) {
                $maxSubdomainsInput = 1000;
            }
            $perUserLimitInput = intval($_POST['per_user_limit'] ?? ($rootRow->per_user_limit ?? 0));
            if ($perUserLimitInput < 0) {
                $perUserLimitInput = 0;
            }
            $defaultTermInput = intval($_POST['default_term_years'] ?? ($rootRow->default_term_years ?? 0));
            if ($defaultTermInput < 0) {
                $defaultTermInput = 0;
            }
            $zoneIdInput = trim($_POST['cloudflare_zone_id'] ?? '');
            $descriptionInput = trim($_POST['description'] ?? '');
            $updatePayload = [
                'cloudflare_zone_id' => $zoneIdInput !== '' ? $zoneIdInput : null,
                'description' => $descriptionInput !== '' ? $descriptionInput : null,
                'max_subdomains' => $maxSubdomainsInput,
                'per_user_limit' => $perUserLimitInput,
                'default_term_years' => $defaultTermInput,
                'provider_account_id' => $providerIdForUpdate,
                'updated_at' => date('Y-m-d H:i:s'),
            ];
            Capsule::table('mod_cloudflare_rootdomains')->where('id', $rootId)->update($updatePayload);
            if (function_exists('cfmod_clear_rootdomain_limits_cache')) {
                cfmod_clear_rootdomain_limits_cache();
            }
            $oldProviderId = intval($rootRow->provider_account_id ?? 0);
            if ($oldProviderId !== $providerIdForUpdate && function_exists('cfmod_reassign_subdomains_provider')) {
                cfmod_reassign_subdomains_provider($rootRow->domain ?? '', $providerIdForUpdate);
            }
            self::flashSuccess('✅ 已更新根域名 ' . htmlspecialchars($rootRow->domain ?? '', ENT_QUOTES, 'UTF-8'));
        } catch (Exception $e) {
            self::flashError('❌ 更新根域名失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_ROOT_WHITELIST);
    }

    private static function handleRootdomainReplace(): void
    {
        $from = trim($_POST['from_root'] ?? '');
        $to = trim($_POST['to_root'] ?? '');
        if ($from === '' || $to === '' || $from === $to) {
            self::flashError('参数无效');
            self::redirect(self::HASH_ROOT_REPLACE);
        }
        $deleteOld = (($_POST['delete_old_records'] ?? '') === '1');
        $mode = ($_POST['run_mode'] ?? 'queue') === 'now' ? 'now' : 'queue';
        try {
            if ($mode === 'queue') {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'replace_root_domain',
                    'payload_json' => json_encode([
                        'from_root' => $from,
                        'to_root' => $to,
                        'delete_old' => $deleteOld,
                    ], JSON_UNESCAPED_UNICODE),
                    'priority' => 5,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                self::triggerQueueInBackground();
                $message = '替换任务已加入队列';
                $type = 'success';
            } else {
                if (function_exists('cfmod_job_replace_root')) {
                    cfmod_job_replace_root(0, ['from_root' => $from, 'to_root' => $to, 'delete_old' => $deleteOld]);
                }
                $message = '替换已完成';
                $type = 'success';
            }
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_replace_rootdomain', [
                    'from' => $from,
                    'to' => $to,
                    'delete_old' => $deleteOld ? 1 : 0,
                    'mode' => $mode,
                ]);
            }
            $fromRow = null;
            $toRow = null;
            try {
                $fromRow = Capsule::table('mod_cloudflare_rootdomains')->whereRaw('LOWER(domain)=?', [strtolower($from)])->first();
                $toRow = Capsule::table('mod_cloudflare_rootdomains')->whereRaw('LOWER(domain)=?', [strtolower($to)])->first();
            } catch (Exception $e) {
            }
            $toZone = null;
            try {
                $zoneProviderAccount = $fromRow ? self::resolveProviderAccount(intval($fromRow->provider_account_id ?? 0), true) : self::resolveProviderAccount(null, true);
                if ($zoneProviderAccount) {
                    $cf = new CloudflareAPI($zoneProviderAccount['access_key_id'] ?? '', $zoneProviderAccount['access_key_secret'] ?? '');
                    $toZone = $cf->getZoneId($to) ?: null;
                }
            } catch (Exception $e) {
                $toZone = null;
            }
            if ($fromRow) {
                try {
                    if ($toRow) {
                        Capsule::table('mod_cloudflare_rootdomains')->where('id', $fromRow->id)->delete();
                    } else {
                        Capsule::table('mod_cloudflare_rootdomains')->where('id', $fromRow->id)->update([
                            'domain' => $to,
                            'cloudflare_zone_id' => $toZone,
                            'updated_at' => date('Y-m-d H:i:s')
                        ]);
                    }
                } catch (Exception $e) {
                }
            }
            if (function_exists('cfmod_clear_rootdomain_limits_cache')) {
                cfmod_clear_rootdomain_limits_cache();
            }
            self::flash($message, $type);
        } catch (Exception $e) {
            self::flashError('替换失败: ' . $e->getMessage());
        }
        self::redirect(self::HASH_ROOT_REPLACE);
    }

    private static function handleRootdomainTransfer(): void
    {
        $rootdomain = strtolower(trim($_POST['transfer_rootdomain'] ?? ''));
        $targetProviderId = intval($_POST['target_provider_account_id'] ?? 0);
        $batchSize = intval($_POST['transfer_batch_size'] ?? 200);
        if ($batchSize <= 0) {
            $batchSize = 200;
        }
        $batchSize = max(25, min(500, $batchSize));
        $deleteOld = ($_POST['transfer_delete_old'] ?? '') === '1';
        $pauseRegistration = ($_POST['transfer_pause_registration'] ?? '') === '1';
        $autoResume = ($_POST['transfer_auto_resume'] ?? '1') === '1';
        $runMode = (($_POST['transfer_run_mode'] ?? 'queue') === 'now') ? 'now' : 'queue';

        if ($rootdomain === '') {
            self::flashError('请选择要迁移的根域名');
            self::redirect(self::HASH_ROOT_WHITELIST);
        }

        try {
            if ($targetProviderId <= 0) {
                throw new Exception('请选择目标 DNS 供应商');
            }
            $moduleSettings = self::moduleSettings();
            $rootRow = Capsule::table('mod_cloudflare_rootdomains')
                ->whereRaw('LOWER(domain)=?', [$rootdomain])
                ->first();
            if (!$rootRow) {
                throw new Exception('未找到该根域名');
            }

            $targetAccount = self::resolveProviderAccount($targetProviderId, true);
            if (!$targetAccount) {
                throw new Exception('目标供应商账号不可用或已停用');
            }

            $targetContext = cfmod_make_provider_client(intval($targetAccount['id']), $rootdomain, null, $moduleSettings, true);
            if (!$targetContext || empty($targetContext['client'])) {
                throw new Exception('无法连接目标供应商，请检查凭据');
            }
            $targetClient = $targetContext['client'];
            $targetZoneId = $targetClient->getZoneId($rootdomain);
            if (!$targetZoneId) {
                throw new Exception('目标供应商中未找到该根域名，请先完成托管后再试');
            }

            $payload = [
                'rootdomain' => $rootdomain,
                'target_provider_id' => intval($targetAccount['id']),
                'target_zone_identifier' => $targetZoneId,
                'batch_size' => $batchSize,
                'delete_old_records' => $deleteOld ? 1 : 0,
                'cursor_id' => 0,
                'resume_status' => $rootRow->status ?? 'active',
                'auto_resume' => $autoResume ? 1 : 0,
                'pause_registration' => $pauseRegistration ? 1 : 0,
            ];

            $now = date('Y-m-d H:i:s');
            if ($pauseRegistration && ($rootRow->status ?? '') === 'active') {
                Capsule::table('mod_cloudflare_rootdomains')
                    ->where('id', $rootRow->id)
                    ->update([
                        'status' => 'suspended',
                        'updated_at' => $now,
                    ]);
            }

            if ($runMode === 'queue') {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'transfer_root_provider',
                    'payload_json' => json_encode($payload, JSON_UNESCAPED_UNICODE),
                    'priority' => 5,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
                self::triggerQueueInBackground();
                self::flashSuccess('迁移任务已加入队列，稍后将在后台逐批处理。');
            } else {
                $jobStub = (object) ['id' => 0, 'priority' => 5];
                $stats = cfmod_job_transfer_root_provider($jobStub, $payload);
                $summary = $stats['message'] ?? '迁移已完成';
                self::flashSuccess('迁移已完成：' . htmlspecialchars($summary, ENT_QUOTES, 'UTF-8'));
            }

            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_transfer_root_provider', [
                    'rootdomain' => $rootdomain,
                    'target_provider_id' => intval($targetAccount['id']),
                    'batch_size' => $batchSize,
                    'delete_old_records' => $deleteOld ? 1 : 0,
                    'run_mode' => $runMode,
                    'pause_registration' => $pauseRegistration ? 1 : 0,
                ]);
            }
        } catch (Exception $e) {
            self::flashError('域名平台迁移失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_ROOT_WHITELIST);
    }

    private static function handleRootdomainExport(): void
    {
        try {
            if (!function_exists('cfmod_collect_rootdomain_dataset') || !function_exists('cfmod_stream_export_dataset')) {
                throw new Exception('当前环境不支持数据导出');
            }
            $targetRoot = trim($_POST['export_rootdomain_value'] ?? '');
            if ($targetRoot === '') {
                throw new Exception('请选择要导出的根域名');
            }
            $dataset = cfmod_collect_rootdomain_dataset($targetRoot);
            cfmod_stream_export_dataset($dataset, $targetRoot);
            exit;
        } catch (Exception $e) {
            self::flashError('导出失败：' . $e->getMessage());
            self::redirect(self::HASH_ROOT_WHITELIST);
        }
    }

    private static function handleRootdomainImport(): void
    {
        try {
            if (!function_exists('cfmod_import_rootdomain_dataset')) {
                throw new Exception('当前环境不支持数据导入');
            }
            if (!isset($_FILES['import_rootdomain_file'])) {
                throw new Exception('请上传导出文件');
            }
            $fileInfo = $_FILES['import_rootdomain_file'];
            if (($fileInfo['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                throw new Exception('文件上传失败');
            }
            $content = file_get_contents($fileInfo['tmp_name']);
            if ($content === '' || $content === false) {
                throw new Exception('文件内容为空');
            }
            if (function_exists('gzdecode') && substr($content, 0, 2) === "\x1f\x8b") {
                $decoded = @gzdecode($content);
                if ($decoded !== false) {
                    $content = $decoded;
                }
            }
            $data = json_decode($content, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception('解析 JSON 失败：' . json_last_error_msg());
            }
            if (!is_array($data)) {
                throw new Exception('导入文件格式不正确');
            }
            $summary = cfmod_import_rootdomain_dataset($data);
            if (function_exists('cfmod_clear_rootdomain_limits_cache')) {
                cfmod_clear_rootdomain_limits_cache();
            }
            $parts = [];
            $parts[] = '子域 ' . intval($summary['subdomains_inserted'] ?? 0) . ' 个';
            $parts[] = 'DNS 记录 ' . intval($summary['dns_records_inserted'] ?? 0) . ' 条';
            if (!empty($summary['domain_risk_inserted'])) {
                $parts[] = '域名风险 ' . intval($summary['domain_risk_inserted']) . ' 条';
            }
            if (!empty($summary['risk_events_inserted'])) {
                $parts[] = '风险事件 ' . intval($summary['risk_events_inserted']) . ' 条';
            }
            if (!empty($summary['sync_results_inserted'])) {
                $parts[] = '同步差异 ' . intval($summary['sync_results_inserted']) . ' 条';
            }
            $parts[] = '配额更新 ' . intval($summary['quota_updates'] ?? 0) . ' 项';
            if (!empty($summary['quota_created'])) {
                $parts[] = '新增配额 ' . intval($summary['quota_created']) . ' 项';
            }
            $rootLabel = $summary['rootdomain'] ?? '未知';
            $message = '导入完成（根域：' . $rootLabel . '）：' . implode('，', $parts);
            if (!empty($summary['warnings'])) {
                $preview = array_slice($summary['warnings'], 0, 3);
                $message .= '。注意：' . implode('；', $preview);
                if (count($summary['warnings']) > 3) {
                    $message .= ' 等。';
                }
            }
            self::flash($message, 'success');
        } catch (Exception $e) {
            self::flashError('导入失败：' . $e->getMessage());
        }
        self::redirect(self::HASH_ROOT_WHITELIST);
    }

    private static function handleRootdomainPurgeLocal(): void
    {
        try {
            $targetRoot = strtolower(trim($_POST['target_rootdomain'] ?? ''));
            $confirmRoot = strtolower(trim($_POST['confirm_rootdomain'] ?? ''));
            $batchSizeInput = intval($_POST['batch_size'] ?? 200);
            $runNow = (($_POST['run_now'] ?? '') === '1');
            if ($targetRoot === '') {
                throw new Exception('请指定要清理的根域名');
            }
            if ($confirmRoot === '' || $confirmRoot !== $targetRoot) {
                throw new Exception('确认根域名与目标不一致');
            }
            if (!preg_match('/^[a-z0-9.-]+$/', $targetRoot)) {
                throw new Exception('根域名格式不正确');
            }
            $estimated = Capsule::table('mod_cloudflare_subdomain')
                ->whereRaw('LOWER(rootdomain) = ?', [$targetRoot])
                ->count();
            if ($estimated === 0) {
                self::flash('未找到根域名 ' . $targetRoot . ' 下的子域名', 'warning');
                self::redirect(self::HASH_ROOT_WHITELIST);
            }
            $batchSize = max(20, min(500, ($batchSizeInput > 0 ? $batchSizeInput : 200)));
            $payload = [
                'rootdomain' => $targetRoot,
                'batch_size' => $batchSize,
                'initiator' => 'admin',
            ];
            if (!empty($_SESSION['adminid'])) {
                $payload['admin_id'] = intval($_SESSION['adminid']);
            }
            $nowTs = date('Y-m-d H:i:s');
            $jobId = Capsule::table('mod_cloudflare_jobs')->insertGetId([
                'type' => 'purge_root_local',
                'payload_json' => json_encode($payload, JSON_UNESCAPED_UNICODE),
                'priority' => 6,
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => $nowTs,
                'updated_at' => $nowTs
            ]);
            if ($runNow) {
                self::triggerQueueInBackground();
            }
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_purge_rootdomain_local_requested', [
                    'rootdomain' => $targetRoot,
                    'batch_size' => $batchSize,
                    'estimated_subdomains' => $estimated,
                    'job_id' => $jobId,
                    'run_now' => $runNow ? 1 : 0,
                ]);
            }
            self::flashSuccess("已提交本地删除任务（Job ID: {$jobId}），预计处理 {$estimated} 个子域名。仅清理本地数据，云端记录保持不变。");
        } catch (Exception $e) {
            self::flashError('提交删除任务失败：' . $e->getMessage());
        }
        self::redirect(self::HASH_ROOT_WHITELIST);
    }

    private static function handleForbiddenAdd(): void
    {
        $banDomain = trim($_POST['ban_domain'] ?? '');
        $banRoot = trim($_POST['ban_root'] ?? '');
        $banReason = trim($_POST['ban_reason'] ?? '');
        if ($banDomain === '') {
            self::flashError('请输入域名');
            self::redirect(self::HASH_FORBIDDEN);
        }
        try {
            $exists = Capsule::table('mod_cloudflare_forbidden_domains')->where('domain', $banDomain)->count();
            if ($exists > 0) {
                self::flash('禁止域名已存在', 'warning');
            } else {
                Capsule::table('mod_cloudflare_forbidden_domains')->insert([
                    'domain' => strtolower($banDomain),
                    'rootdomain' => $banRoot ?: null,
                    'reason' => $banReason ?: null,
                    'added_by' => 'admin',
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('admin_add_forbidden_domain', ['domain' => $banDomain, 'root' => $banRoot, 'reason' => $banReason]);
                }
                self::flashSuccess('已添加禁止域名');
            }
        } catch (Exception $e) {
            self::flashError('添加失败：' . $e->getMessage());
        }
        self::redirect(self::HASH_FORBIDDEN);
    }

    private static function handleForbiddenDelete(): void
    {
        $id = intval($_POST['id'] ?? ($_GET['id'] ?? 0));
        if ($id <= 0) {
            self::flashError('参数无效');
        } else {
            Capsule::table('mod_cloudflare_forbidden_domains')->where('id', $id)->delete();
            self::flashSuccess('已移除禁止域名');
        }
        self::redirect(self::HASH_FORBIDDEN);
    }


    private static function handleJobRetry(): void
    {
        $jobId = intval($_POST['job_id'] ?? 0);
        if ($jobId <= 0) {
            self::flashError('参数无效');
            self::redirect(self::HASH_JOBS);
        }

        try {
            Capsule::table('mod_cloudflare_jobs')->where('id', $jobId)->update([
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
                'last_error' => null,
            ]);
            self::flashSuccess('已重试作业 #' . $jobId);
        } catch (Exception $e) {
            self::flashError('重试失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_JOBS);
    }

    private static function handleJobCancel(): void
    {
        $jobId = intval($_POST['job_id'] ?? 0);
        if ($jobId <= 0) {
            self::flashError('参数无效');
            self::redirect(self::HASH_JOBS);
        }

        try {
            Capsule::table('mod_cloudflare_jobs')->where('id', $jobId)->update([
                'status' => 'cancelled',
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            self::flashSuccess('已取消作业 #' . $jobId);
        } catch (Exception $e) {
            self::flashError('取消失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_JOBS);
    }

    private static function handleEnqueueCalibration(): void
    {
        try {
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'calibrate_all',
                'payload_json' => json_encode(['mode' => ($_POST['mode'] ?? 'dry')], JSON_UNESCAPED_UNICODE),
                'priority' => 5,
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            self::triggerQueueInBackground();
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_enqueue_calibration', ['mode' => ($_POST['mode'] ?? 'dry')]);
            }
            self::flashSuccess('已提交校准作业');
        } catch (Exception $e) {
            self::flashError('提交校准失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_JOBS);
    }

    private static function handleEnqueueRootCalibration(): void
    {
        $mode = (($_POST['mode'] ?? 'dry') === 'fix') ? 'fix' : 'dry';
        $rootdomainRaw = trim((string) ($_POST['rootdomain'] ?? ''));
        $normalizedRoot = strtolower($rootdomainRaw);
        if ($normalizedRoot === '') {
            self::flashError('请选择要校准的根域名');
            self::redirect(self::HASH_JOBS);
        }

        $exists = false;
        try {
            $exists = Capsule::table('mod_cloudflare_rootdomains')
                ->whereRaw('LOWER(domain) = ?', [$normalizedRoot])
                ->exists();
        } catch (Exception $e) {
            $exists = false;
        }
        if (!$exists && function_exists('cfmod_get_known_rootdomains')) {
            try {
                $known = array_map('strtolower', cfmod_get_known_rootdomains(self::moduleSettings()));
                $exists = in_array($normalizedRoot, $known, true);
            } catch (Exception $e) {
                $exists = false;
            }
        }
        if (!$exists) {
            self::flashError('未找到该根域名或尚未接入：' . htmlspecialchars($rootdomainRaw, ENT_QUOTES, 'UTF-8'));
            self::redirect(self::HASH_JOBS);
        }

        try {
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'calibrate_all',
                'payload_json' => json_encode([
                    'mode' => $mode,
                    'rootdomain' => $normalizedRoot,
                ], JSON_UNESCAPED_UNICODE),
                'priority' => 5,
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            self::triggerQueueInBackground();
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_enqueue_root_calibration', [
                    'mode' => $mode,
                    'rootdomain' => $normalizedRoot,
                ]);
            }
            self::flashSuccess(sprintf('已提交根域 %s 的校准作业', htmlspecialchars($rootdomainRaw, ENT_QUOTES, 'UTF-8')));
        } catch (Exception $e) {
            self::flashError('提交校准失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_JOBS);
    }

    private static function handleEnqueueRiskScan(): void
    {
        try {
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'risk_scan_all',
                'payload_json' => json_encode([], JSON_UNESCAPED_UNICODE),
                'priority' => 5,
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_enqueue_risk_scan', []);
            }
            self::flashSuccess('已提交风险扫描作业（将由 Cron 异步执行）');
        } catch (Exception $e) {
            self::flashError('提交风险扫描失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_RISK_MONITOR);
    }

    private static function handleEnqueueReconcile(): void
    {
        try {
            $mode = (($_POST['mode'] ?? 'dry') === 'fix') ? 'fix' : 'dry';
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'reconcile_all',
                'payload_json' => json_encode(['mode' => $mode], JSON_UNESCAPED_UNICODE),
                'priority' => 5,
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            self::triggerQueueInBackground();
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_enqueue_reconcile', ['mode' => $mode]);
            }
            self::flashSuccess('对账任务已入队（' . ($mode === 'fix' ? 'fix' : 'dry') . '）');
        } catch (Exception $e) {
            self::flashError('入队失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_JOBS);
    }

    private static function handleRunQueueOnce(): void
    {
        try {
            self::triggerQueueInBackground();
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_run_queue_once', ['mode' => 'background']);
            }
            self::flashSuccess('已触发后台执行队列（1 个作业）。请稍后刷新');
        } catch (Exception $e) {
            self::flashError('执行队列失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_JOBS);
    }

    private static function handleRunMigrations(): void
    {
        try {
            if (!Capsule::schema()->hasTable('mod_cloudflare_domain_risk')) {
                Capsule::schema()->create('mod_cloudflare_domain_risk', function ($table) {
                    $table->increments('id');
                    $table->integer('subdomain_id')->unsigned();
                    $table->integer('risk_score')->default(0);
                    $table->string('risk_level', 16)->default('low');
                    $table->text('reasons_json')->nullable();
                    $table->dateTime('last_checked_at')->nullable();
                    $table->dateTime('created_at')->nullable();
                    $table->dateTime('updated_at')->nullable();
                    $table->unique('subdomain_id');
                    $table->index(['risk_score', 'risk_level']);
                });
            }
            if (!Capsule::schema()->hasTable('mod_cloudflare_risk_events')) {
                Capsule::schema()->create('mod_cloudflare_risk_events', function ($table) {
                    $table->increments('id');
                    $table->integer('subdomain_id')->unsigned();
                    $table->string('source', 32);
                    $table->integer('score')->default(0);
                    $table->string('level', 16)->default('low');
                    $table->string('reason', 255)->nullable();
                    $table->text('details_json')->nullable();
                    $table->dateTime('created_at')->nullable();
                    $table->dateTime('updated_at')->nullable();
                    $table->index('subdomain_id');
                    $table->index('created_at');
                });
            }
            self::flashSuccess('迁移/修复完成');
        } catch (Exception $e) {
            self::flashError('迁移失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_JOBS);
    }

    private static function handleSaveAdminAnnounce(): void
    {
        try {
            $enabled = isset($_POST['admin_announce_enabled']) && $_POST['admin_announce_enabled'] === '1' ? '1' : '0';
            $title = trim($_POST['admin_announce_title'] ?? '公告');
            $htmlInput = trim($_POST['admin_announce_html'] ?? '');
            $html = html_entity_decode($htmlInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            self::persistModuleSettings([
                'admin_announce_enabled' => $enabled,
                'admin_announce_title' => $title,
                'admin_announce_html' => $html,
            ]);
            self::flashSuccess('后台公告设置已保存');
        } catch (Exception $e) {
            self::flashError('保存公告失败：' . $e->getMessage());
        }

        self::redirect(self::HASH_ANNOUNCEMENTS);
    }

    private static function handleRuntimeSwitches(): void
    {
        $moduleSettings = self::moduleSettings();
        $pause = (($_POST['pause_free_registration'] ?? '') === '1') ? '1' : '0';
        $disableNs = (($_POST['disable_ns_management'] ?? '') === '1') ? '1' : '0';
        $maintenance = (($_POST['maintenance_mode'] ?? '') === '1') ? '1' : '0';
        $maintenanceMsg = trim($_POST['maintenance_message'] ?? '');
        $disableDnsWrite = (($_POST['disable_dns_write'] ?? '') === '1') ? '1' : '0';
        $hideInviteFeature = (($_POST['hide_invite_feature'] ?? '') === '1') ? '1' : '0';
        $enableClientDelete = (($_POST['enable_client_domain_delete'] ?? '') === '1') ? '1' : '0';
        $syncInviteLimitUpOnly = (($_POST['sync_invite_limit_up_only'] ?? '') === '1');
        $clientPageSizeInput = intval($_POST['client_page_size'] ?? ($moduleSettings['client_page_size'] ?? 20));
        $clientPageSize = max(1, min(20, $clientPageSizeInput));
        $cleanupIntervalInput = intval($_POST['domain_cleanup_interval_hours'] ?? ($moduleSettings['domain_cleanup_interval_hours'] ?? 24));
        $cleanupIntervalHours = max(1, min(168, $cleanupIntervalInput));
        $rateLimitRegister = max(0, intval($_POST['rate_limit_register_per_hour'] ?? ($moduleSettings['rate_limit_register_per_hour'] ?? 30)));
        $rateLimitDns = max(0, intval($_POST['rate_limit_dns_per_hour'] ?? ($moduleSettings['rate_limit_dns_per_hour'] ?? 120)));
        $rateLimitApiKey = max(0, intval($_POST['rate_limit_api_key_per_hour'] ?? ($moduleSettings['rate_limit_api_key_per_hour'] ?? 20)));
        $rateLimitQuota = max(0, intval($_POST['rate_limit_quota_gift_per_hour'] ?? ($moduleSettings['rate_limit_quota_gift_per_hour'] ?? 20)));
        $rateLimitAjax = max(0, intval($_POST['rate_limit_ajax_per_hour'] ?? ($moduleSettings['rate_limit_ajax_per_hour'] ?? 60)));
        $rateLimitDnsUnlock = max(0, intval($_POST['rate_limit_dns_unlock_per_hour'] ?? ($moduleSettings['rate_limit_dns_unlock_per_hour'] ?? 10)));
        $riskScanBatchInput = intval($_POST['risk_scan_batch_size'] ?? ($moduleSettings['risk_scan_batch_size'] ?? 50));
        $riskScanBatchSize = max(10, min(1000, $riskScanBatchInput));
        $enableDnsUnlockFeature = (($_POST['enable_dns_unlock'] ?? '') === '1');
        $dnsUnlockShareEnabledSetting = (($_POST['dns_unlock_share_enabled'] ?? '') === '1');
        $dnsUnlockPurchaseEnabledSetting = (($_POST['dns_unlock_purchase_enabled'] ?? '') === '1');
        $dnsUnlockPurchasePriceInput = (float) ($_POST['dns_unlock_purchase_price'] ?? ($moduleSettings['dns_unlock_purchase_price'] ?? 0));
        $dnsUnlockPurchasePrice = round(max(0, $dnsUnlockPurchasePriceInput), 2);

        try {
            self::persistModuleSettings([
                'pause_free_registration' => $pause,
                'disable_ns_management' => $disableNs,
                'maintenance_mode' => $maintenance,
                'maintenance_message' => $maintenanceMsg,
                'disable_dns_write' => $disableDnsWrite,
                'hide_invite_feature' => $hideInviteFeature,
                'enable_client_domain_delete' => $enableClientDelete,
                'sync_invite_limit_up_only' => $syncInviteLimitUpOnly ? '1' : '0',
                'client_page_size' => (string) $clientPageSize,
                'enable_dns_unlock' => $enableDnsUnlockFeature ? '1' : '0',
                'dns_unlock_share_enabled' => $dnsUnlockShareEnabledSetting ? '1' : '0',
                'dns_unlock_purchase_enabled' => $dnsUnlockPurchaseEnabledSetting ? '1' : '0',
                'dns_unlock_purchase_price' => number_format($dnsUnlockPurchasePrice, 2, '.', ''),
                'risk_scan_batch_size' => (string) $riskScanBatchSize,
                'rate_limit_register_per_hour' => (string) $rateLimitRegister,
                'rate_limit_dns_per_hour' => (string) $rateLimitDns,
                'rate_limit_api_key_per_hour' => (string) $rateLimitApiKey,
                'rate_limit_quota_gift_per_hour' => (string) $rateLimitQuota,
                'rate_limit_ajax_per_hour' => (string) $rateLimitAjax,
                'rate_limit_dns_unlock_per_hour' => (string) $rateLimitDnsUnlock,
                'domain_cleanup_interval_hours' => (string) $cleanupIntervalHours,
            ]);
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_save_runtime_switches', [
                    'pause_free_registration' => $pause,
                    'disable_ns_management' => $disableNs,
                    'maintenance_mode' => $maintenance,
                    'disable_dns_write' => $disableDnsWrite,
                    'hide_invite_feature' => $hideInviteFeature,
                    'enable_client_domain_delete' => $enableClientDelete,
                    'maintenance_message_length' => strlen($maintenanceMsg),
                    'client_page_size' => $clientPageSize,
                    'dns_unlock_share_enabled' => $dnsUnlockShareEnabledSetting ? 1 : 0,
                    'dns_unlock_purchase_enabled' => $dnsUnlockPurchaseEnabledSetting ? 1 : 0,
                    'dns_unlock_purchase_price' => $dnsUnlockPurchasePrice,
                    'rate_limit_register_per_hour' => $rateLimitRegister,
                    'rate_limit_dns_per_hour' => $rateLimitDns,
                    'rate_limit_api_key_per_hour' => $rateLimitApiKey,
                    'rate_limit_quota_gift_per_hour' => $rateLimitQuota,
                    'rate_limit_ajax_per_hour' => $rateLimitAjax,
                    'rate_limit_dns_unlock_per_hour' => $rateLimitDnsUnlock,
                    'domain_cleanup_interval_hours' => $cleanupIntervalHours,
                ]);
            }
            if ($syncInviteLimitUpOnly) {
                try {
                    $global = intval(Capsule::table('tbladdonmodules')
                        ->where('module', 'domain_hub')
                        ->where('setting', 'invite_bonus_limit_global')
                        ->value('value') ?? 5);
                    if ($global > 0) {
                        $candidates = Capsule::table('mod_cloudflare_subdomain_quotas')
                            ->whereIn('invite_bonus_limit', [0, 5])
                            ->get();
                        foreach ($candidates as $candidate) {
                            $limit = intval($candidate->invite_bonus_limit ?? 0);
                            if ($limit < $global) {
                                Capsule::table('mod_cloudflare_subdomain_quotas')
                                    ->where('userid', $candidate->userid)
                                    ->update(['invite_bonus_limit' => $global]);
                            }
                        }
                    }
                } catch (Exception $e) {
                    // ignore sync errors
                }
            }
            self::flashSuccess('运行控制设置已保存');
        } catch (Exception $e) {
            self::flashError('保存失败：' . $e->getMessage());
        }

        self::redirect(self::HASH_RUNTIME);
    }

    private static function handleDomainGiftCancel(): void
    {
        try {
            if (!Capsule::schema()->hasTable('mod_cloudflare_domain_gifts')) {
                throw new Exception('尚未启用域名转赠功能');
            }
            $giftId = intval($_POST['gift_id'] ?? 0);
            if ($giftId <= 0) {
                throw new Exception('缺少转赠记录');
            }
            $adminId = isset($_SESSION['adminid']) ? intval($_SESSION['adminid']) : null;
            $now = date('Y-m-d H:i:s');
            $giftInfo = Capsule::transaction(function () use ($giftId, $adminId, $now) {
                $gift = Capsule::table('mod_cloudflare_domain_gifts')
                    ->where('id', $giftId)
                    ->lockForUpdate()
                    ->first();
                if (!$gift) {
                    throw new Exception('转赠记录不存在');
                }
                if (($gift->status ?? '') !== 'pending') {
                    throw new Exception('仅可取消进行中的转赠');
                }
                Capsule::table('mod_cloudflare_domain_gifts')
                    ->where('id', $giftId)
                    ->update([
                        'status' => 'cancelled',
                        'cancelled_at' => $now,
                        'cancelled_by_admin' => $adminId,
                        'updated_at' => $now,
                    ]);
                Capsule::table('mod_cloudflare_subdomain')
                    ->where('id', $gift->subdomain_id)
                    ->where('gift_lock_id', $gift->id)
                    ->update([
                        'gift_lock_id' => null,
                        'updated_at' => $now,
                    ]);
                return $gift;
            });
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_cancel_domain_gift', [
                    'gift_id' => $giftId,
                    'full_domain' => $giftInfo->full_domain ?? '',
                    'from_userid' => $giftInfo->from_userid ?? null,
                ]);
            }
            $_SESSION['admin_api_success'] = '✅ 已取消该转赠记录并解除锁定';
        } catch (Exception $e) {
            $_SESSION['admin_api_error'] = '❌ 取消转赠失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
        }

        self::redirect(self::HASH_DOMAIN_GIFTS);
    }

    private static function handleDomainGiftUnlock(): void
    {
        try {
            $giftId = intval($_POST['gift_id'] ?? 0);
            $subdomainId = intval($_POST['subdomain_id'] ?? 0);
            if ($giftId <= 0 || $subdomainId <= 0) {
                throw new Exception('参数不完整');
            }
            $now = date('Y-m-d H:i:s');
            Capsule::transaction(function () use ($giftId, $subdomainId, $now) {
                $gift = Capsule::table('mod_cloudflare_domain_gifts')
                    ->where('id', $giftId)
                    ->lockForUpdate()
                    ->first();
                $subdomain = Capsule::table('mod_cloudflare_subdomain')
                    ->where('id', $subdomainId)
                    ->lockForUpdate()
                    ->first();
                if (!$subdomain) {
                    throw new Exception('未找到子域名');
                }
                if (intval($subdomain->gift_lock_id ?? 0) !== $giftId) {
                    throw new Exception('该域名未被该转赠记录锁定');
                }
                if ($gift && ($gift->status ?? '') === 'pending') {
                    throw new Exception('请先取消该转赠再解除锁定');
                }
                Capsule::table('mod_cloudflare_subdomain')
                    ->where('id', $subdomainId)
                    ->update([
                        'gift_lock_id' => null,
                        'updated_at' => $now,
                    ]);
            });
            $_SESSION['admin_api_success'] = '✅ 已解除域名转赠锁定';
        } catch (Exception $e) {
            $_SESSION['admin_api_error'] = '❌ 解除锁定失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
        }

        self::redirect(self::HASH_DOMAIN_GIFTS);
    }
    private static function handleBanUser(): void
    {
        $userid = 0;
        $userEmail = trim($_POST['user_email'] ?? '');
        $banReason = trim($_POST['ban_reason'] ?? '');
        $banType = in_array(($_POST['ban_type'] ?? 'permanent'), ['permanent', 'temporary', 'weekly'], true)
            ? $_POST['ban_type']
            : 'permanent';
        $banDurationDays = intval($_POST['ban_days'] ?? 0);
        $banExpiresAt = null;
        if ($banType === 'temporary') {
            $banDurationDays = max(1, $banDurationDays ?: 7);
            $banExpiresAt = date('Y-m-d H:i:s', time() + $banDurationDays * 86400);
        } elseif ($banType === 'weekly') {
            $banExpiresAt = date('Y-m-d H:i:s', time() + 7 * 86400);
        }

        $lookupSource = 'email';
        if ($userEmail !== '') {
            // Check if input looks like an email or a subdomain
            if (filter_var($userEmail, FILTER_VALIDATE_EMAIL)) {
                // Standard email lookup
                try {
                    $row = Capsule::table('tblclients')->where('email', $userEmail)->first();
                    if ($row) {
                        $userid = intval($row->id);
                    }
                } catch (Exception $e) {
                    // ignore lookup failures
                }
            } else {
                // Try to find user by subdomain
                $lookupSource = 'subdomain';
                $subdomainInput = strtolower(trim($userEmail));
                try {
                    // Try exact match first (full subdomain like "test.example.com")
                    $subRow = Capsule::table('mod_cloudflare_subdomain')
                        ->whereRaw('LOWER(subdomain) = ?', [$subdomainInput])
                        ->first();

                    // If not found, try matching as prefix (user might enter just "test" or "test.sub")
                    if (!$subRow) {
                        $subRow = Capsule::table('mod_cloudflare_subdomain')
                            ->whereRaw('LOWER(subdomain) LIKE ?', [$subdomainInput . '.%'])
                            ->first();
                    }

                    // Also try if input contains root domain (e.g., "test.example.com")
                    if (!$subRow && strpos($subdomainInput, '.') !== false) {
                        $subRow = Capsule::table('mod_cloudflare_subdomain')
                            ->whereRaw('LOWER(CONCAT(subdomain, ".", rootdomain)) = ?', [$subdomainInput])
                            ->first();
                    }

                    if ($subRow && !empty($subRow->userid)) {
                        $userid = intval($subRow->userid);
                        // Fetch user email for logging
                        $clientRow = Capsule::table('tblclients')->where('id', $userid)->first();
                        if ($clientRow) {
                            $userEmail = $clientRow->email ?? '';
                        }
                    }
                } catch (Exception $e) {
                    // ignore lookup failures
                }
            }
        }

        if (!$userid) {
            $errorMsg = $lookupSource === 'subdomain'
                ? '未找到该子域名对应的用户，请检查子域名是否正确'
                : '未找到指定用户';
            self::flashError($errorMsg);
            self::redirect(self::HASH_BANS);
        }

        try {
            $user = Capsule::table('tblclients')->where('id', $userid)->first();
            if (!$user) {
                throw new Exception('用户不存在');
            }

            Capsule::table('tblclients')->where('id', $userid)->update(['status' => 'Inactive']);

            self::ensureUserBansTable();
            $banInsert = [
                'userid' => $userid,
                'ban_reason' => $banReason,
                'banned_by' => 'admin',
                'banned_at' => date('Y-m-d H:i:s'),
                'status' => 'banned',
            ];
            try {
                if (Capsule::schema()->hasColumn('mod_cloudflare_user_bans', 'ban_type')) {
                    $banInsert['ban_type'] = $banType;
                }
                if (Capsule::schema()->hasColumn('mod_cloudflare_user_bans', 'ban_expires_at')) {
                    $banInsert['ban_expires_at'] = $banExpiresAt;
                }
            } catch (Exception $e) {
                // ignore schema issues for optional fields
            }
            Capsule::table('mod_cloudflare_user_bans')->insert($banInsert);

            $deleteRecords = (($_POST['delete_user_records_on_ban'] ?? '') === '1');
            $deleteDomains = (($_POST['delete_user_domains_on_ban'] ?? '') === '1');
            if ($deleteRecords || $deleteDomains) {
                try {
                    Capsule::table('mod_cloudflare_jobs')->insert([
                        'type' => 'cleanup_user_subdomains',
                        'payload_json' => json_encode([
                            'userid' => $userid,
                            'delete_records' => $deleteRecords ? 1 : 0,
                            'delete_domains' => $deleteDomains ? 1 : 0,
                            'initiated_by' => 'admin',
                        ], JSON_UNESCAPED_UNICODE),
                        'priority' => 8,
                        'status' => 'pending',
                        'attempts' => 0,
                        'next_run_at' => null,
                        'created_at' => date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s'),
                    ]);
                    if (function_exists('cloudflare_subdomain_log')) {
                        cloudflare_subdomain_log('admin_ban_user_cleanup', [
                            'userid' => $userid,
                            'delete_records' => $deleteRecords ? 1 : 0,
                            'delete_domains' => $deleteDomains ? 1 : 0,
                        ]);
                    }
                } catch (Exception $e) {
                    if (function_exists('cloudflare_subdomain_log')) {
                        cloudflare_subdomain_log('admin_ban_user_cleanup_error', [
                            'userid' => $userid,
                            'error' => $e->getMessage(),
                        ]);
                    }
                }
            }

            try {
                $disabled = Capsule::table('mod_cloudflare_api_keys')
                    ->where('userid', $userid)
                    ->where('status', '!=', 'disabled')
                    ->update([
                        'status' => 'disabled',
                        'updated_at' => date('Y-m-d H:i:s'),
                    ]);
                if ($disabled && function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('admin_ban_user_disable_api', [
                        'userid' => $userid,
                        'disabled_keys' => $disabled,
                    ]);
                }
            } catch (Exception $e) {
                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('admin_ban_user_disable_api_error', [
                        'userid' => $userid,
                        'error' => $e->getMessage(),
                    ]);
                }
            }

            $enforceNow = (($_POST['enforce_dns_now'] ?? '') === '1');
            $moduleSettings = self::moduleSettings();
            $ip4 = trim($_POST['enforce_dns_ip4'] ?? ($moduleSettings['default_ip'] ?? ''));
            if ($enforceNow && $ip4 !== '') {
                try {
                    Capsule::table('mod_cloudflare_jobs')->insert([
                        'type' => 'enforce_ban_dns',
                        'payload_json' => json_encode(['userid' => $userid, 'ipv4' => $ip4], JSON_UNESCAPED_UNICODE),
                        'priority' => 5,
                        'status' => 'pending',
                        'attempts' => 0,
                        'next_run_at' => null,
                        'created_at' => date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s'),
                    ]);
                    self::triggerQueueInBackground();
                    if (function_exists('cloudflare_subdomain_log')) {
                        cloudflare_subdomain_log('admin_ban_user_enforce_dns_enqueue', [
                            'userid' => $userid,
                            'ipv4' => $ip4,
                        ]);
                    }
                } catch (Exception $e) {
                    // ignore enqueue failure
                }
            }

            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_ban_user', [
                    'userid' => $userid,
                    'reason' => $banReason,
                    'ban_type' => $banType,
                    'ban_expires_at' => $banExpiresAt,
                ]);
            }

            self::flashSuccess('用户已封禁');
        } catch (Exception $e) {
            self::flashError('封禁用户失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_BANS);
    }

    private static function handleUnbanUser(): void
    {
        $userid = intval($_POST['userid'] ?? 0);
        if (!$userid && isset($_POST['user_email'])) {
            try {
                $row = Capsule::table('tblclients')->where('email', trim($_POST['user_email']))->first();
                if ($row) {
                    $userid = intval($row->id);
                }
            } catch (Exception $e) {
                // ignore lookup failure
            }
        }

        if (!$userid) {
            self::flashError('参数无效');
            self::redirect(self::HASH_BANS);
        }

        try {
            Capsule::table('tblclients')->where('id', $userid)->update(['status' => 'Active']);
            self::ensureUserBansTable();
            Capsule::table('mod_cloudflare_user_bans')
                ->where('userid', $userid)
                ->where('status', 'banned')
                ->update([
                    'status' => 'unbanned',
                    'unbanned_at' => date('Y-m-d H:i:s'),
                ]);
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_unban_user', ['userid' => $userid]);
            }
            self::flashSuccess('用户已解封');
        } catch (Exception $e) {
            self::flashError('解封用户失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_BANS);
    }

    private static function handleEnforceBanDns(): void
    {
        try {
            $userid = intval($_POST['userid'] ?? 0);
            $moduleSettings = self::moduleSettings();
            $ip4 = trim($_POST['enforce_dns_ip4'] ?? ($moduleSettings['default_ip'] ?? ''));
            if ($userid <= 0 || $ip4 === '') {
                throw new Exception('参数无效（缺少用户或IP）');
            }
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'enforce_ban_dns',
                'payload_json' => json_encode(['userid' => $userid, 'ipv4' => $ip4], JSON_UNESCAPED_UNICODE),
                'priority' => 5,
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            self::triggerQueueInBackground();
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_enforce_ban_dns_enqueue', [
                    'userid' => $userid,
                    'ipv4' => $ip4,
                ]);
            }
            self::flashSuccess('已提交处置DNS作业');
        } catch (Exception $e) {
            self::flashError('提交失败：' . $e->getMessage());
        }

        self::redirect(self::HASH_BANS);
    }

    private static function handleSaveInviteCycleStart(): void
    {
        try {
            $value = trim($_POST['invite_cycle_start'] ?? '');
            if ($value !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
                throw new Exception('日期格式应为 YYYY-MM-DD');
            }
            self::persistModuleSetting('invite_cycle_start', $value);
            self::flashSuccess('周期开始日期已保存');
        } catch (Exception $e) {
            self::flashError('保存失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_INVITE);
    }

    private static function handleSaveLeaderboardDisplay(): void
    {
        try {
            $hideCurrentWeek = (($_POST['hide_current_week_leaderboard'] ?? '') === '1') ? '1' : '0';
            self::persistModuleSetting('hide_current_week_leaderboard', $hideCurrentWeek);
            self::flashSuccess('排行榜显示设置已保存');
        } catch (Exception $e) {
            self::flashError('保存失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_INVITE);
    }

    private static function handleMarkRewardClaimed(): void
    {
        try {
            $rewardId = intval($_POST['reward_id'] ?? 0);
            if ($rewardId <= 0) {
                throw new Exception('缺少奖励ID');
            }
            Capsule::table('mod_cloudflare_invite_rewards')
                ->where('id', $rewardId)
                ->update([
                    'status' => 'claimed',
                    'claimed_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
            self::flashSuccess('已标记为已发放');
        } catch (Exception $e) {
            self::flashError('操作失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_INVITE);
    }

    private static function handleAdminUpsertInviteReward(): void
    {
        self::ensureInviteTables();
        $moduleSettings = self::moduleSettings();
        [$periodStart, $periodEnd] = self::currentInvitePeriod($moduleSettings);

        try {
            $identifier = trim($_POST['user_identifier'] ?? '');
            if ($identifier === '') {
                throw new Exception('缺少用户邮箱或ID');
            }
            if (ctype_digit($identifier)) {
                $userId = intval($identifier);
            } else {
                $client = Capsule::table('tblclients')->select('id')->where('email', $identifier)->first();
                if (!$client) {
                    throw new Exception('找不到该邮箱对应的用户');
                }
                $userId = intval($client->id);
            }
            $rank = max(1, intval($_POST['rank'] ?? 0));
            $count = max(0, intval($_POST['count'] ?? 0));
            $code = trim($_POST['code'] ?? '');
            $status = in_array($_POST['status'] ?? 'eligible', ['eligible', 'pending', 'claimed'], true)
                ? ($_POST['status'] ?? 'eligible')
                : 'eligible';
            if ($code === '') {
                $codeRow = Capsule::table('mod_cloudflare_invitation_codes')->select('code')->where('userid', $userId)->first();
                $code = $codeRow->code ?? '';
            }
            $existing = Capsule::table('mod_cloudflare_invite_rewards')
                ->where('period_start', $periodStart)
                ->where('period_end', $periodEnd)
                ->where('inviter_userid', $userId)
                ->first();
            if ($existing) {
                Capsule::table('mod_cloudflare_invite_rewards')->where('id', $existing->id)->update([
                    'rank' => $rank,
                    'count' => $count,
                    'code' => $code,
                    'status' => $status,
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
                self::flashSuccess('已更新当前周期榜单条目');
            } else {
                Capsule::table('mod_cloudflare_invite_rewards')->insert([
                    'period_start' => $periodStart,
                    'period_end' => $periodEnd,
                    'inviter_userid' => $userId,
                    'code' => $code,
                    'rank' => $rank,
                    'count' => $count,
                    'status' => $status,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
                self::flashSuccess('已新增当前周期榜单条目');
            }
        } catch (Exception $e) {
            self::flashError('操作失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_INVITE);
    }

    private static function handleAdminRebuildInviteRewards(): void
    {
        self::ensureInviteTables();
        $moduleSettings = self::moduleSettings();
        $topN = max(1, intval($moduleSettings['invite_leaderboard_top'] ?? 5));
        $periodDays = max(1, intval($moduleSettings['invite_leaderboard_period_days'] ?? 7));
        $overwrite = (($_POST['overwrite'] ?? '') === '1');
        $periodEnd = date('Y-m-d', strtotime('yesterday'));
        $periodStart = date('Y-m-d', strtotime($periodEnd . ' -' . ($periodDays - 1) . ' days'));

        try {
            if ($overwrite) {
                Capsule::table('mod_cloudflare_invite_rewards')
                    ->where('period_start', $periodStart)
                    ->where('period_end', $periodEnd)
                    ->delete();
            }
            $winners = Capsule::table('mod_cloudflare_invitation_claims as ic')
                ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as cnt'))
                ->whereBetween('ic.created_at', [$periodStart . ' 00:00:00', $periodEnd . ' 23:59:59'])
                ->groupBy('ic.inviter_userid')
                ->orderBy('cnt', 'desc')
                ->limit($topN)
                ->get();
            foreach ($winners as $index => $winner) {
                $codeRow = Capsule::table('mod_cloudflare_invitation_codes')->select('code')->where('userid', $winner->inviter_userid)->first();
                Capsule::table('mod_cloudflare_invite_rewards')->insert([
                    'period_start' => $periodStart,
                    'period_end' => $periodEnd,
                    'inviter_userid' => intval($winner->inviter_userid),
                    'code' => $codeRow->code ?? '',
                    'rank' => $index + 1,
                    'count' => intval($winner->cnt),
                    'status' => 'eligible',
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
            }
            self::flashSuccess('当前周期榜单已重建');
        } catch (Exception $e) {
            self::flashError('重建失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_INVITE);
    }

    private static function handleAdminSettleLastPeriod(): void
    {
        self::ensureInviteTables();
        $moduleSettings = self::moduleSettings();
        $topN = max(1, intval($moduleSettings['invite_leaderboard_top'] ?? 5));
        $periodDays = max(1, intval($moduleSettings['invite_leaderboard_period_days'] ?? 7));

        try {
            $periodEnd = date('Y-m-d', strtotime('yesterday'));
            $periodStart = date('Y-m-d', strtotime($periodEnd . ' -' . ($periodDays - 1) . ' days'));
            $exists = Capsule::table('mod_cloudflare_invite_leaderboard')
                ->where('period_start', $periodStart)
                ->where('period_end', $periodEnd)
                ->count();
            if ($exists) {
                throw new Exception('该周期已结算');
            }
            $winners = Capsule::table('mod_cloudflare_invitation_claims as ic')
                ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as cnt'))
                ->whereBetween('ic.created_at', [$periodStart . ' 00:00:00', $periodEnd . ' 23:59:59'])
                ->groupBy('ic.inviter_userid')
                ->orderBy('cnt', 'desc')
                ->limit($topN)
                ->get();
            $top = [];
            foreach ($winners as $idx => $winner) {
                $codeRow = Capsule::table('mod_cloudflare_invitation_codes')->select('code')->where('userid', $winner->inviter_userid)->first();
                $top[] = [
                    'rank' => $idx + 1,
                    'inviter_userid' => intval($winner->inviter_userid),
                    'code' => $codeRow->code ?? '',
                    'count' => intval($winner->cnt),
                ];
                $rewardExists = Capsule::table('mod_cloudflare_invite_rewards')
                    ->where('period_start', $periodStart)
                    ->where('period_end', $periodEnd)
                    ->where('inviter_userid', $winner->inviter_userid)
                    ->count();
                if (!$rewardExists) {
                    Capsule::table('mod_cloudflare_invite_rewards')->insert([
                        'period_start' => $periodStart,
                        'period_end' => $periodEnd,
                        'inviter_userid' => $winner->inviter_userid,
                        'code' => $codeRow->code ?? '',
                        'rank' => $idx + 1,
                        'count' => intval($winner->cnt),
                        'status' => 'eligible',
                        'created_at' => date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s'),
                    ]);
                }
            }
            Capsule::table('mod_cloudflare_invite_leaderboard')->insert([
                'period_start' => $periodStart,
                'period_end' => $periodEnd,
                'top_json' => json_encode($top, JSON_UNESCAPED_UNICODE),
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            self::flashSuccess('已结算上一期：' . $periodStart . ' ~ ' . $periodEnd);
        } catch (Exception $e) {
            self::flashError('手动结算失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_INVITE);
    }

    private static function handleGenerateInviteSnapshot(): void
    {
        self::ensureInviteTables();
        $moduleSettings = self::moduleSettings();
        $topN = max(1, intval($moduleSettings['invite_leaderboard_top'] ?? 5));
        $periodDays = max(1, intval($moduleSettings['invite_leaderboard_period_days'] ?? 7));

        try {
            $periodEnd = trim($_POST['period_end'] ?? date('Y-m-d', strtotime('yesterday')));
            $periodStart = date('Y-m-d', strtotime($periodEnd . ' -' . ($periodDays - 1) . ' days'));
            $exists = Capsule::table('mod_cloudflare_invite_leaderboard')
                ->where('period_start', $periodStart)
                ->where('period_end', $periodEnd)
                ->count();
            if ($exists) {
                throw new Exception('该周期快照已存在');
            }
            $winners = Capsule::table('mod_cloudflare_invitation_claims as ic')
                ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as cnt'))
                ->whereBetween('ic.created_at', [$periodStart . ' 00:00:00', $periodEnd . ' 23:59:59'])
                ->groupBy('ic.inviter_userid')
                ->orderBy('cnt', 'desc')
                ->limit($topN)
                ->get();
            $top = [];
            foreach ($winners as $idx => $winner) {
                $codeRow = Capsule::table('mod_cloudflare_invitation_codes')->select('code')->where('userid', $winner->inviter_userid)->first();
                $top[] = [
                    'rank' => $idx + 1,
                    'inviter_userid' => intval($winner->inviter_userid),
                    'code' => $codeRow->code ?? '',
                    'count' => intval($winner->cnt),
                ];
            }
            Capsule::table('mod_cloudflare_invite_leaderboard')->insert([
                'period_start' => $periodStart,
                'period_end' => $periodEnd,
                'top_json' => json_encode($top, JSON_UNESCAPED_UNICODE),
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            self::flashSuccess('快照已生成');
        } catch (Exception $e) {
            self::flashError('生成失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_SNAPSHOTS);
    }

    private static function handleRemoveLeaderboardUser(): void
    {
        try {
            $periodStart = trim($_POST['period_start'] ?? '');
            $periodEnd = trim($_POST['period_end'] ?? '');
            $userId = intval($_POST['userid'] ?? 0);
            if ($periodStart === '' || $periodEnd === '' || !$userId) {
                throw new Exception('缺少必要参数');
            }
            Capsule::table('mod_cloudflare_invite_rewards')
                ->where('period_start', $periodStart)
                ->where('period_end', $periodEnd)
                ->where('inviter_userid', $userId)
                ->delete();
            $snap = Capsule::table('mod_cloudflare_invite_leaderboard')
                ->where('period_start', $periodStart)
                ->where('period_end', $periodEnd)
                ->first();
            if ($snap && $snap->top_json) {
                $arr = json_decode($snap->top_json, true) ?: [];
                $arr = array_values(array_filter($arr, function ($row) use ($userId) {
                    return intval($row['inviter_userid'] ?? 0) !== $userId;
                }));
                foreach ($arr as $idx => &$row) {
                    $row['rank'] = $idx + 1;
                }
                Capsule::table('mod_cloudflare_invite_leaderboard')
                    ->where('id', $snap->id)
                    ->update([
                        'top_json' => json_encode($arr, JSON_UNESCAPED_UNICODE),
                        'updated_at' => date('Y-m-d H:i:s'),
                    ]);
            }
            self::flashSuccess('已移除该上榜用户');
        } catch (Exception $e) {
            self::flashError('移除失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_INVITE);
    }

    private static function handleAdminEditLeaderboardUser(): void
    {
        try {
            $rewardId = intval($_POST['reward_id'] ?? 0);
            if ($rewardId <= 0) {
                throw new Exception('缺少ID');
            }
            $rank = max(1, intval($_POST['rank'] ?? 1));
            $count = max(0, intval($_POST['count'] ?? 0));
            $code = trim($_POST['code'] ?? '');
            $row = Capsule::table('mod_cloudflare_invite_rewards')->where('id', $rewardId)->first();
            if (!$row) {
                throw new Exception('记录不存在');
            }
            Capsule::table('mod_cloudflare_invite_rewards')->where('id', $rewardId)->update([
                'rank' => $rank,
                'count' => $count,
                'code' => $code,
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            $snap = Capsule::table('mod_cloudflare_invite_leaderboard')
                ->where('period_start', $row->period_start)
                ->where('period_end', $row->period_end)
                ->first();
            if ($snap && $snap->top_json) {
                $arr = json_decode($snap->top_json, true) ?: [];
                foreach ($arr as &$entry) {
                    if (intval($entry['inviter_userid'] ?? 0) === intval($row->inviter_userid)) {
                        $entry['rank'] = $rank;
                        $entry['count'] = $count;
                        $entry['code'] = $code;
                        break;
                    }
                }
                usort($arr, function ($a, $b) {
                    return intval($a['rank'] ?? 0) <=> intval($b['rank'] ?? 0);
                });
                Capsule::table('mod_cloudflare_invite_leaderboard')
                    ->where('id', $snap->id)
                    ->update([
                        'top_json' => json_encode($arr, JSON_UNESCAPED_UNICODE),
                        'updated_at' => date('Y-m-d H:i:s'),
                    ]);
            }
            self::flashSuccess('已修改上榜用户');
        } catch (Exception $e) {
            self::flashError('修改失败: ' . $e->getMessage());
        }

        self::redirect(self::HASH_INVITE);
    }

    private static function handleAddPrivilegedUser(): void
    {
        try {
            $userId = intval($_POST['user_id'] ?? 0);
            if ($userId <= 0) {
                throw new Exception('用户ID无效');
            }
            $user = Capsule::table('tblclients')->where('id', $userId)->first();
            if (!$user) {
                throw new Exception('用户ID ' . $userId . ' 不存在');
            }
            $notes = trim((string) ($_POST['notes'] ?? ''));
            if ($notes !== '') {
                $notes = function_exists('mb_substr') ? mb_substr($notes, 0, 255, 'UTF-8') : substr($notes, 0, 255);
            } else {
                $notes = null;
            }
            $settings = self::moduleSettings();
            $inviteLimitGlobal = intval($settings['invite_bonus_limit_global'] ?? 5);
            if ($inviteLimitGlobal <= 0) {
                $inviteLimitGlobal = 5;
            }
            $now = date('Y-m-d H:i:s');
            $exists = Capsule::table('mod_cloudflare_special_users')->where('userid', $userId)->first();
            if ($exists) {
                Capsule::table('mod_cloudflare_special_users')
                    ->where('userid', $userId)
                    ->update([
                        'notes' => $notes,
                        'updated_at' => $now,
                    ]);
            } else {
                Capsule::table('mod_cloudflare_special_users')->insert([
                    'userid' => $userId,
                    'notes' => $notes,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
            }
            if (function_exists('cf_clear_privileged_cache')) {
                cf_clear_privileged_cache();
            }
            if (function_exists('cf_mark_user_domains_never_expires')) {
                cf_mark_user_domains_never_expires($userId);
            }
            if (function_exists('cf_ensure_privileged_quota')) {
                cf_ensure_privileged_quota($userId, null, $inviteLimitGlobal);
            }
            $name = trim((string) ($user->firstname ?? '') . ' ' . (string) ($user->lastname ?? ''));
            if ($name === '') {
                $name = $user->email ?? ('ID:' . $userId);
            }
            self::flashSuccess('✅ 已为用户 <strong>' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</strong> (ID:' . $userId . ') 启用特权功能。');
        } catch (Exception $e) {
            self::flashError('❌ 启用特权功能失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_PRIVILEGED);
    }

    private static function handleRemovePrivilegedUser(): void
    {
        try {
            $userId = intval($_POST['user_id'] ?? 0);
            if ($userId <= 0) {
                throw new Exception('用户ID无效');
            }
            $user = Capsule::table('tblclients')->where('id', $userId)->first();
            if (!$user) {
                throw new Exception('用户ID ' . $userId . ' 不存在');
            }
            Capsule::table('mod_cloudflare_special_users')->where('userid', $userId)->delete();
            if (function_exists('cf_clear_privileged_cache')) {
                cf_clear_privileged_cache();
            }
            $settings = self::moduleSettings();
            $baseMax = max(0, intval($settings['max_subdomain_per_user'] ?? 0));
            $inviteLimitGlobal = intval($settings['invite_bonus_limit_global'] ?? 5);
            if ($inviteLimitGlobal <= 0) {
                $inviteLimitGlobal = 5;
            }
            if (function_exists('cf_reset_user_quota_to_base')) {
                cf_reset_user_quota_to_base($userId, $baseMax, $inviteLimitGlobal);
            }
            $name = trim((string) ($user->firstname ?? '') . ' ' . (string) ($user->lastname ?? ''));
            if ($name === '') {
                $name = $user->email ?? ('ID:' . $userId);
            }
            self::flashSuccess('ℹ️ 已取消用户 <strong>' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</strong> (ID:' . $userId . ') 的特权功能。');
        } catch (Exception $e) {
            self::flashError('❌ 取消特权失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_PRIVILEGED);
    }

    private static function handleAdminSetUserQuota(): void
    {
        self::handleUserQuotaUpdate(true);
    }

    private static function handleUpdateUserQuota(): void
    {
        self::handleUserQuotaUpdate(false);
    }

    private static function handleUserQuotaUpdate(bool $legacyPayload): void
    {
        try {
            $userId = intval($_POST['user_id'] ?? 0);
            $email = trim((string) ($_POST['user_email'] ?? ''));
            if ($userId <= 0 && !$legacyPayload && $email !== '') {
                $userLookup = Capsule::table('tblclients')->where('email', $email)->first();
                if ($userLookup) {
                    $userId = intval($userLookup->id);
                }
            }
            if ($userId <= 0) {
                throw new Exception('用户ID无效');
            }
            $user = Capsule::table('tblclients')->where('id', $userId)->first();
            if (!$user) {
                throw new Exception('用户不存在');
            }
            $quotaValue = null;
            foreach (['new_quota', 'max_count'] as $field) {
                if (isset($_POST[$field]) && $_POST[$field] !== '') {
                    $quotaValue = intval($_POST[$field]);
                    break;
                }
            }
            if ($quotaValue === null) {
                throw new Exception('请填写新的配额值');
            }
            $quotaValue = max(0, min(99999999999, $quotaValue));
            $inviteLimitInput = null;
            if (isset($_POST['invite_bonus_limit']) && $_POST['invite_bonus_limit'] !== '') {
                $inviteLimitInput = max(0, min(99999999999, intval($_POST['invite_bonus_limit'])));
            }
            $settings = self::moduleSettings();
            $quotaRow = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userId)->first();
            if ($quotaRow) {
                $updateData = [
                    'max_count' => $quotaValue,
                    'updated_at' => date('Y-m-d H:i:s'),
                ];
                if ($inviteLimitInput !== null) {
                    $updateData['invite_bonus_limit'] = $inviteLimitInput;
                }
                Capsule::table('mod_cloudflare_subdomain_quotas')
                    ->where('userid', $userId)
                    ->update($updateData);
            } else {
                $usedCount = Capsule::table('mod_cloudflare_subdomain')->where('userid', $userId)->count();
                if ($inviteLimitInput === null) {
                    $inviteLimitInput = max(0, intval($settings['invite_bonus_limit_global'] ?? 5));
                }
                Capsule::table('mod_cloudflare_subdomain_quotas')->insert([
                    'userid' => $userId,
                    'used_count' => $usedCount,
                    'max_count' => $quotaValue,
                    'invite_bonus_count' => 0,
                    'invite_bonus_limit' => $inviteLimitInput,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
            }
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_update_user_quota', [
                    'userid' => $userId,
                    'new_quota' => $quotaValue,
                    'invite_bonus_limit' => $inviteLimitInput,
                ]);
            }
            $name = trim((string) ($user->firstname ?? '') . ' ' . (string) ($user->lastname ?? ''));
            if ($name === '') {
                $name = $user->email ?? ('ID:' . $userId);
            }
            $limitText = $inviteLimitInput !== null ? '，邀请上限 ' . $inviteLimitInput : '';
            self::flashSuccess('✅ 用户 <strong>' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</strong> 配额已更新为 ' . $quotaValue . $limitText);
        } catch (Exception $e) {
            self::flashError('❌ 更新用户配额失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_QUOTAS);
    }

    private static function handleToggleQuotaRedeem(): void
    {
        try {
            $enable = ($_POST['enable_quota_redeem'] ?? '') === '1';
            self::persistModuleSetting('enable_quota_redeem', $enable ? '1' : '0');
            self::flashSuccess($enable ? '✅ 兑换功能已开启' : '✅ 兑换功能已关闭');
        } catch (Exception $e) {
            self::flashError('❌ 更新兑换功能状态失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_QUOTAS);
    }

    private static function handleCreateRedeemCode(): void
    {
        try {
            if (class_exists('CfQuotaRedeemService')) {
                CfQuotaRedeemService::ensureTables();
            }
            $code = strtoupper(trim((string) ($_POST['code'] ?? '')));
            if ($code === '') {
                $code = CfQuotaRedeemService::randomCode();
            }
            if (strlen($code) > 191) {
                throw new Exception('兑换码长度不能超过 191 个字符');
            }
            $exists = Capsule::table('mod_cloudflare_quota_codes')->where('code', $code)->exists();
            if ($exists) {
                throw new Exception('该兑换码已存在，请更换其他值');
            }
            $grantAmount = max(1, intval($_POST['grant_amount'] ?? 1));
            $mode = ($_POST['mode'] ?? 'single_use') === 'multi_use' ? 'multi_use' : 'single_use';
            $maxTotal = max(0, intval($_POST['max_total_uses'] ?? 1));
            $perUserLimit = max(1, intval($_POST['per_user_limit'] ?? 1));
            if ($mode === 'single_use') {
                $maxTotal = 1;
                $perUserLimit = 1;
            } elseif ($maxTotal > 0 && $maxTotal < $perUserLimit) {
                $maxTotal = $perUserLimit;
            }
            $validToRaw = trim((string) ($_POST['valid_to'] ?? ''));
            $validTo = null;
            if ($validToRaw !== '') {
                $ts = strtotime($validToRaw);
                if ($ts === false) {
                    throw new Exception('兑换码截止时间格式无效');
                }
                $validTo = date('Y-m-d H:i:s', $ts);
            }
            $notes = trim((string) ($_POST['notes'] ?? ''));
            $now = date('Y-m-d H:i:s');
            Capsule::table('mod_cloudflare_quota_codes')->insert([
                'code' => $code,
                'grant_amount' => $grantAmount,
                'mode' => $mode,
                'max_total_uses' => $maxTotal,
                'per_user_limit' => $perUserLimit,
                'redeemed_total' => 0,
                'valid_from' => $now,
                'valid_to' => $validTo,
                'status' => 'active',
                'batch_tag' => null,
                'created_by_admin_id' => null,
                'notes' => $notes !== '' ? $notes : null,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            self::flashSuccess('✅ 兑换码 ' . htmlspecialchars($code) . ' 已创建');
        } catch (Exception $e) {
            self::flashError('❌ 创建兑换码失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_QUOTAS);
    }

    private static function handleGenerateRedeemCodes(): void
    {
        try {
            if (class_exists('CfQuotaRedeemService')) {
                CfQuotaRedeemService::ensureTables();
            }
            $count = max(1, min(200, intval($_POST['count'] ?? 1)));
            $grantAmount = max(1, intval($_POST['grant_amount'] ?? 1));
            $mode = ($_POST['mode'] ?? 'multi_use') === 'single_use' ? 'single_use' : 'multi_use';
            $maxTotal = max(0, intval($_POST['max_total_uses'] ?? 0));
            $perUserLimit = max(1, intval($_POST['per_user_limit'] ?? 1));
            $validDays = max(0, intval($_POST['valid_days'] ?? 0));
            $batchTag = trim((string) ($_POST['batch_tag'] ?? ''));
            $notes = trim((string) ($_POST['notes'] ?? ''));
            if ($mode === 'single_use') {
                $maxTotal = 1;
                $perUserLimit = 1;
            } elseif ($maxTotal > 0 && $maxTotal < $perUserLimit) {
                $maxTotal = $perUserLimit;
            }
            $now = date('Y-m-d H:i:s');
            $validTo = $validDays > 0 ? date('Y-m-d H:i:s', strtotime('+' . $validDays . ' days')) : null;
            $rows = [];
            for ($i = 0; $i < $count; $i++) {
                $code = CfQuotaRedeemService::randomCode();
                $attempts = 0;
                while (Capsule::table('mod_cloudflare_quota_codes')->where('code', $code)->exists()) {
                    $code = CfQuotaRedeemService::randomCode();
                    $attempts++;
                    if ($attempts > 5) {
                        throw new Exception('生成兑换码时出现重复，请重试');
                    }
                }
                $rows[] = [
                    'code' => $code,
                    'grant_amount' => $grantAmount,
                    'mode' => $mode,
                    'max_total_uses' => $maxTotal,
                    'per_user_limit' => $perUserLimit,
                    'redeemed_total' => 0,
                    'valid_from' => $now,
                    'valid_to' => $validTo,
                    'status' => 'active',
                    'batch_tag' => $batchTag !== '' ? $batchTag : null,
                    'created_by_admin_id' => null,
                    'notes' => $notes !== '' ? $notes : null,
                    'created_at' => $now,
                    'updated_at' => $now,
                ];
            }
            Capsule::table('mod_cloudflare_quota_codes')->insert($rows);
            self::flashSuccess('✅ 已批量生成 ' . count($rows) . ' 个兑换码');
        } catch (Exception $e) {
            self::flashError('❌ 批量生成失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_QUOTAS);
    }

    private static function handleToggleRedeemCodeStatus(): void
    {
        try {
            $codeId = intval($_POST['code_id'] ?? 0);
            $target = ($_POST['target_status'] ?? '') === 'active' ? 'active' : 'disabled';
            if ($codeId <= 0) {
                throw new Exception('参数无效');
            }
            $codeRow = Capsule::table('mod_cloudflare_quota_codes')->where('id', $codeId)->first();
            if (!$codeRow) {
                throw new Exception('兑换码不存在');
            }
            Capsule::table('mod_cloudflare_quota_codes')->where('id', $codeId)->update([
                'status' => $target,
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            self::flashSuccess($target === 'active' ? '✅ 兑换码已启用' : '✅ 兑换码已停用');
        } catch (Exception $e) {
            self::flashError('❌ 更新兑换码状态失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_QUOTAS);
    }

    private static function handleDeleteRedeemCode(): void
    {
        try {
            $codeId = intval($_POST['code_id'] ?? 0);
            if ($codeId <= 0) {
                throw new Exception('参数无效');
            }
            $codeRow = Capsule::table('mod_cloudflare_quota_codes')->where('id', $codeId)->first();
            if (!$codeRow) {
                throw new Exception('兑换码不存在或已删除');
            }
            Capsule::table('mod_cloudflare_quota_codes')->where('id', $codeId)->delete();
            self::flashSuccess('✅ 已删除兑换码 ' . htmlspecialchars($codeRow->code));
        } catch (Exception $e) {
            self::flashError('❌ 删除兑换码失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }
        self::redirect(self::HASH_QUOTAS);
    }

    private static function handleAdminAdjustExpiry(): void
    {
        $subdomainId = intval($_POST['subdomain_id'] ?? 0);
        $mode = (string) ($_POST['mode'] ?? 'set');
        if ($subdomainId <= 0) {
            self::flashError('无效的子域名ID');
            self::redirect(self::HASH_SUBDOMAINS);
        }

        try {
            $subdomain = Capsule::table('mod_cloudflare_subdomain')->where('id', $subdomainId)->first();
            if (!$subdomain) {
                throw new Exception('子域名不存在');
            }
            $label = trim((string) ($subdomain->subdomain ?? ''));
            if ($label === '') {
                $label = 'ID#' . $subdomainId;
            }
            $now = date('Y-m-d H:i:s');
            $updates = ['updated_at' => $now];
            $targetExpiryTs = null;
            $extendDays = null;
            $logDetails = [
                'subdomain' => $label,
                'previous_expires_at' => $subdomain->expires_at ?? null,
                'previous_never_expires' => intval($subdomain->never_expires ?? 0),
                'mode' => $mode,
            ];

            if ($mode === 'set') {
                $inputRaw = trim((string) ($_POST['expires_at_input'] ?? ''));
                if ($inputRaw === '') {
                    throw new Exception('请输入新的到期时间');
                }
                $parsedTs = strtotime(str_replace('T', ' ', $inputRaw));
                if ($parsedTs === false) {
                    throw new Exception('无法解析到期时间');
                }
                $targetExpiryTs = $parsedTs;
                $updates['expires_at'] = date('Y-m-d H:i:s', $parsedTs);
                $updates['never_expires'] = 0;
                $updates['renewed_at'] = $now;
                $updates['auto_deleted_at'] = null;
            } elseif (preg_match('/^extend(\d+)$/', $mode, $matches)) {
                $extendDays = intval($matches[1]);
                if ($extendDays <= 0) {
                    throw new Exception('无效的延长天数');
                }
                if (intval($subdomain->never_expires ?? 0) === 1) {
                    throw new Exception('当前域名为永久有效，请先保存新的到期时间');
                }
                $baseTs = $subdomain->expires_at ? strtotime($subdomain->expires_at) : time();
                if ($baseTs === false || $baseTs < time()) {
                    $baseTs = time();
                }
                $newExpiryTs = strtotime('+' . $extendDays . ' days', $baseTs);
                if ($newExpiryTs === false) {
                    throw new Exception('续期计算失败，请稍后重试');
                }
                $targetExpiryTs = $newExpiryTs;
                $updates['expires_at'] = date('Y-m-d H:i:s', $newExpiryTs);
                $updates['never_expires'] = 0;
                $updates['renewed_at'] = $now;
                $updates['auto_deleted_at'] = null;
                $logDetails['extend_days'] = $extendDays;
            } elseif ($mode === 'never') {
                $updates['expires_at'] = null;
                $updates['never_expires'] = 1;
                $updates['auto_deleted_at'] = null;
            } else {
                throw new Exception('未知操作类型');
            }

            Capsule::table('mod_cloudflare_subdomain')
                ->where('id', $subdomainId)
                ->update($updates);

            $logDetails['new_expires_at'] = $updates['expires_at'] ?? null;
            $logDetails['new_never_expires'] = $updates['never_expires'] ?? intval($subdomain->never_expires ?? 0);
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_adjust_subdomain_expiry', $logDetails, intval($subdomain->userid ?? 0), $subdomainId);
            }

            $displayExpiry = $targetExpiryTs !== null ? date('Y-m-d H:i', $targetExpiryTs) : null;
            $labelSafe = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
            if ($mode === 'never') {
                self::flashSuccess('已将 ' . $labelSafe . ' 设置为永不过期');
            } elseif ($mode === 'set') {
                self::flashSuccess('已将 ' . $labelSafe . ' 的到期时间更新为 ' . ($displayExpiry ?? '未设置'));
            } else {
                self::flashSuccess('已为 ' . $labelSafe . ' 延长 ' . $extendDays . ' 天，新到期时间：' . ($displayExpiry ?? '未设置'));
            }
        } catch (Exception $e) {
            self::flashError('调整到期失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_SUBDOMAINS);
    }

    private static function handleResetModule(): void
    {
        $confirm = trim((string)($_POST['confirm'] ?? ''));
        if ($confirm !== 'RESET') {
            self::flash('请在确认框输入 RESET 以执行重置', 'warning');
            self::redirect(self::HASH_JOBS);
        }

        $tables = [
            'mod_cloudflare_dns_records',
            'mod_cloudflare_sync_results',
            'mod_cloudflare_jobs',
            'mod_cloudflare_logs',
            'mod_cloudflare_domain_risk',
            'mod_cloudflare_risk_events',
            'mod_cloudflare_forbidden_domains',
            'mod_cloudflare_user_stats',
            'mod_cloudflare_user_bans',
            'mod_cloudflare_invitation_claims',
            'mod_cloudflare_invitation_codes',
            'mod_cloudflare_invite_leaderboard',
            'mod_cloudflare_invite_rewards',
            'mod_cloudflare_subdomain',
            'mod_cloudflare_subdomain_quotas',
            'mod_cloudflare_rootdomains',
            'mod_cloudflare_api_keys',
            'mod_cloudflare_api_logs',
            'mod_cloudflare_api_rate_limit',
        ];

        try {
            $clearedCount = 0;
            foreach ($tables as $table) {
                if (!Capsule::schema()->hasTable($table)) {
                    continue;
                }
                try {
                    Capsule::statement("TRUNCATE TABLE `{$table}`");
                } catch (Exception $e) {
                    Capsule::table($table)->delete();
                    Capsule::statement("ALTER TABLE `{$table}` AUTO_INCREMENT = 1");
                }
                $clearedCount++;
            }

            try {
                Capsule::table('tbladdonmodules')->whereIn('module', self::moduleSlugList())->delete();
            } catch (Exception $e) {
                // ignore cleanup failures
            }
            if (function_exists('cf_clear_settings_cache')) {
                cf_clear_settings_cache();
            }
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_reset_module', [
                    'cleared_tables' => $clearedCount,
                    'total_tables' => count($tables),
                ]);
            }
            self::flashSuccess('已完成本地数据清理并重置插件配置（已清空 ' . $clearedCount . ' 个数据表，所有ID已重置为1）');
        } catch (Exception $e) {
            self::flashError('重置失败: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_JOBS);
    }

    private static function handleBatchDelete(): void
    {
        $selected = $_POST['selected_ids'] ?? [];
        if (!is_array($selected) || count($selected) === 0) {
            self::flash('请选择要删除的子域名', 'warning');
            self::redirect(self::HASH_SUBDOMAINS);
        }

        $moduleSettings = self::moduleSettings();
        $deletedCount = 0;
        $totalDnsDeleted = 0;

        try {
            foreach ($selected as $rawId) {
                $subId = intval($rawId);
                if ($subId <= 0) {
                    continue;
                }
                $record = Capsule::table('mod_cloudflare_subdomain')->where('id', $subId)->first();
                if (!$record) {
                    continue;
                }
                $client = null;
                if (function_exists('cfmod_acquire_provider_client_for_subdomain')) {
                    $providerContext = cfmod_acquire_provider_client_for_subdomain($record, $moduleSettings);
                    $client = $providerContext['client'] ?? null;
                }
                $deletedDns = 0;
                if (function_exists('cfmod_admin_deep_delete_subdomain')) {
                    $deletedDns = intval(cfmod_admin_deep_delete_subdomain($client, $record));
                }
                Capsule::table('mod_cloudflare_subdomain')->where('id', $subId)->delete();
                Capsule::table('mod_cloudflare_subdomain_quotas')
                    ->where('userid', $record->userid)
                    ->decrement('used_count');
                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('admin_batch_delete_subdomain', [
                        'subdomain' => $record->subdomain,
                        'dns_records_deleted' => $deletedDns,
                    ], $record->userid, $record->id);
                }
                $deletedCount++;
                $totalDnsDeleted += $deletedDns;
            }

            if ($deletedCount === 0) {
                self::flash('未删除任何子域名，请选择要处理的记录后再试。', 'warning');
            } else {
                $dnsSummary = $totalDnsDeleted > 0 ? '，清理 DNS 记录 ' . $totalDnsDeleted . ' 条' : '';
                self::flashSuccess('批量删除成功，共删除 ' . $deletedCount . ' 个子域名' . $dnsSummary);
            }
        } catch (Exception $e) {
            self::flashError('批量删除失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_SUBDOMAINS);
    }

    private static function handleScanOrphanRecords(): void
    {
        $rootdomain = strtolower(trim((string)($_POST['orphan_rootdomain'] ?? '')));
        $limit = intval($_POST['orphan_subdomain_limit'] ?? 100);
        if ($limit < 10) { $limit = 10; }
        if ($limit > 500) { $limit = 500; }
        $mode = $_POST['orphan_mode'] ?? 'dry';
        $cursorMode = strtolower(trim((string)($_POST['orphan_cursor_mode'] ?? 'resume')));
        if (!in_array($cursorMode, ['resume', 'reset'], true)) {
            $cursorMode = 'resume';
        }

        $payload = [
            'rootdomain' => $rootdomain,
            'limit' => $limit,
            'mode' => $mode,
            'cursor_mode' => $cursorMode,
            'requested_by_admin' => isset($_SESSION['adminid']) ? (int) $_SESSION['adminid'] : 0,
        ];

        try {
            $jobId = Capsule::table('mod_cloudflare_jobs')->insertGetId([
                'type' => 'cleanup_orphan_dns',
                'payload_json' => json_encode($payload, JSON_UNESCAPED_UNICODE),
                'priority' => 12,
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ]);
            self::triggerQueueInBackground();
            self::flashSuccess('孤儿记录扫描任务已加入队列（Job #' . $jobId . '），系统会自动批量处理直至完成。');
        } catch (Exception $e) {
            self::flashError('提交孤儿记录扫描任务失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_RUNTIME);
    }

    public static function executeOrphanScan(array $params = []): array
    {
        $rootdomain = strtolower(trim((string)($params['rootdomain'] ?? '')));
        $limit = intval($params['limit'] ?? 100);
        if ($limit < 10) { $limit = 10; }
        if ($limit > 500) { $limit = 500; }
        $mode = $params['mode'] ?? 'dry';
        $cursorMode = strtolower(trim((string)($params['cursor_mode'] ?? 'resume')));
        if (!in_array($cursorMode, ['resume', 'reset'], true)) {
            $cursorMode = 'resume';
        }
        $dryRun = $mode !== 'delete';

        if ($cursorMode === 'reset') {
            self::setOrphanCursor($rootdomain, 0);
        }
        $lastCursor = self::getOrphanCursor($rootdomain);

        $query = Capsule::table('mod_cloudflare_subdomain')->orderBy('id', 'asc');
        if ($rootdomain !== '') {
            $query->whereRaw('LOWER(rootdomain) = ?', [$rootdomain]);
        }
        if ($cursorMode === 'resume' && $lastCursor > 0) {
            $query->where('id', '>', $lastCursor);
        }
        $subdomains = $query->limit($limit)->get();
        $subdomainItems = self::normalizeRecordList($subdomains);
        $subdomainCount = count($subdomainItems);
        if ($subdomainCount === 0) {
            $message = '未找到符合条件的子域名，请尝试选择“从头开始”或调整根域/数量。';
            if ($lastCursor > 0) {
                $message .= '（当前游标：' . $lastCursor . '）';
            }
            return [
                'scanned_subdomains' => 0,
                'total_records' => 0,
                'orphans_found' => 0,
                'deleted' => 0,
                'cursor' => $lastCursor,
                'mode' => $mode,
                'dry_run' => $dryRun ? 1 : 0,
                'warnings' => [],
                'has_more' => false,
                'message' => $message,
            ];
        }

        $settings = self::moduleSettings();
        $providerService = CfProviderService::instance();
        $providerCache = [];
        $totalRecords = 0;
        $orphans = [];
        $warnings = [];

        foreach ($subdomainItems as $subItem) {
            $sub = is_array($subItem) ? (object) $subItem : $subItem;
            $cacheKey = self::buildProviderCacheKey($sub);
            if (!isset($providerCache[$cacheKey])) {
                $providerCache[$cacheKey] = $providerService->acquireProviderClientForSubdomain($sub, $settings);
            }
            $context = $providerCache[$cacheKey];
            if (!$context || empty($context['client'])) {
                $warnings[] = 'provider:' . ($sub->id ?? 'unknown');
                continue;
            }
            $client = $context['client'];
            $zoneId = $sub->cloudflare_zone_id ?: ($sub->rootdomain ?? null);
            if (!$zoneId) {
                $warnings[] = 'zone:' . ($sub->id ?? 'unknown');
                continue;
            }

            try {
                $remote = $client->getDnsRecords($zoneId, $sub->subdomain);
            } catch (\Throwable $e) {
                $warnings[] = 'remote:' . ($sub->id ?? 'unknown');
                continue;
            }
            if (!($remote['success'] ?? false)) {
                $warnings[] = 'remote:' . ($sub->id ?? 'unknown');
                continue;
            }

            $remoteIds = [];
            $remoteKeys = [];
            foreach (($remote['result'] ?? []) as $rr) {
                $rid = isset($rr['id']) ? (string) $rr['id'] : '';
                if ($rid !== '') {
                    $remoteIds[$rid] = true;
                }
                $remoteKeys[self::normalizeDnsRecordKey($rr['name'] ?? '', $rr['type'] ?? '', $rr['content'] ?? '')] = true;
            }

            $locals = Capsule::table('mod_cloudflare_dns_records')
                ->where('subdomain_id', $sub->id)
                ->get();
            foreach ($locals as $lr) {
                $totalRecords++;
                $localRecordId = trim((string)($lr->record_id ?? ''));
                $isOrphan = true;
                if ($localRecordId !== '' && isset($remoteIds[$localRecordId])) {
                    $isOrphan = false;
                } else {
                    $localKey = self::normalizeDnsRecordKey($lr->name ?? '', $lr->type ?? '', $lr->content ?? '');
                    if (isset($remoteKeys[$localKey])) {
                        $isOrphan = false;
                    }
                }
                if ($isOrphan) {
                    $orphans[] = [
                        'id' => intval($lr->id),
                        'subdomain_id' => intval($sub->id),
                        'subdomain' => (string)($sub->subdomain ?? ''),
                        'rootdomain' => (string)($sub->rootdomain ?? ''),
                        'name' => (string)($lr->name ?? ''),
                        'type' => strtoupper((string)($lr->type ?? '')),
                        'content' => (string)($lr->content ?? ''),
                        'record_id' => $localRecordId,
                    ];
                }
            }
        }

        $orphanCount = count($orphans);
        $deletedCount = 0;
        if (!$dryRun && $orphanCount > 0) {
            $ids = array_column($orphans, 'id');
            foreach (array_chunk($ids, 500) as $chunk) {
                $deletedCount += Capsule::table('mod_cloudflare_dns_records')->whereIn('id', $chunk)->delete();
            }
            if (function_exists('cloudflare_subdomain_log')) {
                foreach ($orphans as $entry) {
                    cloudflare_subdomain_log('admin_cleanup_orphan_dns', [
                        'record' => $entry['name'] . ' ' . $entry['type'],
                        'content' => $entry['content'],
                    ], null, $entry['subdomain_id']);
                }
            }
            self::clearPrimaryPointersForOrphans($orphans);
        }

        $lastSubdomain = $subdomainItems[$subdomainCount - 1] ?? null;
        if (is_array($lastSubdomain)) {
            $lastProcessedId = intval($lastSubdomain['id'] ?? 0);
        } elseif (is_object($lastSubdomain)) {
            $lastProcessedId = intval($lastSubdomain->id ?? 0);
        } else {
            $lastProcessedId = 0;
        }
        if ($lastProcessedId > 0) {
            self::setOrphanCursor($rootdomain, $lastProcessedId);
        }
        $currentCursor = self::getOrphanCursor($rootdomain);

        $hasMore = false;
        if ($lastProcessedId > 0) {
            $moreQuery = Capsule::table('mod_cloudflare_subdomain')->where('id', '>', $lastProcessedId);
            if ($rootdomain !== '') {
                $moreQuery->whereRaw('LOWER(rootdomain) = ?', [$rootdomain]);
            }
            $hasMore = (bool) $moreQuery->exists();
        }

        $message = sprintf(
            '已扫描 %d 个子域，共 %d 条记录，发现 %d 条孤儿记录。',
            $subdomainCount,
            $totalRecords,
            $orphanCount
        );
        if ($dryRun) {
            $message .= '（干跑，仅统计）';
        } else {
            $message .= ' 已删除 ' . $deletedCount . ' 条孤儿记录。';
        }
        $message .= ' 当前游标：' . $currentCursor . '。';
        if ($subdomainCount >= $limit) {
            $message .= ' 可继续执行以扫描下一批子域。';
        } else {
            $message .= ' 已到达末尾，如需重头扫描请选择“从头开始”。';
        }
        if ($rootdomain !== '') {
            $message .= ' 根域：' . $rootdomain . '。';
        }
        if ($orphanCount > 0) {
            $preview = array_slice($orphans, 0, 5);
            $parts = [];
            foreach ($preview as $sample) {
                $label = ($sample['subdomain'] ?: $sample['rootdomain']) . ' - ' . $sample['type'];
                $parts[] = $label;
            }
            if (!empty($parts)) {
                $message .= ' 示例：' . implode('，', $parts);
            }
        }
        if (!empty($warnings)) {
            $message .= ' （有 ' . count($warnings) . ' 个子域因供应商或远端错误被跳过）';
        }

        return [
            'scanned_subdomains' => $subdomainCount,
            'total_records' => $totalRecords,
            'orphans_found' => $orphanCount,
            'deleted' => $deletedCount,
            'cursor' => $currentCursor,
            'mode' => $mode,
            'dry_run' => $dryRun ? 1 : 0,
            'warnings' => $warnings,
            'rootdomain' => $rootdomain,
            'has_more' => $hasMore,
            'next_cursor' => $hasMore ? $currentCursor : null,
            'message' => $message,
        ];
    }

    private static function handleDeleteSubdomain(): void
    {
        $subdomainId = intval($_POST['subdomain_id'] ?? ($_POST['id'] ?? 0));
        if ($subdomainId <= 0) {
            self::flashError('子域名ID无效');
            self::redirect(self::HASH_SUBDOMAINS);
        }

        try {
            $record = Capsule::table('mod_cloudflare_subdomain')->where('id', $subdomainId)->first();
            if (!$record) {
                throw new Exception('子域名不存在或已删除');
            }
            $moduleSettings = self::moduleSettings();
            $client = null;
            if (function_exists('cfmod_acquire_provider_client_for_subdomain')) {
                $providerContext = cfmod_acquire_provider_client_for_subdomain($record, $moduleSettings);
                $client = $providerContext['client'] ?? null;
            }
            $deletedDns = 0;
            if (function_exists('cfmod_admin_deep_delete_subdomain')) {
                $deletedDns = intval(cfmod_admin_deep_delete_subdomain($client, $record));
            }
            Capsule::table('mod_cloudflare_subdomain')->where('id', $subdomainId)->delete();
            Capsule::table('mod_cloudflare_subdomain_quotas')
                ->where('userid', $record->userid)
                ->decrement('used_count');
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_delete_subdomain', [
                    'subdomain' => $record->subdomain,
                    'dns_records_deleted' => $deletedDns,
                ], intval($record->userid ?? 0), $subdomainId);
            }
            $dnsSummary = $deletedDns > 0 ? '（同时清理 ' . $deletedDns . ' 条 DNS 记录）' : '';
            self::flashSuccess('子域名删除成功' . $dnsSummary);
        } catch (Exception $e) {
            self::flashError('删除子域名失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_SUBDOMAINS);
    }

    private static function handleToggleSubdomainStatus(): void
    {
        $subdomainId = intval($_POST['id'] ?? ($_POST['subdomain_id'] ?? 0));
        if ($subdomainId <= 0) {
            self::flashError('子域名ID无效');
            self::redirect(self::HASH_SUBDOMAINS);
        }

        try {
            $record = Capsule::table('mod_cloudflare_subdomain')->where('id', $subdomainId)->first();
            if (!$record) {
                throw new Exception('子域名不存在');
            }
            $newStatus = ($record->status === 'active') ? 'suspended' : 'active';
            Capsule::table('mod_cloudflare_subdomain')
                ->where('id', $subdomainId)
                ->update([
                    'status' => $newStatus,
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_toggle_subdomain_status', [
                    'subdomain' => $record->subdomain,
                    'status' => $newStatus,
                ], intval($record->userid ?? 0), $subdomainId);
            }
            self::flashSuccess('子域名状态已更新');
        } catch (Exception $e) {
            self::flashError('更新子域名状态失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_SUBDOMAINS);
    }

    private static function handleSubdomainRegenerate(): void
    {
        $subdomainId = intval($_POST['subdomain_id'] ?? ($_POST['id'] ?? 0));
        if ($subdomainId <= 0) {
            self::flashError('子域名ID无效');
            self::redirect(self::HASH_SUBDOMAINS);
        }

        try {
            $record = Capsule::table('mod_cloudflare_subdomain')->where('id', $subdomainId)->first();
            if (!$record) {
                throw new Exception('子域名不存在');
            }
            if (!function_exists('cfmod_acquire_provider_client_for_subdomain')) {
                throw new Exception('当前环境不支持此操作');
            }
            $settings = self::moduleSettings();
            $providerContext = cfmod_acquire_provider_client_for_subdomain($record, $settings);
            if (!$providerContext || empty($providerContext['client'])) {
                throw new Exception('未找到可用的 DNS 供应商账号');
            }
            $cf = $providerContext['client'];
            if (!method_exists($cf, 'createSubdomain')) {
                throw new Exception('当前供应商不支持重新生成解析');
            }
            $zoneIdentifier = $record->cloudflare_zone_id ?: ($record->rootdomain ?? '');
            if ($zoneIdentifier === '') {
                throw new Exception('缺少 Zone 信息，请先绑定根域名');
            }
            $defaultIp = trim((string) ($settings['default_ip'] ?? ''));
            if ($defaultIp === '') {
                $defaultIp = '192.0.2.1';
            }
            $response = $cf->createSubdomain($zoneIdentifier, $record->subdomain, $defaultIp);
            if (!($response['success'] ?? false)) {
                $errorPayload = $response['errors'] ?? '供应商返回失败';
                if (is_array($errorPayload)) {
                    $errorPayload = json_encode($errorPayload, JSON_UNESCAPED_UNICODE);
                }
                throw new Exception((string) $errorPayload);
            }
            $recordId = $response['result']['id'] ?? null;
            Capsule::table('mod_cloudflare_subdomain')
                ->where('id', $subdomainId)
                ->update([
                    'dns_record_id' => $recordId,
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('admin_regen_dns', [
                    'subdomain' => $record->subdomain,
                    'record_id' => $recordId,
                ], intval($record->userid ?? 0), $subdomainId);
            }
            self::flashSuccess('解析重新生成成功');
        } catch (Exception $e) {
            self::flashError('重新生成失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
        }

        self::redirect(self::HASH_SUBDOMAINS);
    }

    private static function ensureInviteTables(): void
    {
        try {
            if (!Capsule::schema()->hasTable('mod_cloudflare_invite_leaderboard')) {
                Capsule::schema()->create('mod_cloudflare_invite_leaderboard', function ($table) {
                    $table->increments('id');
                    $table->date('period_start');
                    $table->date('period_end');
                    $table->text('top_json');
                    $table->timestamps();
                    $table->unique(['period_start', 'period_end']);
                    $table->index('period_start');
                });
            }
            if (!Capsule::schema()->hasTable('mod_cloudflare_invite_rewards')) {
                Capsule::schema()->create('mod_cloudflare_invite_rewards', function ($table) {
                    $table->increments('id');
                    $table->date('period_start');
                    $table->date('period_end');
                    $table->integer('inviter_userid')->unsigned();
                    $table->string('code', 64);
                    $table->integer('rank')->unsigned();
                    $table->integer('count')->unsigned();
                    $table->string('status', 20)->default('eligible');
                    $table->dateTime('requested_at')->nullable();
                    $table->dateTime('claimed_at')->nullable();
                    $table->text('notes')->nullable();
                    $table->timestamps();
                    $table->index(['period_start', 'period_end']);
                    $table->index(['inviter_userid', 'period_start']);
                    $table->index('status');
                });
            }
            if (!Capsule::schema()->hasColumn('mod_cloudflare_invite_rewards', 'requested_at')) {
                Capsule::schema()->table('mod_cloudflare_invite_rewards', function ($table) {
                    $table->dateTime('requested_at')->nullable()->after('status');
                });
            }
            if (!Capsule::schema()->hasColumn('mod_cloudflare_invite_rewards', 'claimed_at')) {
                Capsule::schema()->table('mod_cloudflare_invite_rewards', function ($table) {
                    $table->dateTime('claimed_at')->nullable()->after('requested_at');
                });
            }
            if (!Capsule::schema()->hasColumn('mod_cloudflare_invite_rewards', 'notes')) {
                Capsule::schema()->table('mod_cloudflare_invite_rewards', function ($table) {
                    $table->text('notes')->nullable()->after('claimed_at');
                });
            }
        } catch (Exception $e) {
            // ignore migrations errors
        }
    }

    private static function enforceRateLimitForAction(string $action): void
    {
        $scope = self::resolveRateLimitScope($action);
        if ($scope === null) {
            return;
        }
        $limit = CfRateLimiter::resolveLimit($scope, self::moduleSettings());
        CfRateLimiter::enforce($scope, $limit, [
            'userid' => isset($_SESSION['adminid']) ? (int) $_SESSION['adminid'] : 0,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'identifier' => $action,
        ]);
    }

    private static function resolveRateLimitScope(string $action): ?string
    {
        static $map = [
            'admin_create_redeem_code' => CfRateLimiter::SCOPE_QUOTA_GIFT,
            'admin_generate_redeem_codes' => CfRateLimiter::SCOPE_QUOTA_GIFT,
            'admin_delete_redeem_code' => CfRateLimiter::SCOPE_QUOTA_GIFT,
            'admin_toggle_redeem_code_status' => CfRateLimiter::SCOPE_QUOTA_GIFT,
            'admin_cancel_domain_gift' => CfRateLimiter::SCOPE_QUOTA_GIFT,
            'admin_unlock_domain_gift_lock' => CfRateLimiter::SCOPE_QUOTA_GIFT,
        ];
        return $map[$action] ?? null;
    }

    private static function formatRateLimitMessage(int $retryAfterSeconds): string
    {
        $minutes = CfRateLimiter::formatRetryMinutes($retryAfterSeconds);
        $template = cfmod_trans('cfadmin.rate_limit.hit', '操作频率过高，请 %s 分钟后再试。');
        try {
            return sprintf($template, $minutes);
        } catch (\Throwable $e) {
            return '操作频率过高，请稍后再试。';
        }
    }

    private static function clearPrimaryPointersForOrphans(array $orphans): void
    {
        $map = [];
        foreach ($orphans as $entry) {
            $recordId = $entry['record_id'] ?? '';
            if ($recordId === null || $recordId === '') {
                continue;
            }
            $map[$entry['subdomain_id']][] = (string) $recordId;
        }
        if (empty($map)) {
            return;
        }
        $now = date('Y-m-d H:i:s');
        foreach ($map as $subId => $recordIds) {
            $current = Capsule::table('mod_cloudflare_subdomain')->where('id', $subId)->value('dns_record_id');
            if ($current === null || $current === '') {
                continue;
            }
            foreach ($recordIds as $rid) {
                if ((string) $current === $rid) {
                    Capsule::table('mod_cloudflare_subdomain')
                        ->where('id', $subId)
                        ->update([
                            'dns_record_id' => null,
                            'updated_at' => $now,
                        ]);
                    break;
                }
            }
        }
    }

    private static function loadOrphanCursorMap(): array
    {
        if (self::$orphanCursorCache !== null) {
            return self::$orphanCursorCache;
        }
        $settings = self::moduleSettings();
        $raw = $settings[self::ORPHAN_CURSOR_SETTING_KEY] ?? '';
        $map = [];
        if (is_string($raw) && $raw !== '') {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $map = $decoded;
            }
        }
        if (!isset($map[self::ORPHAN_CURSOR_DEFAULT_KEY])) {
            $map[self::ORPHAN_CURSOR_DEFAULT_KEY] = 0;
        }
        self::$orphanCursorCache = $map;
        return $map;
    }

    private static function saveOrphanCursorMap(array $map): void
    {
        ksort($map);
        self::$orphanCursorCache = $map;
        self::persistModuleSetting(self::ORPHAN_CURSOR_SETTING_KEY, json_encode($map));
    }

    private static function getOrphanCursorKey(string $rootdomain): string
    {
        $normalized = strtolower(trim($rootdomain));
        if ($normalized === '') {
            return self::ORPHAN_CURSOR_DEFAULT_KEY;
        }
        return 'root:' . $normalized;
    }

    private static function setOrphanCursor(string $rootdomain, int $cursor): void
    {
        $map = self::loadOrphanCursorMap();
        $key = self::getOrphanCursorKey($rootdomain);
        $map[$key] = max(0, $cursor);
        self::saveOrphanCursorMap($map);
    }

    public static function getOrphanCursor(string $rootdomain = ''): int
    {
        $map = self::loadOrphanCursorMap();
        $key = self::getOrphanCursorKey($rootdomain);
        return intval($map[$key] ?? 0);
    }

    public static function getOrphanCursorSummaryForView(): array
    {
        $map = self::loadOrphanCursorMap();
        $list = [];
        foreach ($map as $key => $value) {
            if ($key === self::ORPHAN_CURSOR_DEFAULT_KEY) {
                continue;
            }
            if (strpos($key, 'root:') === 0) {
                $list[] = [
                    'rootdomain' => substr($key, 5),
                    'cursor' => intval($value),
                ];
            }
        }
        usort($list, static function ($a, $b) {
            return strcmp($a['rootdomain'], $b['rootdomain']);
        });
        return [
            'default' => intval($map[self::ORPHAN_CURSOR_DEFAULT_KEY] ?? 0),
            'list' => $list,
        ];
    }

    private static function buildProviderCacheKey($sub): string
    {
        $pid = intval($sub->provider_account_id ?? 0);
        if ($pid > 0) {
            return 'pid_' . $pid;
        }
        $root = strtolower(trim((string)($sub->rootdomain ?? '')));
        if ($root !== '') {
            return 'root_' . $root;
        }
        return 'sub_' . intval($sub->id ?? 0);
    }

    private static function normalizeDnsRecordKey(?string $name, ?string $type, ?string $content): string
    {
        $normalizedName = strtolower(trim((string) $name));
        if ($normalizedName === '' || $normalizedName === '@') {
            $normalizedName = '@';
        } else {
            $normalizedName = rtrim($normalizedName, '.');
        }
        $normalizedType = strtoupper(trim((string) $type));
        $value = trim((string) $content);
        if (in_array($normalizedType, ['CNAME', 'NS', 'MX', 'SRV'], true)) {
            $value = rtrim($value, '.');
        }
        if ($normalizedType === 'TXT') {
            $value = trim($value, '"');
        }
        $value = strtolower($value);
        return $normalizedName . '|' . $normalizedType . '|' . $value;
    }

    private static function currentInvitePeriod(array $moduleSettings): array
    {
        $periodDays = max(1, intval($moduleSettings['invite_leaderboard_period_days'] ?? 7));
        $cycleStart = trim($moduleSettings['invite_cycle_start'] ?? '');
        if ($cycleStart !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $cycleStart)) {
            $start = $cycleStart;
            $end = date('Y-m-d', strtotime($start . ' +' . ($periodDays - 1) . ' days'));
        } else {
            $end = date('Y-m-d', strtotime('yesterday'));
            $start = date('Y-m-d', strtotime($end . ' -' . ($periodDays - 1) . ' days'));
        }
        return [$start, $end];
    }

    private static function moduleSettings(): array
    {
        if (function_exists('cf_get_module_settings_cached')) {
            $settings = cf_get_module_settings_cached();
            if (is_array($settings)) {
                return $settings;
            }
        }
        $rows = Capsule::table('tbladdonmodules')->where('module', 'domain_hub')->get();
        $settings = [];
        foreach ($rows as $row) {
            $settings[$row->setting] = $row->value;
        }
        return $settings;
    }

    private static function moduleSlugList(): array
    {
        $slug = defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
        $legacy = defined('CF_MODULE_NAME_LEGACY') ? CF_MODULE_NAME_LEGACY : 'cloudflare_subdomain';
        return array_values(array_unique([$slug, $legacy]));
    }

    private static function persistModuleSetting(string $key, string $value): void
    {
        $exists = Capsule::table('tbladdonmodules')
            ->where('module', 'domain_hub')
            ->where('setting', $key)
            ->count();
        if ($exists) {
            Capsule::table('tbladdonmodules')
                ->where('module', 'domain_hub')
                ->where('setting', $key)
                ->update(['value' => $value]);
        } else {
            Capsule::table('tbladdonmodules')->insert([
                'module' => 'domain_hub',
                'setting' => $key,
                'value' => $value,
            ]);
        }
        if (function_exists('cf_clear_settings_cache')) {
            cf_clear_settings_cache();
        }
    }

    private static function persistModuleSettings(array $pairs): void
    {
        foreach ($pairs as $key => $value) {
            self::persistModuleSetting($key, $value);
        }
    }

    private static function ensureUserBansTable(): void
    {
        try {
            if (!Capsule::schema()->hasTable('mod_cloudflare_user_bans')) {
                Capsule::schema()->create('mod_cloudflare_user_bans', function ($table) {
                    $table->increments('id');
                    $table->integer('userid')->unsigned();
                    $table->text('ban_reason');
                    $table->string('banned_by', 100);
                    $table->dateTime('banned_at');
                    $table->dateTime('unbanned_at')->nullable();
                    $table->string('status', 20)->default('banned');
                    $table->string('ban_type', 20)->default('permanent');
                    $table->dateTime('ban_expires_at')->nullable();
                    $table->timestamps();
                    $table->index('userid');
                    $table->index('status');
                    $table->index('banned_at');
                });
            } else {
                if (!Capsule::schema()->hasColumn('mod_cloudflare_user_bans', 'ban_type')) {
                    Capsule::schema()->table('mod_cloudflare_user_bans', function ($table) {
                        $table->string('ban_type', 20)->default('permanent')->after('status');
                    });
                }
                if (!Capsule::schema()->hasColumn('mod_cloudflare_user_bans', 'ban_expires_at')) {
                    Capsule::schema()->table('mod_cloudflare_user_bans', function ($table) {
                        $table->dateTime('ban_expires_at')->nullable()->after('ban_type');
                    });
                }
            }
        } catch (Exception $e) {
            // ignore migration errors
        }
    }

    private static function flashSuccess(string $message): void
    {
        self::flash($message, 'success');
    }

    private static function flashError(string $message): void
    {
        self::flash($message, 'danger');
    }

    private static function flash(string $message, string $type = 'info'): void
    {
        if (!isset($_SESSION['cfmod_admin_flash']) || !is_array($_SESSION['cfmod_admin_flash'])) {
            $_SESSION['cfmod_admin_flash'] = [];
        }
        $_SESSION['cfmod_admin_flash'][] = [
            'type' => $type,
            'message' => $message,
        ];
    }

    private static function redirect(string $hash = ''): void
    {
        $redirectUrl = cfmod_admin_current_url_without_action();
        if ($hash !== '') {
            $redirectUrl .= $hash;
        }
        header('Location: ' . $redirectUrl);
        exit;
    }

    private static function ensureProviderSchema(): void
    {
        cfmod_ensure_provider_schema();
    }

    private static function getDefaultProviderAccountId(): int
    {
        $settings = function_exists('cf_get_module_settings_cached') ? cf_get_module_settings_cached() : [];
        return intval($settings['default_provider_account_id'] ?? 0);
    }

    private static function resolveProviderAccount(?int $providerId = null, bool $withSecret = false): ?array
    {
        $candidateId = $providerId;
        if ($candidateId === null || $candidateId <= 0) {
            $default = cfmod_get_active_provider_account(null, $withSecret, true);
            return $default ?: null;
        }
        $account = cfmod_get_active_provider_account($candidateId, $withSecret, true);
        if ($account) {
            return $account;
        }
        return cfmod_get_active_provider_account(null, $withSecret, true);
    }

    private static function providerTypeLabels(): array
    {
        return [
            'alidns' => '阿里云 DNS (AliDNS)',
            'dnspod_legacy' => 'DNSPod 国际版 Legacy API',
            'dnspod_intl' => 'DNSPod 国际版 API 3.0',
            'powerdns' => 'PowerDNS (自建)',
        ];
    }

    private static function resolveNextRootdomainOrderValue(): int
    {
        if (function_exists('cfmod_next_rootdomain_display_order')) {
            return cfmod_next_rootdomain_display_order();
        }
        try {
            $max = Capsule::table('mod_cloudflare_rootdomains')->max('display_order');
            return (is_numeric($max) ? (int) $max : 0) + 1;
        } catch (\Throwable $e) {
            return 1;
        }
    }

    private static function normalizeRecordList($records): array
    {
        if ($records instanceof \Illuminate\Support\Collection) {
            return $records->all();
        }
        if ($records instanceof \Traversable) {
            return iterator_to_array($records);
        }
        if (is_array($records)) {
            return array_values($records);
        }
        return [];
    }
}
