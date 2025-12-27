<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfAdminController
{
    private static ?self $instance = null;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public function handle(array $vars = []): void
    {
        $this->bootstrapAdminRuntime();

        if (function_exists('cf_ensure_module_settings_migrated')) {
            cf_ensure_module_settings_migrated();
        }

        if (function_exists('cfmod_ensure_admin_csrf_seed')) {
            cfmod_ensure_admin_csrf_seed();
        }

        $this->handleAction();

        $cfAdminViewModel = $this->buildViewModel($vars);

        $modulelink = $vars['modulelink'] ?? '';
        $version = $vars['version'] ?? '';
        $LANG = $vars['_lang'] ?? [];

        include __DIR__ . '/../../templates/admin.tpl';
    }

    private function bootstrapAdminRuntime(): void
    {
        static $bootstrapped = false;
        if ($bootstrapped) {
            return;
        }

        if (!class_exists('CloudflareAPI')) {
            require_once __DIR__ . '/../../lib/CloudflareAPI.php';
        }
        require_once __DIR__ . '/../../lib/ProviderResolver.php';
        require_once __DIR__ . '/../../lib/AdminMaintenance.php';
        if (!function_exists('run_cf_queue_once')) {
            $workerPath = __DIR__ . '/../../worker.php';
            if (file_exists($workerPath)) {
                require_once $workerPath;
            }
        }
        if (!defined('CFMOD_SAFE_JSON_FLAGS')) {
            define('CFMOD_SAFE_JSON_FLAGS', JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
        }

        $bootstrapped = true;
    }

    private function handleAction(): void
    {
        $moduleMatches = isset($_REQUEST['module']) && $_REQUEST['module'] === (defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub');
        $action = (string)($_REQUEST['action'] ?? '');

        if ($moduleMatches && $action === 'get_user_quota') {
            $this->respondUserQuota();
            return;
        }

        if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            return;
        }

        $action = (string)($_POST['action'] ?? '');
        if ($action === '') {
            return;
        }

        if (!cfmod_validate_admin_csrf()) {
            $_SESSION['admin_api_error'] = '❌ 请求已过期或无效，请刷新页面后重试。';
            $this->redirectToCurrentPage();
        }

        if (CfAdminActionService::supports($action)) {
            CfAdminActionService::handle($action);
            if (class_exists('CfAdminViewModelBuilder')) {
                CfAdminViewModelBuilder::flushStatsCache();
            }
            return;
        }

        if (!in_array($action, $this->handledActions(), true)) {
            return;
        }

        try {
            $this->enforceAdminActionRateLimit($action);
        } catch (CfRateLimitExceededException $e) {
            $_SESSION['admin_api_error'] = $this->formatAdminRateLimitMessage($e->getRetryAfterSeconds());
            $this->redirectToCurrentPage();
        }

        switch ($action) {
            case 'admin_create_api_key':
                $this->handleAdminCreateApiKey();
                break;
            case 'admin_set_rate_limit':
                $this->handleAdminSetRateLimit();
                break;
            case 'admin_set_user_quota':
                $this->handleAdminSetUserQuota();
                break;
            case 'admin_disable_api_key':
                $this->handleToggleApiKey(false);
                break;
            case 'admin_enable_api_key':
                $this->handleToggleApiKey(true);
                break;
            case 'admin_delete_api_key':
                $this->handleDeleteApiKey();
                break;
        }
    }

    private function handledActions(): array
    {
        return [
            'admin_create_api_key',
            'admin_set_rate_limit',
            'admin_set_user_quota',
            'admin_disable_api_key',
            'admin_enable_api_key',
            'admin_delete_api_key',
        ];
    }

    private function enforceAdminActionRateLimit(string $action): void
    {
        $scope = $this->resolveAdminActionRateLimitScope($action);
        if ($scope === null) {
            return;
        }
        $settings = cf_get_module_settings_cached();
        if (!is_array($settings)) {
            $settings = [];
        }
        $limit = CfRateLimiter::resolveLimit($scope, $settings);
        CfRateLimiter::enforce($scope, $limit, [
            'userid' => isset($_SESSION['adminid']) ? (int) $_SESSION['adminid'] : 0,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'identifier' => $action,
        ]);
    }

    private function resolveAdminActionRateLimitScope(string $action): ?string
    {
        if (in_array($action, ['admin_create_api_key', 'admin_disable_api_key', 'admin_enable_api_key', 'admin_delete_api_key', 'admin_set_rate_limit'], true)) {
            return CfRateLimiter::SCOPE_API_KEY;
        }
        if ($action === 'admin_set_user_quota') {
            return CfRateLimiter::SCOPE_QUOTA_GIFT;
        }
        return null;
    }

    private function formatAdminRateLimitMessage(int $retryAfterSeconds): string
    {
        $minutes = CfRateLimiter::formatRetryMinutes($retryAfterSeconds);
        $template = cfmod_trans('cfadmin.rate_limit.hit', '操作频率过高，请 %s 分钟后再试。');
        try {
            return sprintf($template, $minutes);
        } catch (\Throwable $e) {
            return '操作频率过高，请稍后再试。';
        }
    }

    private function buildViewModel(array $vars): array
    {
        $base = CfAdminViewModelBuilder::build();
        $base['risk'] = CfAdminViewModelBuilder::buildRisk();
        $base['api'] = $this->buildApiViewModel();
        return $base;
    }

    private function buildApiViewModel(): array
    {
        $apiSearchKeyword = trim((string)($_GET['api_search'] ?? ''));
        $apiSearchType = (string)($_GET['api_search_type'] ?? 'all');
        $apiPage = isset($_GET['api_page']) ? max(1, (int) $_GET['api_page']) : 1;
        $apiPerPage = 20;

        $tablesExist = $this->schemaHasTable('mod_cloudflare_api_keys') && $this->schemaHasTable('mod_cloudflare_api_logs');

        $stats = [
            'total' => 0,
            'active' => 0,
            'totalRequests' => 0,
            'todayRequests' => 0,
        ];
        $pagination = [
            'totalKeys' => 0,
            'totalPages' => 0,
        ];
        $keys = [];

        $logPage = isset($_GET['api_log_page']) ? max(1, (int) $_GET['api_log_page']) : 1;
        $logPerPage = 50;
        $logEntries = [];
        $logTotal = 0;
        $logTotalPages = 0;

        if ($tablesExist) {
            $query = Capsule::table('mod_cloudflare_api_keys as k')
                ->join('tblclients as c', 'k.userid', '=', 'c.id');

            if ($apiSearchKeyword !== '') {
                $query->where(function ($q) use ($apiSearchKeyword, $apiSearchType) {
                    if ($apiSearchType === 'userid') {
                        if (is_numeric($apiSearchKeyword)) {
                            $q->where('k.userid', '=', (int) $apiSearchKeyword);
                        }
                    } elseif ($apiSearchType === 'email') {
                        $q->where('c.email', 'like', '%' . $apiSearchKeyword . '%');
                    } else {
                        $q->where(function ($inner) use ($apiSearchKeyword) {
                            if (is_numeric($apiSearchKeyword)) {
                                $inner->where('k.userid', '=', (int) $apiSearchKeyword);
                            }
                            $inner->orWhere('c.email', 'like', '%' . $apiSearchKeyword . '%');
                        });
                    }
                });
            }

            $totalKeys = (clone $query)->count();
            $stats['total'] = $totalKeys;
            $stats['active'] = Capsule::table('mod_cloudflare_api_keys')->where('status', 'active')->count();
            $stats['totalRequests'] = Capsule::table('mod_cloudflare_api_logs')->count();
            $stats['todayRequests'] = Capsule::table('mod_cloudflare_api_logs')
                ->whereRaw('DATE(created_at) = ?', [date('Y-m-d')])
                ->count();

            $pagination['totalKeys'] = $totalKeys;
            $pagination['totalPages'] = $totalKeys > 0 ? (int) ceil($totalKeys / $apiPerPage) : 0;

            $records = (clone $query)
                ->select('k.*', 'c.firstname', 'c.lastname', 'c.email')
                ->orderBy('k.created_at', 'desc')
                ->offset(($apiPage - 1) * $apiPerPage)
                ->limit($apiPerPage)
                ->get();

            $keys = json_decode(json_encode($records), true) ?: [];

            $logsBase = Capsule::table('mod_cloudflare_api_logs as l')
                ->leftJoin('tblclients as c', 'l.userid', '=', 'c.id')
                ->select('l.*', 'c.email');

            $logTotal = $logsBase->count();
            $logTotalPages = $logTotal > 0 ? (int) ceil($logTotal / $logPerPage) : 1;

            if ($logTotal > 0) {
                $logRecords = (clone $logsBase)
                    ->orderBy('l.created_at', 'desc')
                    ->offset(($logPage - 1) * $logPerPage)
                    ->limit($logPerPage)
                    ->get();
                $logEntries = json_decode(json_encode($logRecords), true) ?: [];
            }
        }

        return [
            'tablesExist' => $tablesExist,
            'search' => [
                'keyword' => $apiSearchKeyword,
                'type' => $apiSearchType,
                'page' => $apiPage,
                'perPage' => $apiPerPage,
            ],
            'pagination' => $pagination,
            'stats' => $stats,
            'keys' => $keys,
            'logs' => [
                'entries' => $logEntries,
                'total' => $logTotal,
                'totalPages' => $logTotalPages,
                'page' => $logPage,
                'perPage' => $logPerPage,
            ],
            'expanded' => isset($_SESSION['admin_api_success']) || isset($_SESSION['admin_api_error']) || $apiSearchKeyword !== '',
        ];
    }

    private function schemaHasTable(string $table): bool
    {
        try {
            return Capsule::schema()->hasTable($table);
        } catch (\Throwable $e) {
            return false;
        }
    }

    private function handleAdminCreateApiKey(): void
    {
        try {
            if (!$this->schemaHasTable('mod_cloudflare_api_keys')) {
                throw new \Exception('API密钥表不存在，请先激活插件或联系管理员');
            }

            $userId = (int) ($_POST['user_id'] ?? 0);
            $keyName = trim((string) ($_POST['key_name'] ?? ''));
            $rateLimit = max(1, (int) ($_POST['rate_limit'] ?? 60));

            if ($userId <= 0) {
                throw new \Exception('请输入有效的用户ID（必须大于0）');
            }
            if ($keyName === '') {
                throw new \Exception('请输入密钥名称');
            }

            $user = Capsule::table('tblclients')->where('id', $userId)->first();
            if (!$user) {
                throw new \Exception("用户ID {$userId} 不存在，请检查用户ID是否正确");
            }

            $apiKey = 'cfsd_' . bin2hex(random_bytes(16));
            $apiSecret = bin2hex(random_bytes(32));
            $hashedSecret = password_hash($apiSecret, PASSWORD_DEFAULT);

            Capsule::table('mod_cloudflare_api_keys')->insert([
                'userid' => $userId,
                'key_name' => $keyName,
                'api_key' => $apiKey,
                'api_secret' => $hashedSecret,
                'status' => 'active',
                'rate_limit' => $rateLimit,
                'request_count' => 0,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);

            if (class_exists('CfAdminViewModelBuilder')) {
                CfAdminViewModelBuilder::flushStatsCache();
            }

            $firstNameSafe = htmlspecialchars($user->firstname ?? '', ENT_QUOTES, 'UTF-8');
            $lastNameSafe = htmlspecialchars($user->lastname ?? '', ENT_QUOTES, 'UTF-8');
            $apiKeySafe = htmlspecialchars($apiKey, ENT_QUOTES, 'UTF-8');
            $apiSecretSafe = htmlspecialchars($apiSecret, ENT_QUOTES, 'UTF-8');
            $_SESSION['admin_api_success'] = "✅ 成功为用户 <strong>{$firstNameSafe} {$lastNameSafe}</strong> (ID:{$userId}) 创建API密钥！<br><br><strong>API Key:</strong> <code style='background:#f0f0f0;padding:5px;'>{$apiKeySafe}</code><br><strong>API Secret:</strong> <code style='background:#f0f0f0;padding:5px;'>{$apiSecretSafe}</code><br><br><span style='color:red;'><strong>⚠️ 重要：</strong>请立即复制保存Secret，关闭此消息后将无法再次查看！</span>";
        } catch (\Throwable $e) {
            $_SESSION['admin_api_error'] = '❌ 创建API密钥失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
        }

        $this->redirectToCurrentPage();
    }

    private function handleAdminSetRateLimit(): void
    {
        try {
            if (!$this->schemaHasTable('mod_cloudflare_api_keys')) {
                throw new \Exception('API密钥表不存在');
            }

            $keyId = (int) ($_POST['key_id'] ?? 0);
            $rateLimit = max(1, (int) ($_POST['rate_limit'] ?? 60));

            if ($keyId <= 0) {
                throw new \Exception('无效的密钥ID');
            }

            $updated = Capsule::table('mod_cloudflare_api_keys')
                ->where('id', $keyId)
                ->update([
                    'rate_limit' => $rateLimit,
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);

            if ($updated) {
                if (class_exists('CfAdminViewModelBuilder')) {
                    CfAdminViewModelBuilder::flushStatsCache();
                }
                $_SESSION['admin_api_success'] = "✅ 速率限制已更新为 {$rateLimit} 次/分钟";
            } else {
                $_SESSION['admin_api_error'] = "API密钥ID {$keyId} 不存在";
            }
        } catch (\Throwable $e) {
            $_SESSION['admin_api_error'] = '❌ 更新速率限制失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
        }

        $this->redirectToCurrentPage();
    }

    private function handleAdminSetUserQuota(): void
    {
        try {
            if (!$this->schemaHasTable('mod_cloudflare_subdomain_quotas')) {
                throw new \Exception('配额表不存在，请先激活插件');
            }

            $userId = (int) ($_POST['user_id'] ?? 0);
            $maxCount = max(0, min(99999999999, (int) ($_POST['max_count'] ?? 0)));
            $inviteBonusLimit = max(0, min(99999999999, (int) ($_POST['invite_bonus_limit'] ?? 0)));

            if ($userId <= 0) {
                throw new \Exception('用户ID无效');
            }

            $user = Capsule::table('tblclients')->where('id', $userId)->first();
            if (!$user) {
                throw new \Exception("用户ID {$userId} 不存在");
            }

            $quota = Capsule::table('mod_cloudflare_subdomain_quotas')
                ->where('userid', $userId)
                ->first();

            if ($quota) {
                Capsule::table('mod_cloudflare_subdomain_quotas')
                    ->where('userid', $userId)
                    ->update([
                        'max_count' => $maxCount,
                        'invite_bonus_limit' => $inviteBonusLimit,
                        'updated_at' => date('Y-m-d H:i:s'),
                    ]);
            } else {
                Capsule::table('mod_cloudflare_subdomain_quotas')->insert([
                    'userid' => $userId,
                    'used_count' => 0,
                    'max_count' => $maxCount,
                    'invite_bonus_count' => 0,
                    'invite_bonus_limit' => $inviteBonusLimit,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
            }

            if (class_exists('CfAdminViewModelBuilder')) {
                CfAdminViewModelBuilder::flushStatsCache();
            }

            $firstNameSafe = htmlspecialchars($user->firstname ?? '', ENT_QUOTES, 'UTF-8');
            $lastNameSafe = htmlspecialchars($user->lastname ?? '', ENT_QUOTES, 'UTF-8');
            $_SESSION['admin_api_success'] = "✅ 用户 <strong>{$firstNameSafe} {$lastNameSafe}</strong> 配额已更新：基础配额 {$maxCount}，邀请奖励上限 {$inviteBonusLimit}";
        } catch (\Throwable $e) {
            $_SESSION['admin_api_error'] = '❌ 更新用户配额失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
        }

        $this->redirectToCurrentPage();
    }

    private function handleToggleApiKey(bool $enable): void
    {
        try {
            if (!$this->schemaHasTable('mod_cloudflare_api_keys')) {
                throw new \Exception('API密钥表不存在');
            }

            $keyId = (int) ($_POST['key_id'] ?? 0);
            if ($keyId <= 0) {
                throw new \Exception('无效的密钥ID');
            }

            $status = $enable ? 'active' : 'disabled';
            $updated = Capsule::table('mod_cloudflare_api_keys')
                ->where('id', $keyId)
                ->update([
                    'status' => $status,
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);

            if (!$updated) {
                throw new \Exception('API密钥不存在');
            }

            if (class_exists('CfAdminViewModelBuilder')) {
                CfAdminViewModelBuilder::flushStatsCache();
            }

            $_SESSION['admin_api_success'] = $enable ? '✅ API密钥已启用' : '✅ API密钥已禁用';
        } catch (\Throwable $e) {
            $_SESSION['admin_api_error'] = '❌ 操作失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
        }

        $this->redirectToCurrentPage();
    }

    private function handleDeleteApiKey(): void
    {
        try {
            if (!$this->schemaHasTable('mod_cloudflare_api_keys')) {
                throw new \Exception('API密钥表不存在');
            }

            $keyId = (int) ($_POST['key_id'] ?? 0);
            if ($keyId <= 0) {
                throw new \Exception('无效的密钥ID');
            }

            $deleted = Capsule::table('mod_cloudflare_api_keys')
                ->where('id', $keyId)
                ->delete();

            if (!$deleted) {
                throw new \Exception('API密钥不存在');
            }

            if (class_exists('CfAdminViewModelBuilder')) {
                CfAdminViewModelBuilder::flushStatsCache();
            }

            $_SESSION['admin_api_success'] = '✅ API密钥已删除';
        } catch (\Throwable $e) {
            $_SESSION['admin_api_error'] = '❌ 删除失败：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
        }

        $this->redirectToCurrentPage();
    }

    private function respondUserQuota(): void
    {
        if (!$this->schemaHasTable('mod_cloudflare_subdomain_quotas')) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['success' => false]);
            exit;
        }

        $userId = isset($_GET['userid']) ? (int) $_GET['userid'] : 0;
        header('Content-Type: application/json; charset=utf-8');
        if ($userId <= 0) {
            echo json_encode(['success' => false]);
            exit;
        }

        $quota = Capsule::table('mod_cloudflare_subdomain_quotas')
            ->where('userid', $userId)
            ->first();

        if ($quota) {
            echo json_encode([
                'success' => true,
                'quota' => [
                    'max_count' => (int) $quota->max_count,
                    'invite_bonus_limit' => (int) $quota->invite_bonus_limit,
                ],
            ]);
        } else {
            echo json_encode(['success' => false]);
        }
        exit;
    }

    private function redirectToCurrentPage(): void
    {
        $redirectUrl = preg_replace('/[?&]action=[^&]*/', '', $_SERVER['REQUEST_URI'] ?? '');
        $redirectUrl = rtrim((string) $redirectUrl, '?&');
        if ($redirectUrl === '') {
            $redirectUrl = 'addonmodules.php?module=' . (defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub');
        }
        header('Location: ' . $redirectUrl);
        exit;
    }
}
