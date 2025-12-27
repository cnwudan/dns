<?php
// phpcs:ignoreFile

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfClientController
{
    private const SUPPORTED_LANGUAGES = ['english', 'chinese'];

    private static ?self $instance = null;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public static function getSupportedLanguages(): array
    {
        return self::SUPPORTED_LANGUAGES;
    }

    public static function encodeLanguageRedirectPayload(array $params): string
    {
        if (($params['action'] ?? '') === 'change_language') {
            unset($params['action']);
        }
        unset($params['lang'], $params['cf_lang'], $params['return']);
        if (empty($params)) {
            return '';
        }
        $query = http_build_query($params);
        if ($query === '') {
            return '';
        }
        $encoded = base64_encode($query);
        return rtrim(strtr($encoded, '+/', '-_'), '=');
    }

    private static function decodeLanguageRedirectPayload(?string $payload): array
    {
        if (!is_string($payload) || $payload === '') {
            return [];
        }
        $normalized = strtr($payload, '-_', '+/');
        $pad = strlen($normalized) % 4;
        if ($pad > 0) {
            $normalized .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($normalized, true);
        if ($decoded === false) {
            $decoded = base64_decode($payload, true);
            if ($decoded === false) {
                return [];
            }
        }
        parse_str($decoded, $params);
        return is_array($params) ? $params : [];
    }

    public static function resolveClientEntryScript(): string
    {
        return self::isClientAreaRequestContext() ? 'clientarea.php' : 'index.php';
    }

    public static function buildClientBaseQuery(string $moduleSlug): array
    {
        if (self::isClientAreaRequestContext()) {
            return ['action' => 'addon', 'module' => $moduleSlug];
        }
        return ['m' => $moduleSlug];
    }

    private static function isClientAreaRequestContext(): bool
    {
        $script = strtolower(basename($_SERVER['SCRIPT_NAME'] ?? ''));
        if ($script === 'clientarea.php') {
            return true;
        }
        $action = strtolower($_REQUEST['action'] ?? '');
        if ($action === 'addon' && isset($_REQUEST['module'])) {
            return true;
        }
        $rp = $_REQUEST['rp'] ?? '';
        if (is_string($rp) && stripos($rp, 'clientarea.php') !== false) {
            return true;
        }
        return false;
    }

    private static function paramsIndicateClientArea(array $params): bool
    {
        $action = strtolower($params['action'] ?? '');
        if ($action === 'addon' && isset($params['module'])) {
            return true;
        }
        if (isset($params['module']) && !isset($params['m'])) {
            return true;
        }
        return false;
    }

    private static function ensureLanguageRedirectBaseParams(array $params, string $moduleSlug): array
    {
        if (self::paramsIndicateClientArea($params)) {
            if (($params['action'] ?? '') !== 'addon') {
                $params['action'] = 'addon';
            }
            if (!isset($params['module']) || $params['module'] === '') {
                $params['module'] = $moduleSlug;
            }
            return $params;
        }

        if (!isset($params['m']) || $params['m'] === '') {
            $params['m'] = $moduleSlug;
        }
        return $params;
    }

    private static function resolveRedirectScript(array $params): string
    {
        return self::paramsIndicateClientArea($params) ? 'clientarea.php' : 'index.php';
    }

    public function handle(array $vars = [], bool $isLegacyEntry = false, bool $forceRender = false): void
    {
            if (!$forceRender && !cf_is_module_request()) {
                return;
            }
        
            if (defined('CFMOD_CLIENTAREA_PAGE_RENDERED')) {
                return;
            }
            define('CFMOD_CLIENTAREA_PAGE_RENDERED', true);
        
            $moduleSlug = defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
            $actionParam = $_GET['action'] ?? '';
            if ($actionParam === 'change_language') {
                $requestedLang = (string)($_GET['lang'] ?? '');
                $returnPayload = is_string($_GET['return'] ?? null) ? (string)$_GET['return'] : null;
                $returnParams = self::decodeLanguageRedirectPayload($returnPayload);
                if (empty($returnParams)) {
                    $returnParams = $_GET ?? [];
                }
                $this->handleLanguageSwitchRequest($requestedLang, $moduleSlug, $returnParams);
            }
            $requestedLanguage = $_GET['cf_lang'] ?? null;
            if ($requestedLanguage !== null) {
                $returnPayload = is_string($_GET['return'] ?? null) ? (string) $_GET['return'] : null;
                $returnParams = self::decodeLanguageRedirectPayload($returnPayload);
                if (empty($returnParams)) {
                    $returnParams = $_GET ?? [];
                }
                $this->handleLanguageSwitchRequest((string) $requestedLanguage, $moduleSlug, $returnParams);
            }
        
            if (cf_is_api_request()) {
                cf_dispatch_api_request();
            }
        
            if (!isset($_SESSION['uid'])) {
                header('Location: login.php');
                exit;
            }
        
            cfmod_ensure_client_csrf_seed();
            $clientCsrfValid = cfmod_validate_client_area_csrf();
            $GLOBALS['cfmod_client_csrf_valid'] = $clientCsrfValid;
            if (!$clientCsrfValid && strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
                $_POST = [];
                $GLOBALS['cfmod_client_csrf_error'] = true;
            }
        
            // 如果执行到这里，说明其他钩子都已经检查过了，没有重定向
            // 现在执行插件自己的验证
        
            $userId = intval($_SESSION['uid']);
        
            // 执行WHMCS标准客户区访问验证
            // 检查用户账户状态
            $client = Capsule::table('tblclients')->where('id', $userId)->first();
            if (!$client) {
                header('Location: login.php');
                exit;
            }
        
            // 检查账户状态 - 若非 Active，允许插件封禁用户进入页面但禁止操作
            if (isset($client->status) && strtolower($client->status) !== 'active') {
                $pluginBanned = Capsule::table('mod_cloudflare_user_bans')
                    ->where('userid', $userId)
                    ->where('status', 'banned')
                    ->exists();
                if (!$pluginBanned) {
                    header('Location: clientarea.php?action=details');
                    exit;
                }
            }
        
            // 检查是否需要邮箱验证
            if (isset($client->email_verified) && $client->email_verified == 0) {
                // 检查系统是否启用了邮箱验证要求
                $emailVerificationEnabled = Capsule::table('tblconfiguration')
                    ->where('setting', 'RequireClientEmailVerification')
                    ->value('value');
                if ($emailVerificationEnabled == 'on') {
                    header('Location: clientarea.php');
                    exit;
                }
            }
        
            // 使用WHMCS的钩子系统检查额外限制
            // 触发一个自定义钩子点，允许其他插件/钩子阻止访问
            $pageTitleText = cfmod_trans('cfclient.breadcrumb.client_page', '我的二级域名管理');
            $hookResults = run_hook('ClientAreaPageBeforeAccess', [
                'userid' => $userId,
                'module' => CF_MODULE_NAME,
                'legacy_module' => CF_MODULE_NAME_LEGACY,
                'pagetitle' => $pageTitleText
            ]);
        
            // 检查是否有任何钩子返回了重定向指令
            foreach ($hookResults as $result) {
                if (is_array($result) && isset($result['redirect'])) {
                    header('Location: ' . $result['redirect']);
                    exit;
                }
                if (is_string($result) && strpos($result, 'Location:') === 0) {
                    header($result);
                    exit;
                }
            }
        
            // 检查安全问题（如果系统要求）
            $securityQuestionsEnabled = Capsule::table('tblconfiguration')
                ->where('setting', 'SecurityQuestionsEnabled')
                ->value('value');
            if ($securityQuestionsEnabled == 'on') {
                $hasAnsweredQuestions = Capsule::table('tblclientsecurityquestions')
                    ->where('userid', $userId)
                    ->count();
                $requiredQuestions = Capsule::table('tblconfiguration')
                    ->where('setting', 'SecurityQuestionsRequired')
                    ->value('value');
                if ($requiredQuestions && $hasAnsweredQuestions < intval($requiredQuestions)) {
                    header('Location: clientarea.php?action=security');
                    exit;
                }
            }
        
            // 检查两步验证要求（如果系统强制启用）
            $twoFactorAuthRequired = Capsule::table('tblconfiguration')
                ->where('setting', 'TwoFactorAuthenticationRequired')
                ->value('value');
            if ($twoFactorAuthRequired == 'on') {
                $hasTwoFactor = Capsule::table('tblusers_twofactor')
                    ->where('user_id', $userId)
                    ->where('user_type', 'Client')
                    ->count();
                if (!$hasTwoFactor) {
                    header('Location: clientarea.php?action=security');
                    exit;
                }
            }
        
            $actionOverrides = [];
            if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
                $preViewModel = $this->buildViewModel($userId, $client, $vars);
                $preGlobals = $preViewModel['globals'] ?? [];
                $actionOverrides = $this->handleAction($userId, $client, $preGlobals);
                $cfViewModel = $this->buildViewModel($userId, $client, $vars);
                $GLOBALS['cfClientViewModel'] = $this->applyActionOverrides($cfViewModel, $actionOverrides);
            } else {
                $GLOBALS['cfClientViewModel'] = $this->buildViewModel($userId, $client, $vars);
            }

// 设置页面标题和面包屑
            $homeLabel = cfmod_trans('cfclient.breadcrumb.home', '首页');
            $vars['pagetitle'] = $pageTitleText;
            $vars['breadcrumb'] = [
                ['url' => 'index.php', 'label' => $homeLabel],
                ['url' => '#', 'label' => $pageTitleText]
            ];
        
            // 包含客户端模板
        include __DIR__ . '/../../templates/client.tpl';
            exit;
    }

    private function handleLanguageSwitchRequest(string $languageCode, string $moduleSlug, ?array $returnParams = null): void
    {
            try {
                if (session_status() !== PHP_SESSION_ACTIVE) {
                    @session_start();
                }
            } catch (\Throwable $e) {}

            $normalized = function_exists('cfmod_normalize_language_code') ? cfmod_normalize_language_code($languageCode) : strtolower(trim($languageCode));
            if ($normalized === '' || !in_array($normalized, self::SUPPORTED_LANGUAGES, true)) {
                $normalized = 'english';
            }
            $_SESSION['Language'] = $normalized;
            $_SESSION['language'] = $normalized;
            setcookie('WHMCSLanguage', $normalized, time() + 86400 * 365, '/', '', false, true);

            $params = $returnParams ?? ($_GET ?? []);
            if (($params['action'] ?? '') === 'change_language') {
                unset($params['action']);
            }
            unset($params['cf_lang'], $params['lang'], $params['return']);
            $params = self::ensureLanguageRedirectBaseParams($params, $moduleSlug);
            $query = http_build_query($params);
            $redirect = self::resolveRedirectScript($params) . ($query ? ('?' . $query) : '');
            header('Location: ' . $redirect);
            exit;
    }

    

    

    private function handleAction(int $userId, $client, array $globals): array
    {
                // AJAX处理：API密钥管理
                            $action = $_GET['action'] ?? $_POST['action'] ?? '';

                            try {
                                self::enforceAjaxRateLimit($action, $userId);
                            } catch (CfRateLimitExceededException $e) {
                                self::respondAjaxRateLimitError($e);
                            }

                            // VPN检测（AJAX）- 用于前端弹窗时预检
                            if ($action === 'ajax_check_vpn') {
                                header('Content-Type: application/json; charset=utf-8');
                                $settings = cf_get_module_settings_cached();
                                
                                // 检查DNS操作VPN检测是否启用
                                if (!class_exists('CfVpnDetectionService') || !CfVpnDetectionService::isDnsCheckEnabled($settings)) {
                                    echo json_encode(['success' => true, 'blocked' => false, 'reason' => 'disabled']);
                                    exit;
                                }
                                
                                $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
                                $vpnCheckResult = CfVpnDetectionService::shouldBlockDnsOperation($clientIp, $settings);
                                
                                if (!empty($vpnCheckResult['blocked'])) {
                                    if (function_exists('cloudflare_subdomain_log')) {
                                        cloudflare_subdomain_log('vpn_detection_ajax_check', [
                                            'ip' => $clientIp,
                                            'reason' => $vpnCheckResult['reason'] ?? 'unknown',
                                            'blocked' => true,
                                        ], $userId, null);
                                    }
                                    echo json_encode([
                                        'success' => true,
                                        'blocked' => true,
                                        'reason' => $vpnCheckResult['reason'] ?? 'vpn_proxy',
                                        'message' => self::actionText('dns.vpn_blocked', '检测到您正在使用VPN或代理，请关闭后再进行DNS操作。')
                                    ]);
                                    exit;
                                }
                                
                                echo json_encode(['success' => true, 'blocked' => false]);
                                exit;
                            }

                            // 创建API密钥
                            if ($action === 'ajax_create_api_key') {
                                try {
                                    // CSRF 校验
                                    $hdr = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
                                    if (!empty($_SESSION['cfmod_csrf']) && (!hash_equals($_SESSION['cfmod_csrf'], (string)$hdr))) {
                                        echo json_encode(['success'=>false,'error'=>self::actionText('cfclient.csrf_failed', '安全校验失败：请刷新页面后重试。')]);
                                        exit;
                                    }
                                    $rawInput = file_get_contents('php://input');
                                    $data = json_decode($rawInput, true);

                                    $keyName = trim($data['key_name'] ?? '');
                                    $ipWhitelist = trim($data['ip_whitelist'] ?? '');

                                    if (empty($keyName)) {
                                        echo json_encode(['success' => false, 'error' => self::actionText('cfclient.ajax.api.name_required', '密钥名称不能为空')]);
                                        exit;
                                    }

                                    // 读取设置
                                    $settings = cf_get_module_settings_cached();

                                    $maxKeys = intval($settings['api_keys_per_user'] ?? 3);
                                    $requireQuota = intval($settings['api_require_quota'] ?? 1);

                                    // 检查数量限制
                                    $currentCount = Capsule::table('mod_cloudflare_api_keys')
                                        ->where('userid', $userId)
                                        ->count();

                                    if ($currentCount >= $maxKeys) {
                                        echo json_encode(['success' => false, 'error' => self::actionText('cfclient.ajax.api.limit_reached', 'API密钥数量已达上限')]);
                                        exit;
                                    }

                                    // 检查配额要求
                                    if ($requireQuota > 0) {
                                        $quota = Capsule::table('mod_cloudflare_subdomain_quotas')
                                            ->where('userid', $userId)
                                            ->first();

                                        $totalQuota = intval($quota->max_count ?? 0);
                                        if ($totalQuota < $requireQuota) {
                                            echo json_encode(['success' => false, 'error' => self::actionText('cfclient.ajax.api.quota_required', '配额不足，需要至少 %s 个配额', [$requireQuota])]);
                                            exit;
                                        }
                                    }

                                    // 生成API密钥
                                    $apiKey = 'cfsd_' . bin2hex(random_bytes(16));
                                    $apiSecret = bin2hex(random_bytes(32));
                                    $hashedSecret = password_hash($apiSecret, PASSWORD_DEFAULT);
                                    $defaultRateLimit = intval($settings['api_rate_limit'] ?? 60);
                                    if ($defaultRateLimit <= 0) {
                                        $defaultRateLimit = 60;
                                    }

                                    Capsule::table('mod_cloudflare_api_keys')->insert([
                                        'userid' => $userId,
                                        'key_name' => $keyName,
                                        'api_key' => $apiKey,
                                        'api_secret' => $hashedSecret,
                                        'status' => 'active',
                                        'ip_whitelist' => $ipWhitelist,
                                        'permissions' => json_encode(['subdomains' => true, 'dns_records' => true]),
                                        'rate_limit' => $defaultRateLimit,
                                        'request_count' => 0,
                                        'created_at' => date('Y-m-d H:i:s'),
                                        'updated_at' => date('Y-m-d H:i:s')
                                    ]);

                                    echo json_encode([
                                        'success' => true,
                                        'api_key' => $apiKey,
                                        'api_secret' => $apiSecret
                                    ]);
                                } catch (\Exception $e) {
                                    $errorText = cfmod_format_provider_error($e->getMessage(), self::actionText('cfclient.ajax.api.create_failed', '创建失败，请稍后再试。'));
                                    echo json_encode(['success' => false, 'error' => $errorText]);
                                }
                                exit;
                            }

                            // 获取API密钥详情
                            if ($action === 'ajax_get_api_key_details') {
                                try {
                                    $keyId = intval($_GET['key_id'] ?? 0);

                                    $key = Capsule::table('mod_cloudflare_api_keys')
                                        ->where('id', $keyId)
                                        ->where('userid', $userId)
                                        ->first();

                                    if (!$key) {
                                        echo json_encode(['success' => false, 'error' => self::actionText('cfclient.ajax.api.not_found', 'API密钥不存在')]);
                                        exit;
                                    }

                                    echo json_encode([
                                        'success' => true,
                                        'key' => [
                                            'id' => $key->id,
                                            'key_name' => $key->key_name,
                                            'api_key' => $key->api_key,
                                            'status' => $key->status,
                                            'ip_whitelist' => $key->ip_whitelist,
                                            'request_count' => $key->request_count,
                                            'last_used_at' => $key->last_used_at,
                                            'created_at' => $key->created_at
                                        ]
                                    ]);
                                } catch (\Exception $e) {
                                    $errorText = cfmod_format_provider_error($e->getMessage(), self::actionText('cfclient.ajax.api.get_failed', '获取失败，请稍后再试。'));
                                    echo json_encode(['success' => false, 'error' => $errorText]);
                                }
                                exit;
                            }

                            // 重新生成API密钥
                            if ($action === 'ajax_regenerate_api_key') {
                                try {
                                    // CSRF 校验
                                    $hdr = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
                                    if (!empty($_SESSION['cfmod_csrf']) && (!hash_equals($_SESSION['cfmod_csrf'], (string)$hdr))) {
                                        echo json_encode(['success'=>false,'error'=>self::actionText('cfclient.csrf_failed', '安全校验失败：请刷新页面后重试。')]);
                                        exit;
                                    }
                                    $rawInput = file_get_contents('php://input');
                                    $data = json_decode($rawInput, true);
                                    $keyId = intval($data['key_id'] ?? 0);

                                    $key = Capsule::table('mod_cloudflare_api_keys')
                                        ->where('id', $keyId)
                                        ->where('userid', $userId)
                                        ->first();

                                    if (!$key) {
                                        echo json_encode(['success' => false, 'error' => self::actionText('cfclient.ajax.api.not_found', 'API密钥不存在')]);
                                        exit;
                                    }

                                    // 检查API状态
                                    if ($key->status === 'disabled') {
                                        echo json_encode(['success' => false, 'error' => self::actionText('cfclient.ajax.api.disabled', '此API密钥已被管理员禁用，无法执行此操作')]);
                                        exit;
                                    }

                                    // 生成新密钥
                                    $newApiSecret = bin2hex(random_bytes(32));
                                    $hashedSecret = password_hash($newApiSecret, PASSWORD_DEFAULT);

                                    Capsule::table('mod_cloudflare_api_keys')
                                        ->where('id', $keyId)
                                        ->update([
                                            'api_secret' => $hashedSecret,
                                            'updated_at' => date('Y-m-d H:i:s')
                                        ]);

                                    echo json_encode([
                                        'success' => true,
                                        'api_key' => $key->api_key,
                                        'api_secret' => $newApiSecret
                                    ]);
                                } catch (\Exception $e) {
                                    $errorText = cfmod_format_provider_error($e->getMessage(), self::actionText('cfclient.ajax.api.reset_failed', '重置失败，请稍后再试。'));
                                    echo json_encode(['success' => false, 'error' => $errorText]);
                                }
                                exit;
                            }

                            // 删除API密钥
                            if ($action === 'ajax_delete_api_key') {
                                try {
                                    // CSRF 校验
                                    $hdr = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
                                    if (!empty($_SESSION['cfmod_csrf']) && (!hash_equals($_SESSION['cfmod_csrf'], (string)$hdr))) {
                                        echo json_encode(['success'=>false,'error'=>self::actionText('cfclient.csrf_failed', '安全校验失败：请刷新页面后重试。')]);
                                        exit;
                                    }
                                    $rawInput = file_get_contents('php://input');
                                    $data = json_decode($rawInput, true);
                                    $keyId = intval($data['key_id'] ?? 0);

                                    $key = Capsule::table('mod_cloudflare_api_keys')
                                        ->where('id', $keyId)
                                        ->where('userid', $userId)
                                        ->first();

                                    if (!$key) {
                                        echo json_encode(['success' => false, 'error' => self::actionText('cfclient.ajax.api.not_found', 'API密钥不存在')]);
                                        exit;
                                    }

                                    // 检查API状态
                                    if ($key->status === 'disabled') {
                                        echo json_encode(['success' => false, 'error' => self::actionText('cfclient.ajax.api.disabled', '此API密钥已被管理员禁用，无法执行此操作')]);
                                        exit;
                                    }

                                    Capsule::table('mod_cloudflare_api_keys')
                                        ->where('id', $keyId)
                                        ->delete();

                                    echo json_encode(['success' => true]);
                                } catch (\Exception $e) {
                                    $errorText = cfmod_format_provider_error($e->getMessage(), self::actionText('cfclient.ajax.api.delete_failed', '删除失败，请稍后再试。'));
                                    echo json_encode(['success' => false, 'error' => $errorText]);
                                }
                                exit;
                            }

                            // 额度兑换 AJAX
                            if (in_array($action, ['ajax_redeem_quota_code', 'ajax_list_quota_redeems'], true)) {
                                header('Content-Type: application/json; charset=utf-8');
                                $settingsForRedeem = cf_get_module_settings_cached();
                                $redeemEnabled = in_array(($settingsForRedeem['enable_quota_redeem'] ?? '0'), ['1','on','yes','true','enabled'], true);
                                if (!$redeemEnabled) {
                                    echo json_encode(['success' => false, 'error' => self::actionText('cfclient.redeem.disabled', '兑换功能未开启')]);
                                    exit;
                                }
                                try {
                                    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
                                    if (empty($_SESSION['cfmod_csrf']) || !hash_equals($_SESSION['cfmod_csrf'], (string)$csrf)) {
                                        throw new CfQuotaRedeemException('csrf_invalid');
                                    }

                                    $banState = cfmod_resolve_user_ban_state($userId);
                                    if (!empty($banState['is_banned'])) {
                                        $reasonText = trim((string)($banState['reason'] ?? ''));
                                        $message = self::actionText('cfclient.redeem.banned', '您的账号已被限制操作，无法使用兑换功能。');
                                        if ($reasonText !== '') {
                                            $message .= ' ' . $reasonText;
                                        }
                                        echo json_encode(['success' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
                                        exit;
                                    }

                                    $rawInput = file_get_contents('php://input');
                                    $payload = json_decode($rawInput, true);
                                    if (!is_array($payload)) {
                                        $payload = [];
                                    }

                                    if ($action === 'ajax_redeem_quota_code') {
                                        $codeInput = (string)($payload['code'] ?? '');
                                        $service = CfQuotaRedeemService::instance();
                                        $result = $service->redeemCode($userId, $codeInput, $_SERVER['REMOTE_ADDR'] ?? '', $settingsForRedeem);
                                        echo json_encode([
                                            'success' => true,
                                            'data' => $result,
                                        ], JSON_UNESCAPED_UNICODE);
                                        exit;
                                    }

                                    if ($action === 'ajax_list_quota_redeems') {
                                        $page = isset($payload['page']) ? max(1, (int)$payload['page']) : 1;
                                        $service = CfQuotaRedeemService::instance();
                                        $history = $service->getUserHistory($userId, $page);
                                        echo json_encode([
                                            'success' => true,
                                            'data' => $history['items'],
                                            'pagination' => [
                                                'page' => $history['page'],
                                                'total_pages' => $history['totalPages'],
                                                'total' => $history['total'],
                                            ],
                                        ], JSON_UNESCAPED_UNICODE);
                                        exit;
                                    }
                                } catch (CfQuotaRedeemException $e) {
                                    $message = $this->translateRedeemError($e->getReason());
                                    echo json_encode([
                                        'success' => false,
                                        'error' => $message,
                                        'reason' => $e->getReason(),
                                    ], JSON_UNESCAPED_UNICODE);
                                    exit;
                                } catch (\Throwable $e) {
                                    echo json_encode([
                                        'success' => false,
                                        'error' => self::actionText('cfclient.redeem.error.generic', '兑换失败，请稍后再试。'),
                                    ], JSON_UNESCAPED_UNICODE);
                                    exit;
                                }
                            }

                            // 域名转赠 AJAX
                            if (in_array($action, ['ajax_initiate_domain_gift','ajax_accept_domain_gift','ajax_cancel_domain_gift','ajax_list_domain_gifts'], true)) {
                                header('Content-Type: application/json; charset=utf-8');
                                $settingsForGift = cf_get_module_settings_cached();
                                if (!cfmod_is_domain_gift_enabled($settingsForGift)) {
                                    echo json_encode(['success' => false, 'error' => self::actionText('cfclient.ajax.gift.feature_disabled', '域名转赠功能未开启')]);
                                    exit;
                                }
                                try {
                                    $csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
                                    if (empty($_SESSION['cfmod_csrf']) || !hash_equals($_SESSION['cfmod_csrf'], (string)$csrf)) {
                                        throw new \RuntimeException(self::actionText('cfclient.csrf_failed', '安全校验失败：请刷新页面后重试。'));
                                    }

                                    $banState = cfmod_resolve_user_ban_state($userId);
                                    if (!empty($banState['is_banned'])) {
                                        $reasonText = trim((string)($banState['reason'] ?? ''));
                                        $message = self::actionText('cfclient.ajax.gift.banned', '您的账号已被限制操作，无法进行域名转赠。');
                                        if ($reasonText !== '') {
                                            $message .= ' ' . $reasonText;
                                        }
                                        echo json_encode(['success' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
                                        exit;
                                    }

                                    $rawInput = file_get_contents('php://input');
                                    $payload = json_decode($rawInput, true);
                                    if (!is_array($payload)) {
                                        $payload = [];
                                    }
                                    $subdomainId = isset($payload['subdomain_id']) ? (int) $payload['subdomain_id'] : 0;
                                    $now = time();
                                    $nowStr = date('Y-m-d H:i:s', $now);

                                    if ($action === 'ajax_initiate_domain_gift') {

                                        if ($subdomainId <= 0) {
                                            throw new \RuntimeException(self::actionText('cfclient.ajax.gift.select_domain', '请选择要转赠的域名'));
                                        }
                                        $ttlHours = cfmod_get_domain_gift_ttl_hours($settingsForGift);
                                        $expiresAt = date('Y-m-d H:i:s', $now + $ttlHours * 3600);
                                        $result = Capsule::transaction(function () use ($subdomainId, $userId, $expiresAt, $settingsForGift, $nowStr, $now) {
                                            $subdomain = Capsule::table('mod_cloudflare_subdomain')
                                                ->where('id', $subdomainId)
                                                ->where('userid', $userId)
                                                ->lockForUpdate()
                                                ->first();
                                            if (!$subdomain) {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.domain_not_found', '未找到该域名或无权操作'));
                                            }

                                            $createdAtTs = $subdomain->created_at ? strtotime((string) $subdomain->created_at) : 0;
                                            $minGiftAgeSeconds = 7 * 86400;
                                            if ($createdAtTs <= 0 || ($now - $createdAtTs) < $minGiftAgeSeconds) {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.min_age', '该域名注册未满7天，暂不支持转赠'));
                                            }

                                            if (intval($subdomain->gift_lock_id ?? 0) > 0) {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.already_transferring', '该域名正在转赠中，请等待当前转赠完成'));
                                            }
                                            $attempts = 0;
                                            do {
                                                $code = cfmod_generate_domain_gift_code();
                                                $exists = Capsule::table('mod_cloudflare_domain_gifts')->where('code', $code)->exists();
                                                $attempts++;
                                            } while ($exists && $attempts < 5);
                                            if ($exists) {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.generate_failed', '生成转赠码失败，请稍后再试'));
                                            }
                                            $giftId = Capsule::table('mod_cloudflare_domain_gifts')->insertGetId([
                                                'code' => $code,
                                                'subdomain_id' => $subdomainId,
                                                'from_userid' => $userId,
                                                'to_userid' => null,
                                                'full_domain' => $subdomain->subdomain,
                                                'status' => 'pending',
                                                'expires_at' => $expiresAt,
                                                'completed_at' => null,
                                                'cancelled_at' => null,
                                                'cancelled_by_admin' => null,
                                                'created_at' => $nowStr,
                                                'updated_at' => $nowStr,
                                            ]);
                                            Capsule::table('mod_cloudflare_subdomain')
                                                ->where('id', $subdomainId)
                                                ->update([
                                                    'gift_lock_id' => $giftId,
                                                    'updated_at' => $nowStr,
                                                ]);
                                            return [
                                                'gift_id' => $giftId,
                                                'code' => $code,
                                                'expires_at' => $expiresAt,
                                                'full_domain' => $subdomain->subdomain,
                                                'subdomain_id' => $subdomainId,
                                            ];
                                        });
                                        if (function_exists('cloudflare_subdomain_log')) {
                                            cloudflare_subdomain_log('client_gift_initiate', $result, $userId, $result['subdomain_id']);
                                        }
                                        echo json_encode(['success' => true, 'data' => $result], JSON_UNESCAPED_UNICODE);
                                        exit;
                                    }

                                    if ($action === 'ajax_accept_domain_gift') {
                                        $codeInput = strtoupper(trim((string)($payload['code'] ?? '')));
                                        if ($codeInput === '' || strlen($codeInput) < 6) {
                                            throw new \RuntimeException(self::actionText('cfclient.ajax.gift.code_required', '请输入有效的接收码'));
                                        }
                                        $settings = $settingsForGift;
                                        $acceptResult = Capsule::transaction(function () use ($codeInput, $userId, $nowStr, $settings) {
                                            $gift = Capsule::table('mod_cloudflare_domain_gifts')
                                                ->where('code', $codeInput)
                                                ->lockForUpdate()
                                                ->first();
                                            if (!$gift) {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.code_not_found', '接收码不存在'));
                                            }
                                            if ($gift->status !== 'pending') {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.code_used', '该接收码已被使用或失效'));
                                            }
                                            if (strtotime($gift->expires_at) !== false && strtotime($gift->expires_at) < time()) {
                                                Capsule::table('mod_cloudflare_domain_gifts')
                                                    ->where('id', $gift->id)
                                                    ->update([
                                                        'status' => 'expired',
                                                        'cancelled_at' => $nowStr,
                                                        'updated_at' => $nowStr,
                                                    ]);
                                                Capsule::table('mod_cloudflare_subdomain')
                                                    ->where('id', $gift->subdomain_id)
                                                    ->where('gift_lock_id', $gift->id)
                                                    ->update(['gift_lock_id' => null, 'updated_at' => $nowStr]);
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.code_expired', '接收码已过期'));
                                            }
                                            if (intval($gift->from_userid) === $userId) {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.self_redeem', '不能领取自己发起的转赠'));
                                            }
                                            $subdomain = Capsule::table('mod_cloudflare_subdomain')
                                                ->where('id', $gift->subdomain_id)
                                                ->lockForUpdate()
                                                ->first();
                                            if (!$subdomain || intval($subdomain->gift_lock_id ?? 0) !== intval($gift->id)) {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.domain_invalid', '当前域名状态异常，请稍后再试'));
                                            }

                                            $rootForGift = (string)($subdomain->rootdomain ?? '');
                                            if ($rootForGift !== '' && function_exists('cfmod_check_rootdomain_user_limit')) {
                                                $limitCheck = cfmod_check_rootdomain_user_limit($userId, $rootForGift, 1);
                                                if (!$limitCheck['allowed']) {
                                                    $limitMessage = cfmod_format_rootdomain_limit_message($rootForGift, $limitCheck['limit']);
                                                    if ($limitMessage === '') {
                                                        $limitValueText = max(1, intval($limitCheck['limit'] ?? 0));
                                                        $limitMessage = self::actionText('cfclient.actions.register.root_user_limit', '%1$s 每个账号最多注册 %2$s 个，您已达到上限', [$rootForGift, $limitValueText]);
                                                    }
                                                    throw new \RuntimeException($limitMessage);
                                                }
                                            }

                                            $quotaTable = 'mod_cloudflare_subdomain_quotas';
                                            $donorQuota = Capsule::table($quotaTable)
                                                ->where('userid', $gift->from_userid)
                                                ->lockForUpdate()
                                                ->first();
                                            $recipientQuota = Capsule::table($quotaTable)
                                                ->where('userid', $userId)
                                                ->lockForUpdate()
                                                ->first();

                                            $baseMax = max(0, intval($settings['max_subdomain_per_user'] ?? 0));
                                            $inviteLimit = intval($settings['invite_bonus_limit_global'] ?? 5);
                                            if ($inviteLimit <= 0) {
                                                $inviteLimit = 5;
                                            }
                                            $isRecipientPrivileged = function_exists('cf_is_user_privileged') && cf_is_user_privileged($userId);
                                            $privilegedLimit = function_exists('cf_get_privileged_limit') ? cf_get_privileged_limit() : 0;

                                            if (!$recipientQuota) {
                                                Capsule::table($quotaTable)->insert([
                                                    'userid' => $userId,
                                                    'used_count' => 0,
                                                    'max_count' => $isRecipientPrivileged ? $privilegedLimit : $baseMax,
                                                    'invite_bonus_count' => 0,
                                                    'invite_bonus_limit' => $inviteLimit,
                                                    'created_at' => $nowStr,
                                                    'updated_at' => $nowStr,
                                                ]);
                                                $recipientQuota = Capsule::table($quotaTable)
                                                    ->where('userid', $userId)
                                                    ->lockForUpdate()
                                                    ->first();
                                            }

                                            if ($isRecipientPrivileged) {
                                                if (intval($recipientQuota->max_count ?? 0) !== $privilegedLimit && $privilegedLimit > 0) {
                                                    Capsule::table($quotaTable)
                                                        ->where('userid', $userId)
                                                        ->update(['max_count' => $privilegedLimit, 'updated_at' => $nowStr]);
                                                    $recipientQuota->max_count = $privilegedLimit;
                                                }
                                            } else {
                                                $bonusCount = max(0, intval($recipientQuota->invite_bonus_count ?? 0));
                                                $currentMax = intval($recipientQuota->max_count ?? 0);
                                                $currentBase = max(0, $currentMax - $bonusCount);
                                                if ($baseMax > 0 && $currentBase < $baseMax) {
                                                    $newMax = $baseMax + $bonusCount;
                                                    Capsule::table($quotaTable)
                                                        ->where('userid', $userId)
                                                        ->update(['max_count' => $newMax, 'updated_at' => $nowStr]);
                                                    $recipientQuota->max_count = $newMax;
                                                }
                                            }

                                            $recipientMax = intval($recipientQuota->max_count ?? 0);
                                            $recipientUsed = intval($recipientQuota->used_count ?? 0);
                                            if (!$isRecipientPrivileged && $recipientMax > 0 && $recipientUsed >= $recipientMax) {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.quota_insufficient', '您的配额不足，请先提升配额后再领取'));
                                            }

                                            if (!$donorQuota) {
                                                Capsule::table($quotaTable)->insert([
                                                    'userid' => $gift->from_userid,
                                                    'used_count' => 0,
                                                    'max_count' => max($baseMax, 0),
                                                    'invite_bonus_count' => 0,
                                                    'invite_bonus_limit' => $inviteLimit,
                                                    'created_at' => $nowStr,
                                                    'updated_at' => $nowStr,
                                                ]);
                                                $donorQuota = Capsule::table($quotaTable)
                                                    ->where('userid', $gift->from_userid)
                                                    ->lockForUpdate()
                                                    ->first();
                                            }

                                            Capsule::table('mod_cloudflare_subdomain')
                                                ->where('id', $subdomain->id)
                                                ->update([
                                                    'userid' => $userId,
                                                    'gift_lock_id' => null,
                                                    'updated_at' => $nowStr,
                                                ]);

                                            Capsule::table($quotaTable)
                                                ->where('userid', $gift->from_userid)
                                                ->update([
                                                    'used_count' => max(0, intval($donorQuota->used_count ?? 0) - 1),
                                                    'updated_at' => $nowStr,
                                                ]);

                                            Capsule::table($quotaTable)
                                                ->where('userid', $userId)
                                                ->update([
                                                    'used_count' => $recipientUsed + 1,
                                                    'updated_at' => $nowStr,
                                                ]);

                                            Capsule::table('mod_cloudflare_domain_gifts')
                                                ->where('id', $gift->id)
                                                ->update([
                                                    'status' => 'accepted',
                                                    'to_userid' => $userId,
                                                    'completed_at' => $nowStr,
                                                    'updated_at' => $nowStr,
                                                ]);

                                            return [
                                                'full_domain' => $subdomain->subdomain,
                                                'gift_id' => $gift->id,
                                                'from_userid' => $gift->from_userid,
                                                'subdomain_id' => $subdomain->id,
                                            ];
                                        });
                                        if (function_exists('cloudflare_subdomain_log')) {
                                            cloudflare_subdomain_log('client_gift_accept', $acceptResult, $userId, $acceptResult['subdomain_id']);
                                        }
                                        echo json_encode(['success' => true, 'data' => $acceptResult], JSON_UNESCAPED_UNICODE);
                                        exit;
                                    }

                                    if ($action === 'ajax_cancel_domain_gift') {
                                        $giftId = intval($payload['gift_id'] ?? 0);
                                        if ($giftId <= 0) {
                                            throw new \RuntimeException(self::actionText('cfclient.ajax.gift.missing_record', '缺少转赠记录'));
                                        }
                                        $cancelResult = Capsule::transaction(function () use ($giftId, $userId, $nowStr) {
                                            $gift = Capsule::table('mod_cloudflare_domain_gifts')
                                                ->where('id', $giftId)
                                                ->lockForUpdate()
                                                ->first();
                                            if (!$gift || intval($gift->from_userid) !== $userId) {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.record_forbidden', '转赠记录不存在或无权操作'));
                                            }
                                            if ($gift->status !== 'pending') {
                                                throw new \RuntimeException(self::actionText('cfclient.ajax.gift.cancel_restriction', '仅可取消进行中的转赠'));
                                            }
                                            Capsule::table('mod_cloudflare_domain_gifts')
                                                ->where('id', $giftId)
                                                ->update([
                                                    'status' => 'cancelled',
                                                    'cancelled_at' => $nowStr,
                                                    'updated_at' => $nowStr,
                                                ]);
                                            Capsule::table('mod_cloudflare_subdomain')
                                                ->where('id', $gift->subdomain_id)
                                                ->where('gift_lock_id', $gift->id)
                                                ->update([
                                                    'gift_lock_id' => null,
                                                    'updated_at' => $nowStr,
                                                ]);
                                            return [
                                                'gift_id' => $giftId,
                                                'full_domain' => $gift->full_domain,
                                                'subdomain_id' => $gift->subdomain_id,
                                            ];
                                        });
                                        if (function_exists('cloudflare_subdomain_log')) {
                                            cloudflare_subdomain_log('client_gift_cancel', $cancelResult, $userId, $cancelResult['subdomain_id']);
                                        }
                                        echo json_encode(['success' => true, 'data' => $cancelResult], JSON_UNESCAPED_UNICODE);
                                        exit;
                                    }

                                    if ($action === 'ajax_list_domain_gifts') {
                                        $page = max(1, intval($payload['page'] ?? 1));
                                        $perPage = 5;
                                        $baseQuery = Capsule::table('mod_cloudflare_domain_gifts')
                                            ->where(function ($q) use ($userId) {
                                                $q->where('from_userid', $userId)
                                                  ->orWhere('to_userid', $userId);
                                            });
                                        $total = (clone $baseQuery)->count();
                                        $totalPages = max(1, (int)ceil($total / $perPage));
                                        if ($page > $totalPages) {
                                            $page = $totalPages;
                                        }
                                        $records = $baseQuery
                                            ->orderBy('id', 'desc')
                                            ->offset(($page - 1) * $perPage)
                                            ->limit($perPage)
                                            ->get();
                                        $items = [];
                                        foreach ($records as $record) {
                                            $role = ((int)$record->from_userid === $userId) ? 'sent' : 'received';
                                            $items[] = [
                                                'id' => (int)$record->id,
                                                'code' => $record->code,
                                                'full_domain' => $record->full_domain,
                                                'status' => $record->status,
                                                'expires_at' => $record->expires_at,
                                                'created_at' => $record->created_at,
                                                'completed_at' => $record->completed_at,
                                                'cancelled_at' => $record->cancelled_at,
                                                'to_userid' => $record->to_userid ? (int)$record->to_userid : null,
                                                'role' => $role,
                                            ];
                                        }
                                        echo json_encode([
                                            'success' => true,
                                            'data' => $items,
                                            'pagination' => [
                                                'page' => $page,
                                                'per_page' => $perPage,
                                                'total' => $total,
                                                'total_pages' => $totalPages,
                                            ]
                                        ], JSON_UNESCAPED_UNICODE);
                                        exit;
                                    }
                                } catch (\Throwable $e) {
                                    $errorText = cfmod_format_provider_error($e->getMessage(), self::actionText('cfclient.ajax.gift.process_failed', '处理失败，请稍后再试。'));
                                    echo json_encode(['success' => false, 'error' => $errorText], JSON_UNESCAPED_UNICODE);
                                    exit;
                                }
                            }

                            // 轻量接口：实时排行榜（当前周期 Top N）
                            if ($action === 'realtime_top') {
                                try {
                                    // 读取模块设置
                                    $settings = cf_get_module_settings_cached();
                                    $periodDays = max(1, intval($settings['invite_leaderboard_period_days'] ?? 7));
                                    $cycleStart = trim($settings['invite_cycle_start'] ?? '');
                                    $limit = max(1, min(50, intval($_GET['limit'] ?? 5)));

                                    // 实时榜单API：一直返回实时数据，不检查周期结束

                                    // 计算实时窗口：包含今天
                                    $todayYmd = date('Y-m-d');
                                    if ($cycleStart !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $cycleStart)) {
                                        $startTs = strtotime($cycleStart);
                                        $todayTs = strtotime($todayYmd);
                                        if ($todayTs >= $startTs) {
                                            $k = (int) floor((($todayTs - $startTs) / 86400) / $periodDays);
                                            $periodStart = date('Y-m-d', strtotime('+' . ($k * $periodDays) . ' days', $startTs));
                                            $periodEnd = date('Y-m-d', strtotime('+' . (($k * $periodDays) + $periodDays - 1) . ' days', $startTs));
                                            // 如果当前周期还没开始，则使用今天作为开始
                                            if ($todayTs < strtotime($periodStart)) {
                                                $periodStart = $todayYmd;
                                                $periodEnd = $todayYmd;
                                            }
                                        } else { 
                                            $periodStart = $todayYmd; 
                                            $periodEnd = $todayYmd; 
                                        }
                                    } else {
                                        $periodEnd = $todayYmd;
                                        $periodStart = date('Y-m-d', strtotime($periodEnd . ' -' . ($periodDays - 1) . ' days'));
                                    }
                                    // 查询实时 Top N
                                    $rt = Capsule::table('mod_cloudflare_invitation_claims as ic')
                                        ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as cnt'))
                                        ->whereBetween('ic.created_at', [$periodStart.' 00:00:00', $periodEnd.' 23:59:59'])
                                        ->groupBy('ic.inviter_userid')
                                        ->orderBy('cnt','desc')
                                        ->limit($limit)
                                        ->get();
                                    $rows = [];
                                    foreach ($rt as $i => $row) {
                                        $uid = intval($row->inviter_userid);
                                        // 邮箱掩码
                                        $emailMasked = '***';
                                        $u = Capsule::table('tblclients')->select('email')->where('id',$uid)->first();
                                        if ($u && !empty($u->email)) {
                                            $parts = explode('@', $u->email);
                                            if (count($parts) === 2) {
                                                $local = $parts[0]; $domain = $parts[1];
                                                $localMasked = strlen($local) > 2 ? substr($local,0,2) . str_repeat('*', max(0, strlen($local)-2)) : str_repeat('*', strlen($local));
                                                $domainMasked = preg_replace('/(^.).*(\..{1,2})$/', '$1***$2', $domain);
                                                $emailMasked = $localMasked . '@' . $domainMasked;
                                            }
                                        }
                                        // 邀请码掩码
                                        $codeRow = Capsule::table('mod_cloudflare_invitation_codes')->select('code')->where('userid',$uid)->first();
                                        $codeVal = $codeRow->code ?? '';
                                        $codeMasked = cfmod_mask_invite_code($codeVal);
                                        $rows[] = [
                                            'rank' => $i + 1,
                                            'uid' => $uid,
                                            'emailMasked' => $emailMasked,
                                            'codeMasked' => $codeMasked,
                                            'count' => intval($row->cnt)
                                        ];
                                    }

                                    header('Content-Type: application/json; charset=utf-8');
                                    echo json_encode([
                                        'ok' => true,
                                        'periodStart' => $periodStart,
                                        'periodEnd' => $periodEnd,
                                        'rows' => $rows,
                                        'serverTime' => date('Y-m-d H:i:s')
                                    ], JSON_UNESCAPED_UNICODE);
                                } catch (\Throwable $e) {
                                    header('Content-Type: application/json; charset=utf-8');
                                    $errorText = cfmod_format_provider_error($e->getMessage(), self::actionText('cfclient.ajax.realtime.fetch_failed', '数据获取失败，请稍后再试。'));
                                    echo json_encode(['ok'=>false,'error'=>$errorText]);
                                }
                                exit;
                            }



        return $this->handleClientFormAction($userId, $globals);
    }

    private function handleClientFormAction(int $userId, array $globals): array
    {
        $requestMethod = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        if ($requestMethod !== 'POST') {
            return [];
        }

        $csrfValid = $GLOBALS['cfmod_client_csrf_valid'] ?? true;
        if (!$csrfValid) {
            return [
                'msg' => self::actionText('cfclient.csrf_failed', '安全校验失败：请刷新页面后重试。'),
                'msg_type' => 'danger',
            ];
        }

        if (!isset($_POST['action'])) {
            return [];
        }

        if (empty($globals['tables_exist'])) {
            return [];
        }

        $action = (string) ($_POST['action'] ?? '');
        if ($action === '' || in_array($action, ['__csrf_failed__', '__maintenance__', '__banned__'], true)) {
            return [];
        }

        if (!empty($globals['isUserBannedOrInactive'])) {
            $banReasonText = trim((string) ($globals['banReasonText'] ?? ''));
            $messageTemplate = cfmod_trans('cfclient.account_banned', '您的账号已被封禁或停用，操作已被禁止。%s');
            $message = sprintf($messageTemplate, $banReasonText !== '' ? (' ' . $banReasonText) : '');
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('client_banned_attempt', ['original_action' => $action], $userId, null);
            }
            return [
                'msg' => $message,
                'msg_type' => 'danger',
            ];
        }

        if (!empty($globals['maintenanceMode'])) {
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('client_maintenance_attempt', ['original_action' => $action], $userId, null);
            }
            return [
                'msg' => cfmod_trans('cfclient.maintenance_notice', '系统维护中，当前暂不可操作，请稍后再试。'),
                'msg_type' => 'warning',
            ];
        }

        return CfClientActionService::process($globals);
    }

    private function translateRedeemError(string $reason): string
    {
        switch ($reason) {
            case 'csrf_invalid':
                return self::actionText('cfclient.csrf_failed', '安全校验失败：请刷新页面后重试。');
            case 'invalid_user':
            case 'empty_code':
            case 'code_not_found':
                return self::actionText('cfclient.redeem.error.invalid_code', '兑换码不存在或已失效');
            case 'code_inactive':
                return self::actionText('cfclient.redeem.error.inactive', '该兑换码已被停用');
            case 'code_not_started':
                return self::actionText('cfclient.redeem.error.not_started', '兑换尚未开始');
            case 'code_expired':
                return self::actionText('cfclient.redeem.error.expired', '兑换码已过期');
            case 'code_exhausted':
                return self::actionText('cfclient.redeem.error.exhausted', '兑换次数已用完');
            case 'per_user_limit':
                return self::actionText('cfclient.redeem.error.per_user_limit', '您已使用过该兑换码');
            case 'grant_invalid':
                return self::actionText('cfclient.redeem.error.invalid_grant', '兑换码配置异常，请联系客服');
            case 'quota_unavailable':
                return self::actionText('cfclient.redeem.error.quota_unavailable', '当前无法更新您的额度，请稍后重试');
            default:
                return self::actionText('cfclient.redeem.error.generic', '兑换失败，请稍后再试。');
        }
    }

    private function applyActionOverrides(array $viewModel, array $overrides): array
    {
        if (empty($overrides)) {
            return $viewModel;
        }

        if (!isset($viewModel['globals']) || !is_array($viewModel['globals'])) {
            $viewModel['globals'] = [];
        }

        foreach ($overrides as $key => $value) {
            $viewModel['globals'][$key] = $value;
        }

        if (isset($viewModel['meta']['template_variables']) && is_array($viewModel['meta']['template_variables'])) {
            $viewModel['meta']['template_variables'] = array_values(array_unique(array_merge($viewModel['meta']['template_variables'], array_keys($overrides))));
        }

        return $viewModel;
    }

    private function buildViewModel(int $userId, $client, array $vars): array
    {
        if (class_exists('CfClientViewModelBuilder')) {
            return CfClientViewModelBuilder::build($userId);
        }

        return ['globals' => []];
    }

    private function resolveMaintenanceState(array $settings): array
    {
        $enabled = (int)($settings['client_maintenance_mode'] ?? $settings['maintenance_mode'] ?? 0) === 1;
        return [
            'enabled' => $enabled,
            'message' => trim((string)($settings['client_maintenance_message'] ?? '')),
        ];
    }

    private function resolveBanState(int $userId): array
    {
        if (function_exists('cfmod_resolve_user_ban_state')) {
            $state = cfmod_resolve_user_ban_state($userId);
            return [
                'isBanned' => !empty($state['is_banned']),
                'reason' => trim((string)($state['reason'] ?? '')),
            ];
        }

        $record = Capsule::table('mod_cloudflare_user_bans')
            ->where('userid', $userId)
            ->where('status', 'banned')
            ->first();

        return [
            'isBanned' => (bool) $record,
            'reason' => $record ? trim((string)($record->reason ?? '')) : '',
        ];
    }

    private function resolveQuotaState(int $userId, array $settings): array
    {
        $quota = Capsule::table('mod_cloudflare_subdomain_quotas')
            ->where('userid', $userId)
            ->first();

        $baseMax = max(0, (int)($settings['max_subdomain_per_user'] ?? 0));

        return [
            'max' => (int)($quota->max_count ?? $baseMax),
            'used' => (int)($quota->used_count ?? 0),
            'invite_bonus_limit' => (int)($quota->invite_bonus_limit ?? ($settings['invite_bonus_limit_global'] ?? 0)),
            'invite_bonus_count' => (int)($quota->invite_bonus_count ?? 0),
        ];
    }

    private function resolveRootOptions(): array
    {
        if (function_exists('cfmod_get_known_rootdomains')) {
            $domains = cfmod_get_known_rootdomains();
            if (is_array($domains)) {
                return array_values(array_map(static function ($domain) {
                    return ['domain' => $domain];
                }, $domains));
            }
        }

        try {
            $rows = Capsule::table('mod_cloudflare_rootdomains')
                ->select('domain', 'status')
                ->where('status', 'active')
                ->orderBy('domain')
                ->get();
        } catch (\Throwable $e) {
            return [];
        }

        return array_map(static function ($row) {
            return [
                'domain' => $row->domain ?? '',
                'status' => $row->status ?? 'active',
            ];
        }, $rows ? $rows->all() : []);
    }

    private function buildRegisterFormState(array $settings): array
    {
        $limits = function_exists('cf_get_prefix_length_limits') ? cf_get_prefix_length_limits($settings) : ['min' => 3, 'max' => 32];
        return [
            'length' => $limits,
            'term_years' => (int)($settings['domain_registration_term_years'] ?? 1),
        ];
    }

    private function buildSubdomainView(int $userId, array $settings): array
    {
        $searchTerm = trim((string)($_GET['search'] ?? ''));
        $page = isset($_GET['page']) ? max(1, (int) $_GET['page']) : 1;
        $pageSize = (int)($settings['client_subdomain_page_size'] ?? 20);
        $pageSize = max(5, min(100, $pageSize));

        [$records, $total, $totalPages, $currentPage] = CfSubdomainService::instance()
            ->loadSubdomainsPaginated($userId, $page, $pageSize, $searchTerm);

        $normalized = array_map([$this, 'normalizeSubdomainRecord'], $records);

        return [
            'items' => $normalized,
            'pagination' => [
                'page' => $currentPage,
                'pageSize' => $pageSize,
                'total' => $total,
                'totalPages' => $totalPages,
            ],
            'search' => $searchTerm,
        ];
    }

    private function normalizeSubdomainRecord($record): array
    {
        if ($record instanceof \stdClass) {
            $record = (array) $record;
        }

        if (!is_array($record)) {
            return [];
        }

        $record['created_at'] = isset($record['created_at']) ? (string) $record['created_at'] : '';
        $record['updated_at'] = isset($record['updated_at']) ? (string) $record['updated_at'] : '';

        return $record;
    }

    private function buildScriptPayload(array $settings): array
    {
        return [
            'csrfToken' => $_SESSION['cfmod_csrf'] ?? '',
            'ajaxEndpoints' => $this->buildAjaxEndpoints(),
            'featureFlags' => [
                'domainGift' => !empty($settings['domain_gift_enabled']),
            ],
        ];
    }

    private function buildAjaxEndpoints(): array
    {
        $base = 'clientarea.php?action=addon&module=' . CF_MODULE_NAME;

        return [
            'createApiKey' => $base . '&action=ajax_create_api_key',
            'getApiKey' => $base . '&action=ajax_get_api_key_details',
            'regenerateApiKey' => $base . '&action=ajax_regenerate_api_key',
            'deleteApiKey' => $base . '&action=ajax_delete_api_key',
            'domainGift' => [
                'initiate' => $base . '&action=ajax_initiate_domain_gift',
                'accept' => $base . '&action=ajax_accept_domain_gift',
                'cancel' => $base . '&action=ajax_cancel_domain_gift',
                'list' => $base . '&action=ajax_list_domain_gifts',
            ],
            'leaderboard' => $base . '&ajax=realtime_top',
        ];
    }

    private static function enforceAjaxRateLimit(string $action, int $userId): void
    {
        $scope = self::resolveAjaxRateLimitScope($action);
        if ($scope === null) {
            return;
        }
        $settings = cf_get_module_settings_cached();
        if (!is_array($settings)) {
            $settings = [];
        }
        $limit = CfRateLimiter::resolveLimit($scope, $settings);
        CfRateLimiter::enforce($scope, $limit, [
            'userid' => $userId,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'identifier' => $action,
        ]);
    }

    private static function resolveAjaxRateLimitScope(string $action): ?string
    {
        if ($action === '') {
            return null;
        }
        if (in_array($action, ['ajax_create_api_key', 'ajax_regenerate_api_key', 'ajax_delete_api_key'], true)) {
            return CfRateLimiter::SCOPE_API_KEY;
        }
        if (in_array($action, ['ajax_redeem_quota_code', 'ajax_initiate_domain_gift', 'ajax_accept_domain_gift', 'ajax_cancel_domain_gift'], true)) {
            return CfRateLimiter::SCOPE_QUOTA_GIFT;
        }
        if (in_array($action, ['ajax_get_api_key_details', 'ajax_list_quota_redeems', 'ajax_list_domain_gifts'], true)) {
            return null;
        }
        if (strpos($action, 'ajax_') === 0) {
            return CfRateLimiter::SCOPE_AJAX_SENSITIVE;
        }
        return null;
    }

    private static function respondAjaxRateLimitError(CfRateLimitExceededException $e): void
    {
        $minutes = CfRateLimiter::formatRetryMinutes($e->getRetryAfterSeconds());
        $template = cfmod_trans('cfclient.rate_limit.hit', '操作频率过高，请 %s 分钟后再试。');
        try {
            $message = sprintf($template, $minutes);
        } catch (\Throwable $ex) {
            $message = '操作频率过高，请稍后再试。';
        }
        echo json_encode([
            'success' => false,
            'error' => $message,
            'retry_after_minutes' => $minutes,
        ]);
        exit;
    }

    private static function actionText(string $key, string $default, array $params = []): string
    {
        $text = cfmod_trans($key, $default);
        if (!empty($params)) {
            try {
                $text = vsprintf($text, $params);
            } catch (\Throwable $e) {
            }
        }
        return $text;
    }

}
