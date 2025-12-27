<?php
// phpcs:ignoreFile

declare(strict_types=1);

use WHMCS\Database\Capsule;

require_once __DIR__ . '/DnsUnlockService.php';

class CfClientViewModelBuilder
{
    public static function build(int $userId): array
    {
        $globals = [];

        if (function_exists('cfmod_load_language')) {
            cfmod_load_language();
        }

        $languageMeta = function_exists('cfmod_resolve_language_preference') ? cfmod_resolve_language_preference() : ['normalized' => 'english'];
        $currentLanguage = $languageMeta['normalized'] ?? 'english';
        $globals['currentLanguage'] = $currentLanguage;
        $globals['availableLanguages'] = self::buildClientLanguageOptions($currentLanguage);

        $noscriptText = cfmod_trans('cfmod.client.enable_js_notice', '为确保账户安全，请启用浏览器的 JavaScript 后重试。');
        $globals['cfmodClientNoscriptNotice'] = '<noscript><div class="alert alert-danger m-3">' . htmlspecialchars($noscriptText) . '</div></noscript>';
        $globals['msg'] = '';
        $globals['msg_type'] = '';
        $globals['registerError'] = '';

        $moduleSlug = defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
        $legacyModuleSlug = defined('CF_MODULE_NAME_LEGACY') ? CF_MODULE_NAME_LEGACY : 'cloudflare_subdomain';
        $globals['moduleSlug'] = $moduleSlug;
        $globals['legacyModuleSlug'] = $legacyModuleSlug;
        $globals['moduleSlugList'] = array_values(array_unique([$moduleSlug, $legacyModuleSlug]));

        $globals['tables_exist'] = self::checkCoreTablesExist();
        if (!$globals['tables_exist']) {
            $globals['module_settings'] = [];
            return [
                'globals' => $globals,
                'meta' => ['template_variables' => array_keys($globals)],
            ];
        }

        $moduleSettings = self::loadModuleSettings($moduleSlug, $legacyModuleSlug);
        $globals['module_settings'] = $moduleSettings;

        $globals['domainGiftEnabled'] = cfmod_is_domain_gift_enabled($moduleSettings);
        $globals['domainGiftTtlHours'] = cfmod_get_domain_gift_ttl_hours($moduleSettings);
        $globals['quotaRedeemEnabled'] = in_array(($moduleSettings['enable_quota_redeem'] ?? '0'), ['1','on','yes','true','enabled'], true);

        $prefixLimits = function_exists('cf_get_prefix_length_limits') ? cf_get_prefix_length_limits($moduleSettings) : ['min' => 3, 'max' => 32];
        $globals['prefixLengthLimits'] = $prefixLimits;
        $globals['subPrefixMinLength'] = $prefixLimits['min'];
        $globals['subPrefixMaxLength'] = $prefixLimits['max'];
        $globals['subPrefixPatternHtml'] = '[a-zA-Z0-9\-]{' . $prefixLimits['min'] . ',' . $prefixLimits['max'] . '}';

        $globals['forbidden'] = array_map('trim', explode(',', $moduleSettings['forbidden_prefix'] ?? 'www,mail,ftp,admin,root,gov,pay,bank'));
        $globals['disableDnsWrite'] = in_array(($moduleSettings['disable_dns_write'] ?? '0'), ['1','on','yes','true','enabled'], true);
        $globals['pauseFreeRegistration'] = in_array(($moduleSettings['pause_free_registration'] ?? '0'), ['1','on','yes','true','enabled'], true);
        $globals['disableNsManagement'] = in_array(($moduleSettings['disable_ns_management'] ?? '0'), ['1','on','yes','true','enabled'], true);
        $globals['hideInviteFeature'] = in_array(($moduleSettings['hide_invite_feature'] ?? '0'), ['1','on','yes','true','enabled'], true);
        $globals['nsMaxPerDomain'] = max(1, intval($moduleSettings['ns_max_per_domain'] ?? 8));
        $globals['redeemTicketUrl'] = trim($moduleSettings['redeem_ticket_url'] ?? '') ?: 'submitticket.php';

        $globals['maintenanceMode'] = in_array(($moduleSettings['maintenance_mode'] ?? '0'), ['1','on','yes','true','enabled'], true);
        $globals['maintenanceMessage'] = trim($moduleSettings['maintenance_message'] ?? '');

        $dnsUnlockFeatureEnabled = cfmod_setting_enabled($moduleSettings['enable_dns_unlock'] ?? '0');
        $globals['dnsUnlockFeatureEnabled'] = $dnsUnlockFeatureEnabled;
        $dnsUnlockPurchaseEnabledSetting = cfmod_setting_enabled($moduleSettings['dns_unlock_purchase_enabled'] ?? '0');
        $dnsUnlockShareEnabledSetting = cfmod_setting_enabled($moduleSettings['dns_unlock_share_enabled'] ?? '1');
        $dnsUnlockPurchasePriceSetting = round(max(0, (float)($moduleSettings['dns_unlock_purchase_price'] ?? 0)), 2);
        $globals['dnsUnlockPurchaseEnabled'] = $dnsUnlockFeatureEnabled && $dnsUnlockPurchaseEnabledSetting;
        $globals['dnsUnlockShareAllowed'] = $dnsUnlockFeatureEnabled && $dnsUnlockShareEnabledSetting;
        $globals['dnsUnlockPurchasePrice'] = $dnsUnlockPurchasePriceSetting;

        $globals['clientAnnounceEnabled'] = in_array(($moduleSettings['admin_announce_enabled'] ?? '0'), ['1','on','yes','true','enabled'], true);
        $globals['clientAnnounceTitle'] = trim($moduleSettings['admin_announce_title'] ?? '');
        $rawAnnounceHtml = (string) ($moduleSettings['admin_announce_html'] ?? '');
        $decodedAnnounceHtml = html_entity_decode($rawAnnounceHtml, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $trimmedAnnounceHtml = trim($decodedAnnounceHtml);
        if ($trimmedAnnounceHtml !== '' && strip_tags($trimmedAnnounceHtml) === $trimmedAnnounceHtml) {
            $trimmedAnnounceHtml = nl2br($trimmedAnnounceHtml);
        }
        $globals['clientAnnounceHtml'] = $trimmedAnnounceHtml;
        $globals['clientAnnounceCookieKey'] = 'cfmod_client_announce_' . substr(md5(($globals['clientAnnounceTitle'] ?: '') . '|' . ($globals['clientAnnounceHtml'] ?: '')), 0, 8);
        $globals['clientDeleteEnabled'] = cfmod_setting_enabled($moduleSettings['enable_client_domain_delete'] ?? '0');

        // VPN检测配置
        $vpnDetectionEnabled = cfmod_setting_enabled($moduleSettings['enable_vpn_detection'] ?? '0');
        $vpnDetectionDnsEnabled = $vpnDetectionEnabled && cfmod_setting_enabled($moduleSettings['vpn_detection_dns_enabled'] ?? '0');
        $globals['vpnDetectionEnabled'] = $vpnDetectionEnabled;
        $globals['vpnDetectionDnsEnabled'] = $vpnDetectionDnsEnabled;

        $globals['max'] = intval($moduleSettings['max_subdomain_per_user'] ?? 5);
        if ($globals['max'] < 0) {
            $globals['max'] = 5;
        }
        $globals['inviteLimitGlobal'] = intval($moduleSettings['invite_bonus_limit_global'] ?? 5);
        if ($globals['inviteLimitGlobal'] <= 0) {
            $globals['inviteLimitGlobal'] = 5;
        }

        $globals['enableInviteLeaderboard'] = ((($moduleSettings['enable_invite_leaderboard'] ?? 'on') === 'on') || (($moduleSettings['enable_invite_leaderboard'] ?? '1') == '1')) && !in_array(($moduleSettings['hide_invite_feature'] ?? '0'), ['1','on'], true);
        $globals['inviteLeaderboardTop'] = max(1, intval($moduleSettings['invite_leaderboard_top'] ?? 5));
        $globals['inviteLeaderboardDays'] = max(1, intval($moduleSettings['invite_leaderboard_period_days'] ?? 7));
        $globals['inviteCycleStart'] = trim($moduleSettings['invite_cycle_start'] ?? '');
        $globals['inviteRewardInstructions'] = trim($moduleSettings['invite_reward_instructions'] ?? '');
        $globals['hideCurrentWeekLeaderboard'] = ($moduleSettings['hide_current_week_leaderboard'] ?? '') === '1';

        $globals['redemptionModeSetting'] = strtolower(trim($moduleSettings['domain_redemption_mode'] ?? 'manual'));
        if (!in_array($globals['redemptionModeSetting'], ['manual', 'auto_charge'], true)) {
            $globals['redemptionModeSetting'] = 'manual';
        }
        $globals['redemptionFeeSetting'] = round(max(0, (float)($moduleSettings['domain_redemption_fee_amount'] ?? 0)), 2);

        if ($dnsUnlockFeatureEnabled) {
            $unlockPage = isset($_GET['unlock_page']) ? max(1, (int) $_GET['unlock_page']) : 1;
            $dnsUnlockState = self::loadDnsUnlockState($userId, $unlockPage);
            $globals['dnsUnlock'] = $dnsUnlockState;
            $globals['dnsUnlockRequired'] = !$dnsUnlockState['unlocked'];
        } else {
            $globals['dnsUnlock'] = [
                'code' => '',
                'unlocked' => true,
                'logs' => [],
                'pagination' => [
                    'page' => 1,
                    'perPage' => 10,
                    'total' => 0,
                    'totalPages' => 1,
                ],
            ];
            $globals['dnsUnlockRequired'] = false;
        }

        $globals['roots'] = self::loadRootDomains();
        $globals['rootLimitMap'] = self::loadRootLimitMap();

        $globals['userid'] = $userId;
        $globals['myInviteCode'] = self::ensureInviteCode($userId);

        $banState = function_exists('cfmod_resolve_user_ban_state') ? cfmod_resolve_user_ban_state($userId) : ['is_banned' => false, 'reason' => ''];
        $globals['banState'] = $banState;
        $globals['isUserBannedOrInactive'] = !empty($banState['is_banned']);
        $globals['banReasonText'] = $banState['reason'] !== '' ? htmlspecialchars($banState['reason']) : '';

        $quota = self::loadOrCreateQuota($userId, $globals['max'], $globals['inviteLimitGlobal']);
        $globals['quota'] = $quota;
        $globals['domainGiftSubdomains'] = [];

        $domainSearch = self::resolveDomainSearch($moduleSlug, $moduleSettings);
        $globals = array_merge($globals, $domainSearch);

        [$existing, $existingTotal, $domainTotalPages, $domainPage] = \CfSubdomainService::instance()->loadSubdomainsPaginated(
            $userId,
            $domainSearch['domainPage'],
            $domainSearch['domainPageSize'],
            $domainSearch['domainSearchTerm']
        );
        $globals['existing'] = $existing;
        $globals['existing_total'] = $existingTotal;
        $globals['domainTotalPages'] = $domainTotalPages;
        $globals['domainPage'] = $domainPage;

        if ($globals['domainGiftEnabled'] && is_array($existing)) {
            $globals['domainGiftSubdomains'] = array_map(static function ($row) {
                if (is_object($row)) {
                    return [
                        'id' => intval($row->id ?? 0),
                        'fullDomain' => (string)($row->subdomain ?? ''),
                        'rootdomain' => (string)($row->rootdomain ?? ''),
                        'locked' => intval($row->gift_lock_id ?? 0) > 0,
                        'status' => (string)($row->status ?? ''),
                    ];
                }
                return [
                    'id' => intval($row['id'] ?? 0),
                    'fullDomain' => (string)($row['subdomain'] ?? ''),
                    'rootdomain' => (string)($row['rootdomain'] ?? ''),
                    'locked' => intval($row['gift_lock_id'] ?? 0) > 0,
                    'status' => (string)($row['status'] ?? ''),
                ];
            }, $existing);
        }

        $dnsFilter = self::resolveDnsFilter();
        $globals = array_merge($globals, $dnsFilter);

        $dnsDataset = [];
        if (function_exists('cfmod_fetch_dns_records_for_subdomains')) {
            $dnsDataset = cfmod_fetch_dns_records_for_subdomains(
                is_array($existing) ? $existing : [],
                $dnsFilter['filter_type'],
                $dnsFilter['filter_name'],
                [
                    'page_size' => $dnsFilter['dnsPageSize'],
                    'dns_page' => $dnsFilter['dnsPage'],
                    'dns_page_for' => $dnsFilter['dnsPageFor'],
                ]
            );
        }
        $globals['recordsBySubId'] = $dnsDataset['records'] ?? [];
        $globals['filteredBySubId'] = $globals['recordsBySubId'];
        $globals['nsBySubId'] = $dnsDataset['ns'] ?? [];
        $globals['dnsTotalsBySubId'] = $dnsDataset['totals'] ?? [];

        return [
            'globals' => $globals,
            'meta' => ['template_variables' => array_keys($globals)],
        ];
    }

    private static function checkCoreTablesExist(): bool
    {
        try {
            $schema = Capsule::schema();
            return $schema->hasTable('mod_cloudflare_subdomain')
                && $schema->hasTable('mod_cloudflare_subdomain_quotas')
                && $schema->hasTable('mod_cloudflare_rootdomains')
                && $schema->hasTable('mod_cloudflare_dns_records');
        } catch (\Throwable $e) {
            return false;
        }
    }

    private static function loadModuleSettings(string $moduleSlug, string $legacyModuleSlug): array
    {
        try {
            $configs = Capsule::table('tbladdonmodules')->where('module', $moduleSlug)->get();
            if (count($configs) === 0 && $legacyModuleSlug !== $moduleSlug) {
                $configs = Capsule::table('tbladdonmodules')->where('module', $legacyModuleSlug)->get();
            }
            $settings = [];
            foreach ($configs as $config) {
                $settings[$config->setting] = $config->value;
            }
            if (!empty($settings)) {
                return $settings;
            }
        } catch (\Throwable $e) {
            // ignore
        }

        return [
            'cloudflare_api_key' => '',
            'cloudflare_email' => '',
            'max_subdomain_per_user' => 5,
            'root_domains' => '',
            'forbidden_prefix' => 'www,mail,ftp,admin,root,gov,pay,bank',
            'default_ip' => '192.0.2.1'
        ];
    }

    private static function loadDnsUnlockState(int $userId, int $page): array
    {
        $default = [
            'code' => '',
            'unlocked' => false,
            'last_used_code' => '',
            'last_used_owner_userid' => 0,
            'last_used_at' => null,
            'logs' => [],
            'pagination' => [
                'page' => max(1, $page),
                'perPage' => 10,
                'total' => 0,
                'totalPages' => 1,
            ],
        ];
        if ($userId <= 0 || !class_exists('CfDnsUnlockService')) {
            return $default;
        }
        try {
            $profile = CfDnsUnlockService::ensureProfile($userId);
            $logsData = CfDnsUnlockService::fetchLogs($userId, $page, 10);
            $lastUsedInfo = CfDnsUnlockService::getLastUsedUnlockInfo($userId);
            return [
                'code' => $profile['unlock_code'],
                'unlocked' => !empty($profile['unlocked_at']),
                'last_used_code' => $lastUsedInfo['code'] ?? '',
                'last_used_owner_userid' => $lastUsedInfo['owner_userid'] ?? 0,
                'last_used_at' => $lastUsedInfo['used_at'] ?? null,
                'logs' => $logsData['items'] ?? [],
                'pagination' => $logsData['pagination'] ?? $default['pagination'],
            ];
        } catch (\Throwable $e) {
            return $default;
        }
    }

    private static function loadRootDomains(): array
    {
        $roots = [];
        try {
            $rows = Capsule::table('mod_cloudflare_rootdomains')
                ->where('status', 'active')
                ->orderBy('display_order', 'asc')
                ->orderBy('id', 'asc')
                ->get();
            foreach ($rows as $row) {
                $domain = trim((string)($row->domain ?? ''));
                if ($domain !== '') {
                    $roots[] = $domain;
                }
            }
        } catch (\Throwable $e) {
            // ignore
        }

        return array_values(array_unique(array_filter($roots, static function ($d) {
            return $d !== '';
        })));
    }

    private static function loadRootLimitMap(): array
    {
        if (!function_exists('cfmod_get_rootdomain_limits_map')) {
            return [];
        }
        try {
            return array_change_key_case(cfmod_get_rootdomain_limits_map(), CASE_LOWER);
        } catch (\Throwable $e) {
            return [];
        }
    }

    private static function ensureInviteCode(int $userId): string
    {
        try {
            $row = Capsule::table('mod_cloudflare_invitation_codes')->where('userid', $userId)->first();
            if ($row) {
                return (string)($row->code ?? '');
            }
            $attempts = 0;
            do {
                $code = self::generateRandomPrefix() . strtoupper(bin2hex(random_bytes(4)));
                $exists = Capsule::table('mod_cloudflare_invitation_codes')->where('code', $code)->exists();
                $attempts++;
            } while ($exists && $attempts < 5);
            if ($exists) {
                $code = self::generateRandomPrefix() . strtoupper(bin2hex(random_bytes(3)));
            }
            Capsule::table('mod_cloudflare_invitation_codes')->insert([
                'userid' => $userId,
                'code' => $code,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ]);
            return $code;
        } catch (\Throwable $e) {
            return '';
        }
    }

    private static function generateRandomPrefix(): string
    {
        $letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        return $letters[random_int(0, 25)] . $letters[random_int(0, 25)];
    }

    private static function loadOrCreateQuota(int $userId, int $max, int $inviteLimitGlobal)
    {
        try {
            $quota = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userId)->first();
            if (!$quota) {
                Capsule::table('mod_cloudflare_subdomain_quotas')->insert([
                    'userid' => $userId,
                    'used_count' => 0,
                    'max_count' => $max,
                    'invite_bonus_count' => 0,
                    'invite_bonus_limit' => $inviteLimitGlobal,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                $quota = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userId)->first();
            }
            return $quota;
        } catch (\Throwable $e) {
            return (object) [
                'used_count' => 0,
                'max_count' => $max,
                'invite_bonus_count' => 0,
                'invite_bonus_limit' => $inviteLimitGlobal,
            ];
        }
    }

    private static function resolveDomainSearch(string $moduleSlug, array $moduleSettings): array
    {
        $domainSearchTerm = '';
        $domainSearchTermRaw = trim($_GET['domain_search'] ?? '');
        if ($domainSearchTermRaw !== '') {
            $domainSearchTerm = function_exists('mb_substr')
                ? trim(mb_substr($domainSearchTermRaw, 0, 100, 'UTF-8'))
                : trim(substr($domainSearchTermRaw, 0, 100));
        }
        $domainSearchClearParams = $_GET;
        unset($domainSearchClearParams['domain_search'], $domainSearchClearParams['p'], $domainSearchClearParams['page']);
        $domainSearchClearParams['m'] = $moduleSlug;
        $domainSearchClearQueryString = http_build_query($domainSearchClearParams);
        if ($domainSearchClearQueryString === '') {
            $domainSearchClearQueryString = 'm=' . urlencode($moduleSlug);
        }
        $domainPageSizeSetting = intval($moduleSettings['client_page_size'] ?? 20);
        $domainPageSize = max(1, min(20, $domainPageSizeSetting));
        $domainPage = isset($_GET['p']) ? intval($_GET['p']) : 1;
        if ($domainPage < 1) {
            $domainPage = 1;
        }

        return [
            'domainSearchTerm' => $domainSearchTerm,
            'domainSearchClearUrl' => '?' . $domainSearchClearQueryString,
            'domainPageSize' => $domainPageSize,
            'domainPage' => $domainPage,
        ];
    }

    private static function resolveDnsFilter(): array
    {
        $filter_type = trim($_POST['filter_type'] ?? ($_GET['filter_type'] ?? ''));
        $filter_name = trim($_POST['filter_name'] ?? ($_GET['filter_name'] ?? ''));
        $dnsPage = max(1, intval($_GET['dns_page'] ?? 1));
        $dnsPageFor = intval($_GET['dns_for'] ?? 0);
        $dnsPageSize = 20;

        return [
            'filter_type' => $filter_type,
            'filter_name' => $filter_name,
            'dnsPage' => $dnsPage,
            'dnsPageFor' => $dnsPageFor,
            'dnsPageSize' => $dnsPageSize,
        ];
    }

    private static function buildClientLanguageOptions(string $currentLanguage): array
    {
        $moduleSlug = defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
        $supported = self::resolveSupportedLanguages();
        $options = [];

        foreach ($supported as $code) {
            $options[] = [
                'code' => $code,
                'label' => self::resolveLanguageLabel($code),
            ];
        }

        foreach ($options as &$option) {
            $option['active'] = ($option['code'] === $currentLanguage);
            $option['url'] = self::buildLanguageSwitchUrl($moduleSlug, $option['code']);
        }
        unset($option);

        return $options;
    }

    private static function buildLanguageSwitchUrl(string $moduleSlug, string $code): string
    {
        $currentParams = $_GET ?? [];
        if (($currentParams['action'] ?? '') === 'change_language') {
            unset($currentParams['action']);
        }
        unset($currentParams['cf_lang'], $currentParams['lang'], $currentParams['return']);
        $currentParams = self::ensureLanguageBaseParams($currentParams, $moduleSlug);
        $returnToken = self::encodeLanguageRedirectParams($currentParams);

        $params = [
            'm' => $moduleSlug,
            'action' => 'change_language',
            'lang' => $code,
        ];
        if ($returnToken !== '') {
            $params['return'] = $returnToken;
        }

        return 'index.php?' . http_build_query($params);
    }

    private static function encodeLanguageRedirectParams(array $params): string
    {
        if (class_exists('CfClientController') && method_exists('CfClientController', 'encodeLanguageRedirectPayload')) {
            return CfClientController::encodeLanguageRedirectPayload($params);
        }
        return self::fallbackEncodeLanguageParams($params);
    }

    private static function fallbackEncodeLanguageParams(array $params): string
    {
        $query = http_build_query($params);
        if ($query === '') {
            return '';
        }
        return base64_encode($query);
    }

    private static function resolveSupportedLanguages(): array
    {
        if (class_exists('CfClientController') && method_exists('CfClientController', 'getSupportedLanguages')) {
            return CfClientController::getSupportedLanguages();
        }
        return ['english', 'chinese'];
    }

    private static function resolveLanguageLabel(string $code): string
    {
        $map = [
            'english' => ['key' => 'cfclient.language.english', 'default' => 'English'],
            'chinese' => ['key' => 'cfclient.language.chinese', 'default' => '简体中文'],
        ];

        if (isset($map[$code])) {
            return cfmod_trans($map[$code]['key'], $map[$code]['default']);
        }

        return ucfirst($code);
    }

    private static function entryBaseQuery(string $moduleSlug): array
    {
        if (class_exists('CfClientController') && method_exists('CfClientController', 'buildClientBaseQuery')) {
            return CfClientController::buildClientBaseQuery($moduleSlug);
        }
        if (self::detectClientAreaRequest()) {
            return ['action' => 'addon', 'module' => $moduleSlug];
        }
        return ['m' => $moduleSlug];
    }

    private static function ensureLanguageBaseParams(array $params, string $moduleSlug): array
    {
        $baseParams = self::entryBaseQuery($moduleSlug);
        foreach ($baseParams as $key => $value) {
            if (!isset($params[$key]) || $params[$key] === '') {
                $params[$key] = $value;
            }
        }
        return $params;
    }

    private static function detectClientAreaRequest(): bool
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
}
