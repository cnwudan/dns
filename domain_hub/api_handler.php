<?php
if (!defined('WHMCS')) {
    // Try bootstrap WHMCS when called from clientarea index
    $cwd = getcwd();
    $dirs = [ $cwd, dirname($cwd), dirname(dirname($cwd)), dirname(dirname(dirname($cwd))) ];
    foreach ($dirs as $dir) {
        if (is_file($dir . '/init.php')) { require_once $dir . '/init.php'; break; }
    }
}

use WHMCS\Database\Capsule;

require_once __DIR__ . '/lib/autoload.php';
CfModuleSettings::bootstrap();
require_once __DIR__ . '/lib/AtomicOperations.php';
require_once __DIR__ . '/lib/ErrorFormatter.php';
require_once __DIR__ . '/lib/TtlHelper.php';
require_once __DIR__ . '/lib/RootDomainLimitHelper.php';
require_once __DIR__ . '/lib/SecurityHelpers.php';
require_once __DIR__ . '/lib/ProviderResolver.php';


function api_json($arr, $code = 200){
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($arr, JSON_UNESCAPED_UNICODE);
}

function api_get_header($name){
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    return $_SERVER[$key] ?? null;
}

function api_client_ip(){
    return $_SERVER['REMOTE_ADDR'] ?? '';
}

function api_load_settings(): array {
    static $cache = null;
    if (is_array($cache)) {
        return $cache;
    }
    try {
        $rows = Capsule::table('tbladdonmodules')->where('module', CF_MODULE_NAME)->get();
        if (count($rows) === 0) {
            $legacyRows = Capsule::table('tbladdonmodules')->where('module', CF_MODULE_NAME_LEGACY)->get();
            if (count($legacyRows) > 0) {
                foreach ($legacyRows as $row) {
                    Capsule::table('tbladdonmodules')->updateOrInsert(
                        ['module' => CF_MODULE_NAME, 'setting' => $row->setting],
                        ['value' => $row->value]
                    );
                }
                $rows = Capsule::table('tbladdonmodules')->where('module', CF_MODULE_NAME)->get();
                if (count($rows) === 0) {
                    $rows = $legacyRows;
                }
            }
        }
        $settings = [];
        foreach ($rows as $r) {
            $settings[$r->setting] = $r->value;
        }
        $cache = $settings;
    } catch (\Throwable $e) {
        $cache = [];
    }
    return $cache;
}

function api_setting_enabled($value): bool {
    if (is_bool($value)) {
        return $value;
    }
    $normalized = strtolower(trim((string)$value));
    if ($normalized === '') {
        return false;
    }
    return in_array($normalized, ['1', 'on', 'yes', 'true', 'enabled'], true);
}

function api_handle_subdomain_register(array $data, $keyRow, array $settings): array {
    $code = 200;
    $result = null;

    if (api_setting_enabled($settings['maintenance_mode'] ?? '0')) {
        $code = 503;
        $result = ['error' => 'System under maintenance'];
        return [$code, $result];
    }

    if (api_setting_enabled($settings['pause_free_registration'] ?? '0')) {
        $code = 403;
        $result = ['error' => 'Registration paused'];
        return [$code, $result];
    }

    $sub = trim((string)($data['subdomain'] ?? ''));
    $root = trim((string)($data['rootdomain'] ?? ''));
    $prefixLimits = cf_get_prefix_length_limits($settings);
    $prefixMinLen = $prefixLimits['min'];
    $prefixMaxLen = $prefixLimits['max'];
    $subLen = strlen($sub);

    if ($sub === '' || $root === '') {
        $code = 400;
        $result = ['error' => 'invalid parameters'];
        return [$code, $result];
    }

    if (!preg_match('/^[a-zA-Z0-9\-]+$/', $sub)) {
        $code = 400;
        $result = ['error' => 'prefix invalid characters'];
        return [$code, $result];
    }

    if ($subLen < $prefixMinLen || $subLen > $prefixMaxLen) {
        $code = 400;
        $result = [
            'error' => 'prefix length invalid',
            'min_length' => $prefixMinLen,
            'max_length' => $prefixMaxLen
        ];
        return [$code, $result];
    }

    $quota = api_get_user_quota($keyRow->userid, $settings);
    if (!$quota) {
        $code = 500;
        $result = ['error' => 'quota unavailable'];
        return [$code, $result];
    }

    $forbiddenList = array_filter(array_map('trim', explode(',', (string)($settings['forbidden_prefix'] ?? 'www,mail,ftp,admin,root,gov,pay,bank'))));
    $forbiddenLower = array_map('strtolower', $forbiddenList);
    if (in_array(strtolower($sub), $forbiddenLower, true)) {
        $code = 400;
        $result = ['error' => 'prefix forbidden'];
        return [$code, $result];
    }

    $full = strtolower($sub) . '.' . strtolower($root);
    try {
        $isForbidden = Capsule::table('mod_cloudflare_forbidden_domains')
            ->whereRaw('LOWER(domain)=?', [$full])
            ->exists();
    } catch (\Throwable $e) {
        $isForbidden = false;
    }
    if ($isForbidden) {
        $code = 403;
        $result = ['error' => 'domain forbidden'];
        return [$code, $result];
    }

    if (!api_is_rootdomain_allowed($root, $settings)) {
        $code = 400;
        $result = ['error' => 'root domain not allowed'];
        return [$code, $result];
    }

    $limitCheck = function_exists('cfmod_check_rootdomain_user_limit') ? cfmod_check_rootdomain_user_limit($keyRow->userid, $root, 1) : ['allowed' => true, 'limit' => 0];
    if (!$limitCheck['allowed']) {
        $code = 403;
        $limitMessage = cfmod_format_rootdomain_limit_message($root, $limitCheck['limit']);
        if ($limitMessage === '') {
            $limitValueText = max(1, intval($limitCheck['limit'] ?? 0));
            $limitMessage = $root . ' 每个账号最多注册 ' . $limitValueText . ' 个，您已达到上限';
        }
        $result = ['error' => 'root domain per-user limit exceeded', 'message' => $limitMessage];
        return [$code, $result];
    }

    try {
        $existsLocal = Capsule::table('mod_cloudflare_subdomain')
            ->whereRaw('LOWER(subdomain)=?', [$full])
            ->exists();
    } catch (\Throwable $e) {
        $existsLocal = false;
    }
    if ($existsLocal) {
        $code = 400;
        $result = ['error' => 'already registered'];
        return [$code, $result];
    }

    $providerContext = cfmod_acquire_provider_client_for_rootdomain($root, $settings);
    if (!$providerContext || empty($providerContext['client'])) {
        $code = 500;
        $result = ['error' => 'provider unavailable'];
        return [$code, $result];
    }

    $cf = $providerContext['client'];
    $providerAccountId = intval($providerContext['provider_account_id'] ?? 0);
    $zone = $cf->getZoneId($root);
    if (!$zone) {
        $code = 400;
        $result = ['error' => 'root not found'];
        return [$code, $result];
    }
    if ($cf->checkDomainExists($zone, $full)) {
        $code = 400;
        $result = ['error' => 'already exists on DNS'];
        return [$code, $result];
    }

    try {
        $created = cf_atomic_register_subdomain($keyRow->userid, $full, $root, $zone, $settings, [
            'dns_record_id' => null,
            'notes' => '已注册，等待解析设置',
            'provider_account_id' => $providerAccountId > 0 ? $providerAccountId : null,
        ]);
        if (is_object($quota)) {
            $quota->used_count = $created['used_count'];
            $quota->max_count = $created['max_count'];
        }
        $result = [
            'success' => true,
            'message' => 'Subdomain registered successfully',
            'subdomain_id' => $created['id'],
            'full_domain' => $full
        ];
    } catch (CfAtomicQuotaExceededException $e) {
        $code = 403;
        $result = ['error' => 'quota exceeded'];
    } catch (CfAtomicAlreadyRegisteredException $e) {
        $code = 400;
        $result = ['error' => 'already registered'];
    } catch (CfAtomicInvalidPrefixLengthException $e) {
        $code = 400;
        $result = [
            'error' => 'prefix length invalid',
            'min_length' => $prefixMinLen,
            'max_length' => $prefixMaxLen
        ];
    } catch (\Throwable $e) {
        $code = 500;
        $result = ['error' => 'registration failed'];
    }

    return [$code, $result];
}

function api_handle_subdomain_renew(array $data, $keyRow, array $settings): array {
    $code = 200;
    $result = null;

    $subId = intval($data['subdomain_id'] ?? ($_POST['subdomain_id'] ?? 0));
    if ($subId <= 0) {
        $code = 400;
        $result = ['error' => 'invalid parameters'];
        return [$code, $result];
    }

    $termYearsRaw = $settings['domain_registration_term_years'] ?? 1;
    $termYears = is_numeric($termYearsRaw) ? (int)$termYearsRaw : 1;
    if ($termYears <= 0) {
        $code = 403;
        $result = ['error' => 'renewal disabled'];
        return [$code, $result];
    }

    $nowTs = time();
    $freeWindowDays = max(0, intval($settings['domain_free_renew_window_days'] ?? 30));
    $freeWindowSeconds = $freeWindowDays * 86400;
    $graceDaysRaw = $settings['domain_grace_period_days'] ?? ($settings['domain_auto_delete_grace_days'] ?? 45);
    $graceDays = is_numeric($graceDaysRaw) ? (int)$graceDaysRaw : 45;
    if ($graceDays < 0) {
        $graceDays = 0;
    }
    $redemptionDaysRaw = $settings['domain_redemption_days'] ?? 0;
    $redemptionDays = is_numeric($redemptionDaysRaw) ? (int)$redemptionDaysRaw : 0;
    if ($redemptionDays < 0) {
        $redemptionDays = 0;
    }
    $graceSeconds = $graceDays * 86400;
    $redemptionSeconds = $redemptionDays * 86400;
    $redemptionModeRaw = strtolower(trim((string)($settings['domain_redemption_mode'] ?? 'manual')));
    if (!in_array($redemptionModeRaw, ['manual', 'auto_charge'], true)) {
        $redemptionModeRaw = 'manual';
    }
    $redemptionFeeRaw = $settings['domain_redemption_fee_amount'] ?? 0;
    $redemptionFee = round(max(0, (float) $redemptionFeeRaw), 2);

    try {
        $renewResult = Capsule::transaction(function () use ($subId, $keyRow, $termYears, $nowTs, $freeWindowSeconds, $graceSeconds, $redemptionSeconds, $redemptionModeRaw, $redemptionFee) {
            $sub = Capsule::table('mod_cloudflare_subdomain')
                ->where('id', $subId)
                ->where('userid', $keyRow->userid)
                ->lockForUpdate()
                ->first();
            if (!$sub) {
                throw new ApiRenewException('subdomain not found', 404);
            }
            if (intval($sub->never_expires ?? 0) === 1) {
                throw new ApiRenewException('subdomain is set to never expire', 400, ['never_expires' => 1]);
            }
            $statusLower = strtolower((string)($sub->status ?? ''));
            if (!in_array($statusLower, ['active', 'pending'], true)) {
                throw new ApiRenewException('current status does not allow renewal', 403, ['status' => $statusLower]);
            }
            $expiresRaw = $sub->expires_at ?? null;
            if (!$expiresRaw) {
                throw new ApiRenewException('expires_at not set', 400);
            }
            $expiresTs = strtotime($expiresRaw);
            if ($expiresTs === false) {
                throw new ApiRenewException('unable to parse expires_at', 500);
            }
            if ($freeWindowSeconds > 0 && $nowTs < ($expiresTs - $freeWindowSeconds)) {
                $secondsUntil = ($expiresTs - $freeWindowSeconds) - $nowTs;
                $payload = [
                    'seconds_until_window' => max(0, $secondsUntil),
                    'days_until_window' => max(0, (int) ceil($secondsUntil / 86400)),
                ];
                throw new ApiRenewException('renewal not yet available', 403, $payload);
            }
            $graceDeadlineTs = $expiresTs + $graceSeconds;
            $chargeAmount = 0.0;
            if ($nowTs > $graceDeadlineTs) {
                $redemptionDeadlineTs = $graceDeadlineTs + $redemptionSeconds;
                if ($redemptionSeconds > 0 && $nowTs <= $redemptionDeadlineTs) {
                    if ($redemptionModeRaw === 'auto_charge') {
                        if ($redemptionFee > 0) {
                            $clientRow = Capsule::table('tblclients')
                                ->where('id', $keyRow->userid)
                                ->lockForUpdate()
                                ->first();
                            if (!$clientRow) {
                                throw new ApiRenewException('unable to load client balance', 500, ['stage' => 'redemption']);
                            }
                            $currentCredit = (float)($clientRow->credit ?? 0.0);
                            if ($currentCredit + 1e-8 < $redemptionFee) {
                                throw new ApiRenewException('insufficient balance for redemption renewal', 402, [
                                    'stage' => 'redemption',
                                    'reason' => 'insufficient_balance',
                                    'balance' => round($currentCredit, 2),
                                    'required' => $redemptionFee,
                                ]);
                            }
                            $newCredit = round($currentCredit - $redemptionFee, 2);
                            Capsule::table('tblclients')
                                ->where('id', $keyRow->userid)
                                ->update(['credit' => number_format($newCredit, 2, '.', '')]);
                            static $creditSchemaInfo = null;
                            if ($creditSchemaInfo === null) {
                                $creditSchemaInfo = [
                                    'has_table' => false,
                                    'has_relid' => false,
                                    'has_refundid' => false,
                                ];
                                try {
                                    $creditSchemaInfo['has_table'] = Capsule::schema()->hasTable('tblcredit');
                                    if ($creditSchemaInfo['has_table']) {
                                        $creditSchemaInfo['has_relid'] = Capsule::schema()->hasColumn('tblcredit', 'relid');
                                        $creditSchemaInfo['has_refundid'] = Capsule::schema()->hasColumn('tblcredit', 'refundid');
                                    }
                                } catch (\Throwable $ignored) {
                                    $creditSchemaInfo = [
                                        'has_table' => false,
                                        'has_relid' => false,
                                        'has_refundid' => false,
                                    ];
                                }
                            }
                            if ($creditSchemaInfo['has_table']) {
                                $creditInsert = [
                                    'clientid' => $keyRow->userid,
                                    'date' => date('Y-m-d H:i:s', $nowTs),
                                    'description' => 'Redeem period renewal charge',
                                    'amount' => 0 - $redemptionFee,
                                ];
                                if ($creditSchemaInfo['has_relid']) {
                                    $creditInsert['relid'] = 0;
                                }
                                if ($creditSchemaInfo['has_refundid']) {
                                    $creditInsert['refundid'] = 0;
                                }
                                Capsule::table('tblcredit')->insert($creditInsert);
                            }
                            $chargeAmount = $redemptionFee;
                        }
                    } else {
                        throw new ApiRenewException('redemption period requires administrator', 403, ['stage' => 'redemption']);
                    }
                } else {
                    throw new ApiRenewException('renewal window expired', 403, ['stage' => $redemptionSeconds > 0 ? 'redemption_expired' : 'expired']);
                }
            }
            $baseTs = max($expiresTs, $nowTs);
            $nowStr = date('Y-m-d H:i:s', $nowTs);
            $newExpiryTs = strtotime('+' . $termYears . ' years', $baseTs);
            if ($newExpiryTs === false) {
                throw new ApiRenewException('renewal calculation failed', 500);
            }
            $newExpiry = date('Y-m-d H:i:s', $newExpiryTs);
            Capsule::table('mod_cloudflare_subdomain')
                ->where('id', $subId)
                ->update([
                    'expires_at' => $newExpiry,
                    'renewed_at' => $nowStr,
                    'never_expires' => 0,
                    'auto_deleted_at' => null,
                    'updated_at' => $nowStr,
                ]);
            return [
                'subdomain' => $sub->subdomain,
                'status' => $sub->status,
                'previous_expires_at' => $sub->expires_at,
                'new_expires_at' => $newExpiry,
                'renewed_at' => $nowStr,
                'never_expires' => 0,
                'charged_amount' => $chargeAmount,
            ];
        });
        if (function_exists('cloudflare_subdomain_log')) {
            cloudflare_subdomain_log('api_renew_subdomain', [
                'subdomain' => $renewResult['subdomain'],
                'previous_expires_at' => $renewResult['previous_expires_at'],
                'new_expires_at' => $renewResult['new_expires_at'],
                'charged_amount' => $renewResult['charged_amount'] ?? 0,
            ], $keyRow->userid, $subId);
        }
        $newExpiryTs = strtotime($renewResult['new_expires_at']);
        $remainingDays = null;
        if ($newExpiryTs !== false) {
            $remainingDays = max(0, (int) ceil(($newExpiryTs - time()) / 86400));
        }
        $chargedAmount = isset($renewResult['charged_amount']) ? (float)$renewResult['charged_amount'] : 0.0;
        $result = [
            'success' => true,
            'message' => 'Subdomain renewed successfully',
            'subdomain_id' => $subId,
            'subdomain' => $renewResult['subdomain'],
            'previous_expires_at' => $renewResult['previous_expires_at'],
            'new_expires_at' => $renewResult['new_expires_at'],
            'renewed_at' => $renewResult['renewed_at'],
            'never_expires' => $renewResult['never_expires'],
            'status' => $renewResult['status'] ?? null,
            'charged_amount' => $chargedAmount,
        ];
        if ($chargedAmount > 0) {
            $result['message'] = 'Subdomain renewed successfully (charged ' . number_format($chargedAmount, 2, '.', '') . ')';
        }
        if ($remainingDays !== null) {
            $result['remaining_days'] = $remainingDays;
        }
    } catch (ApiRenewException $e) {
        $code = $e->getHttpCode();
        $payload = $e->getPayload();
        $result = array_merge(['error' => $e->getMessage()], $payload);
    } catch (\Throwable $e) {
        if (function_exists('cfmod_report_exception')) {
            cfmod_report_exception('api_renew_subdomain', $e);
        } else {
            error_log('[domain_hub][api_renew_subdomain] ' . $e->getMessage());
        }
        $code = 500;
        $result = ['error' => 'renew failed'];
    }

    return [$code, $result];
}

if (!class_exists('ApiRenewException')) {
    class ApiRenewException extends \RuntimeException {
        protected $httpCode;
        protected $payload;

        public function __construct(string $message, int $httpCode = 400, array $payload = [])
        {
            parent::__construct($message);
            $this->httpCode = $httpCode;
            $this->payload = $payload;
        }

        public function getHttpCode(): int
        {
            return $this->httpCode;
        }

        public function getPayload(): array
        {
            return $this->payload;
        }
    }
}



function api_root_config_list(array $settings): array {
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $domains = [];
    try {
        if (Capsule::schema()->hasTable('mod_cloudflare_rootdomains')) {
            $rows = Capsule::table('mod_cloudflare_rootdomains')
                ->where('status', 'active')
                ->orderBy('id', 'asc')
                ->get();
            foreach ($rows as $row) {
                $value = trim((string)($row->domain ?? ''));
                if ($value !== '') {
                    $domains[] = $value;
                }
            }
        }
    } catch (\Throwable $e) {
        // ignore lookup errors
    }
    $domains = array_values(array_unique($domains));
    $cache = $domains;
    return $domains;
}

function api_is_rootdomain_allowed(string $rootdomain, array $settings): bool {
    $rootdomain = strtolower(trim($rootdomain));
    if ($rootdomain === '') {
        return false;
    }

    $active = array_map('strtolower', api_root_config_list($settings));
    return in_array($rootdomain, $active, true);
}

function api_get_user_quota(int $userid, array $settings) {
    if ($userid <= 0) {
        return null;
    }
    try {
        if (!Capsule::schema()->hasTable('mod_cloudflare_subdomain_quotas')) {
            return null;
        }
    } catch (\Throwable $e) {
        return null;
    }

    try {
        $quota = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userid)->first();
    } catch (\Throwable $e) {
        $quota = null;
    }

    $maxBase = max(0, intval($settings['max_subdomain_per_user'] ?? 0));
    $inviteLimit = intval($settings['invite_bonus_limit_global'] ?? 5);
    if ($inviteLimit <= 0) {
        $inviteLimit = 5;
    }
    $isPrivileged = function_exists('cf_is_user_privileged') && cf_is_user_privileged($userid);
    $privilegedLimit = cf_get_privileged_limit();
    if ($isPrivileged) {
        $maxBase = $privilegedLimit;
    }
    $now = date('Y-m-d H:i:s');

    if (!$quota) {
        try {
            Capsule::table('mod_cloudflare_subdomain_quotas')->insert([
                'userid' => $userid,
                'used_count' => 0,
                'max_count' => $maxBase,
                'invite_bonus_count' => 0,
                'invite_bonus_limit' => $inviteLimit,
                'created_at' => $now,
                'updated_at' => $now
            ]);
            $quota = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userid)->first();
        } catch (\Throwable $e) {
            $quota = (object)[
                'userid' => $userid,
                'used_count' => 0,
                'max_count' => $maxBase,
                'invite_bonus_count' => 0,
                'invite_bonus_limit' => $inviteLimit,
            ];
        }
    }

    if ($isPrivileged) {
        return cf_ensure_privileged_quota($userid, $quota, $inviteLimit);
    }

    if (function_exists('cf_sync_user_base_quota_if_needed')) {
        $quota = cf_sync_user_base_quota_if_needed($userid, $maxBase, $quota);
    } elseif ($quota && $maxBase > 0 && intval($quota->max_count ?? 0) < $maxBase) {
        try {
            Capsule::table('mod_cloudflare_subdomain_quotas')
                ->where('userid', $userid)
                ->update([
                    'max_count' => $maxBase,
                    'updated_at' => $now
                ]);
            $quota->max_count = $maxBase;
        } catch (\Throwable $e) {
            // ignore update errors
        }
    }

    if (function_exists('cf_sync_user_invite_limit_if_needed')) {
        $quota = cf_sync_user_invite_limit_if_needed($userid, $inviteLimit, $quota);
    } elseif ($quota && $inviteLimit > 0 && intval($quota->invite_bonus_limit ?? 0) < $inviteLimit) {
        try {
            Capsule::table('mod_cloudflare_subdomain_quotas')
                ->where('userid', $userid)
                ->update([
                    'invite_bonus_limit' => $inviteLimit,
                    'updated_at' => $now
                ]);
            $quota->invite_bonus_limit = $inviteLimit;
        } catch (\Throwable $e) {
            // ignore update errors
        }
    }

    return $quota;
}

function api_cleanup_rate_limit_table(int $hours = 48): void {
    static $lastCleanupTs = null;
    $hours = max(1, $hours);
    $now = time();
    if ($lastCleanupTs !== null && ($now - $lastCleanupTs) < 60) {
        return;
    }
    $lastCleanupTs = $now;

    try {
        if (!Capsule::schema()->hasTable('mod_cloudflare_api_rate_limit')) {
            return;
        }
    } catch (\Throwable $e) {
        return;
    }

    try {
        $cutoff = date('Y-m-d H:i:s', $now - $hours * 3600);
        Capsule::table('mod_cloudflare_api_rate_limit')
            ->where('window_end', '<', $cutoff)
            ->delete();
    } catch (\Throwable $e) {
        // ignore cleanup errors
    }
}

function api_auth(){
    $apiKey = api_get_header('X-API-Key') ?: ($_GET['api_key'] ?? $_POST['api_key'] ?? null);
    $apiSecret = api_get_header('X-API-Secret') ?: ($_GET['api_secret'] ?? $_POST['api_secret'] ?? null);
    if (!$apiKey || !$apiSecret) { return [false, 'Missing API credentials']; }
    $row = Capsule::table('mod_cloudflare_api_keys')->where('api_key', $apiKey)->first();
    if (!$row) { return [false, 'Invalid API key']; }
    if (($row->status ?? '') !== 'active') { return [false, 'API key disabled']; }
    if (!password_verify((string)$apiSecret, (string)$row->api_secret)) { return [false, 'Invalid API secret']; }
    // IP whitelist
    $ipwl = trim((string)($row->ip_whitelist ?? ''));
    if ($ipwl !== ''){
        $ips = array_filter(array_map('trim', preg_split('/[,\n\r]+/', $ipwl)));
        if (!in_array(api_client_ip(), $ips, true)) {
            return [false, 'IP not allowed'];
        }
    }

    try {
        $client = Capsule::table('tblclients')->select('status')->where('id', $row->userid)->first();
        if ($client && strtolower($client->status ?? '') !== 'active') {
            return [false, 'User is banned'];
        }
        if (Capsule::schema()->hasTable('mod_cloudflare_user_bans')) {
            $banned = Capsule::table('mod_cloudflare_user_bans')
                ->where('userid', $row->userid)
                ->where('status', 'banned')
                ->exists();
            if ($banned) {
                return [false, 'User is banned'];
            }
        }
    } catch (\Throwable $e) {
        // ignore schema/query errors silently
    }

    return [true, $row];
}

function api_rate_limit($keyRow, ?array $settings = null){
    if ($settings === null) {
        $settings = api_load_settings();
    }

    $limit = intval($keyRow->rate_limit ?? 0);
    if ($limit <= 0) {
        $limit = intval($settings['api_rate_limit'] ?? 60);
    }
    $limit = max(1, min(6000, $limit));

    $windowKey = $keyRow->id . '_' . date('Y-m-d_H:i');
    $windowStart = date('Y-m-d H:i:00');
    $windowEnd = date('Y-m-d H:i:59');
    $now = date('Y-m-d H:i:s');
    $currentCount = null;

    try {
        Capsule::transaction(function () use ($keyRow, $windowKey, $windowStart, $windowEnd, $now, &$currentCount) {
            Capsule::statement(
                'INSERT INTO `mod_cloudflare_api_rate_limit` (`api_key_id`, `window_key`, `request_count`, `window_start`, `window_end`, `created_at`, `updated_at`)' .
                ' VALUES (?, ?, 1, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE `request_count` = `request_count` + 1, `updated_at` = VALUES(`updated_at`)',
                [$keyRow->id, $windowKey, $windowStart, $windowEnd, $now, $now]
            );

            $currentCount = (int) Capsule::table('mod_cloudflare_api_rate_limit')
                ->where('api_key_id', $keyRow->id)
                ->where('window_key', $windowKey)
                ->value('request_count');
        });
    } catch (\Throwable $e) {
        error_log('[domain_hub][api_rate_limit] ' . $e->getMessage());
        return [false, [
            'error' => 'Rate limit temporarily unavailable',
            'reason' => 'storage_error',
            'remaining' => 0,
            'limit' => $limit,
            'reset_at' => $windowEnd,
            'status_code' => 503
        ]];
    }

    if ($currentCount === null) {
        $currentCount = 1;
    }

    api_cleanup_rate_limit_table();

    if ($currentCount > $limit) {
        return [false, [
            'error' => 'Rate limit exceeded',
            'reason' => 'limit_exceeded',
            'remaining' => 0,
            'limit' => $limit,
            'reset_at' => $windowEnd,
            'status_code' => 429
        ]];
    }

    return [true, ['remaining' => max(0, $limit - $currentCount), 'limit' => $limit, 'reset_at' => $windowEnd]];
}

function api_enforce_scope_rate_limit(string $scope, $keyRow, array $settings, string $identifier): void
{
    if (!$keyRow) {
        return;
    }
    $limit = CfRateLimiter::resolveLimit($scope, $settings);
    CfRateLimiter::enforce($scope, $limit, [
        'userid' => intval($keyRow->userid ?? 0),
        'ip' => api_client_ip(),
        'identifier' => $identifier,
    ]);
}

function api_emit_scope_rate_limit_error(CfRateLimitExceededException $e): void
{
    $minutes = CfRateLimiter::formatRetryMinutes($e->getRetryAfterSeconds());
    api_json([
        'error' => 'rate_limit_exceeded',
        'message' => 'Too many requests. Please try again in ' . $minutes . ' minutes.',
        'retry_after_seconds' => $e->getRetryAfterSeconds(),
        'retry_after_minutes' => $minutes,
    ], 429);
    exit;
}

function cfmod_normalize_whois_domain(?string $domain): string {
    $clean = strtolower(trim((string) $domain));
    $clean = trim($clean, '.');
    if ($clean === '' || strpos($clean, '.') === false) {
        return '';
    }
    if (strlen($clean) > 253 || strpos($clean, '..') !== false) {
        return '';
    }
    if (!preg_match('/^[a-z0-9.-]+$/', $clean)) {
        return '';
    }
    return $clean;
}

function cfmod_detect_allowed_rootdomain(string $domain, array $settings): ?string {
    $parts = explode('.', $domain);
    $count = count($parts);
    if ($count < 2) {
        return null;
    }
    for ($i = 1; $i < $count; $i++) {
        $candidateParts = array_slice($parts, $i);
        if (count($candidateParts) < 2) {
            continue;
        }
        $candidate = implode('.', $candidateParts);
        if (api_is_rootdomain_allowed($candidate, $settings)) {
            return $candidate;
        }
    }
    return null;
}

function cfmod_mask_email_for_whois(?string $email): string {
    $email = trim((string) $email);
    if ($email === '' || strpos($email, '@') === false) {
        return '';
    }
    [$local, $domain] = explode('@', $email, 2);
    $localMasked = strlen($local) > 2 ? substr($local, 0, 2) . str_repeat('*', max(1, strlen($local) - 2)) : str_repeat('*', strlen($local));
    $domainMasked = $domain;
    if (strlen($domain) > 4) {
        $parts = explode('.', $domain);
        $parts = array_map(function ($segment) {
            if (strlen($segment) <= 2) {
                return str_repeat('*', strlen($segment));
            }
            return substr($segment, 0, 1) . str_repeat('*', max(1, strlen($segment) - 2)) . substr($segment, -1);
        }, $parts);
        $domainMasked = implode('.', $parts);
    }
    return $localMasked . '@' . $domainMasked;
}

function cfmod_parse_default_nameservers($value): array {
    $list = preg_split('/[\r\n]+/', (string) $value);
    $result = [];
    foreach ($list as $item) {
        $item = trim($item);
        if ($item !== '') {
            $result[] = $item;
        }
    }
    return array_values(array_unique($result));
}

function cfmod_build_whois_response($domainInput, array $settings): array {
    $domain = cfmod_normalize_whois_domain($domainInput);
    if ($domain === '') {
        return [400, ['success' => false, 'error' => 'invalid domain'], null];
    }
    $rootdomain = cfmod_detect_allowed_rootdomain($domain, $settings);
    if ($rootdomain === null) {
        return [403, ['success' => false, 'error' => 'root domain unmanaged', 'domain' => $domain], null];
    }
    try {
        $record = Capsule::table('mod_cloudflare_subdomain as s')
            ->leftJoin('tblclients as c', 's.userid', '=', 'c.id')
            ->select('s.*', 'c.email as client_email')
            ->whereRaw('LOWER(s.subdomain)=?', [$domain])
            ->first();
    } catch (\Throwable $e) {
        return [500, ['success' => false, 'error' => 'lookup failed'], null];
    }
    if (!$record) {
        return [200, [
            'success' => true,
            'domain' => $domain,
            'registered' => false,
            'status' => 'unregistered',
            'message' => 'domain not registered'
        ], null];
    }

    $nameservers = [];
    try {
        $nsRows = Capsule::table('mod_cloudflare_dns_records')
            ->where('subdomain_id', $record->id)
            ->where('type', 'NS')
            ->orderBy('id', 'asc')
            ->pluck('content');
        if ($nsRows instanceof \Illuminate\Support\Collection) {
            $nsRows = $nsRows->all();
        }
        foreach ((array)$nsRows as $ns) {
            $ns = trim((string)$ns);
            if ($ns !== '') {
                $nameservers[] = $ns;
            }
        }
    } catch (\Throwable $e) {}
    if (empty($nameservers)) {
        $nameservers = cfmod_parse_default_nameservers($settings['whois_default_nameservers'] ?? '');
    }

    $emailMode = strtolower((string)($settings['whois_email_mode'] ?? 'anonymous'));
    $anonEmail = trim((string)($settings['whois_anonymous_email'] ?? 'whois@example.com'));
    if ($anonEmail === '') {
        $anonEmail = 'whois@example.com';
    }
    $clientEmail = trim((string)($record->client_email ?? ''));
    if ($emailMode === 'real') {
        $whoisEmail = $clientEmail !== '' ? $clientEmail : $anonEmail;
    } elseif ($emailMode === 'masked') {
        $masked = cfmod_mask_email_for_whois($clientEmail);
        $whoisEmail = $masked !== '' ? $masked : $anonEmail;
    } else {
        $whoisEmail = $anonEmail;
    }

    $neverExpires = (bool) ($record->never_expires ?? false);
    $expiresAt = $record->expires_at;
    if ($neverExpires) {
        $expiresAt = '2099-12-31 23:59:59';
    }

    $response = [
        'success' => true,
        'domain' => $record->subdomain,
        'status' => $record->status,
        'registered_at' => $record->created_at,
        'expires_at' => $expiresAt,
        'registrant_email' => $whoisEmail,
        'nameservers' => array_values(array_unique($nameservers)),
    ];

    return [200, $response, $record];
}

function cfmod_log_whois_query($record, string $mode): void {
    if (!function_exists('cloudflare_subdomain_log')) {
        return;
    }
    $details = [
        'domain' => $record->subdomain ?? '',
        'mode' => $mode,
        'ip' => api_client_ip(),
    ];
    $userid = isset($record->userid) ? intval($record->userid) : null;
    $subId = isset($record->id) ? intval($record->id) : null;
    cloudflare_subdomain_log('whois_query', $details, $userid > 0 ? $userid : null, $subId > 0 ? $subId : null);
}

function cfmod_cleanup_whois_rate_limit_table(): void {
    static $lastCleanup = null;
    $now = time();
    if ($lastCleanup !== null && ($now - $lastCleanup) < 60) {
        return;
    }
    $lastCleanup = $now;
    try {
        Capsule::table('mod_cloudflare_whois_rate_limit')
            ->where('window_end', '<', date('Y-m-d H:i:s', $now - 3600))
            ->delete();
    } catch (\Throwable $e) {}
}

function cfmod_whois_rate_limit(array $settings): array {
    $limit = intval($settings['whois_rate_limit_per_minute'] ?? 2);
    if ($limit <= 0) {
        return [true, null];
    }
    $ip = api_client_ip() ?: 'unknown';
    $windowKey = date('Y-m-d_H:i');
    $windowStart = date('Y-m-d H:i:00');
    $windowEnd = date('Y-m-d H:i:59');
    $now = date('Y-m-d H:i:s');
    try {
        Capsule::statement(
            'INSERT INTO `mod_cloudflare_whois_rate_limit` (`ip`,`window_key`,`request_count`,`window_start`,`window_end`,`created_at`,`updated_at`) VALUES (?,?,?,?,?,?,?) '
            . 'ON DUPLICATE KEY UPDATE `request_count` = `request_count` + 1, `updated_at` = VALUES(`updated_at`)',
            [$ip, $windowKey, 1, $windowStart, $windowEnd, $now, $now]
        );
        $count = Capsule::table('mod_cloudflare_whois_rate_limit')
            ->where('ip', $ip)
            ->where('window_key', $windowKey)
            ->value('request_count');
    } catch (\Throwable $e) {
        return [true, ['limit' => $limit, 'remaining' => $limit, 'reset_at' => $windowEnd]];
    }
    cfmod_cleanup_whois_rate_limit_table();
    $meta = [
        'limit' => $limit,
        'remaining' => max(0, $limit - intval($count)),
        'reset_at' => $windowEnd
    ];
    if (intval($count) > $limit) {
        $meta['remaining'] = 0;
        return [false, $meta];
    }
    return [true, $meta];
}

function cfmod_handle_public_whois(array $settings, string $method, array $data): void {
    if (strtoupper($method) !== 'GET') {
        api_json(['success' => false, 'error' => 'method not allowed'], 405);
        return;
    }
    $domainParam = $_GET['domain'] ?? ($data['domain'] ?? '');
    $normalized = cfmod_normalize_whois_domain($domainParam);
    if ($normalized === '') {
        api_json(['success' => false, 'error' => 'invalid domain'], 400);
        return;
    }
    list($pass, $meta) = cfmod_whois_rate_limit($settings);
    if (!$pass) {
        $payload = ['success' => false, 'error' => 'rate limit exceeded'];
        if ($meta !== null) {
            $payload['rate_limit'] = $meta;
        }
        api_json($payload, 429);
        return;
    }
    list($status, $payload, $record) = cfmod_build_whois_response($normalized, $settings);
    if ($meta !== null) {
        $payload['rate_limit'] = $meta;
    }
    if ($status === 200 && $record) {
        cfmod_log_whois_query($record, 'public');
    }
    api_json($payload, $status);
}

function handleApiRequest(){
    $t0 = microtime(true);
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $rawIn = file_get_contents('php://input');
    $data = json_decode($rawIn, true);
    if (!is_array($data)) { $data = $_POST; }
    $endpoint = $_GET['endpoint'] ?? ($data['endpoint'] ?? '');
    $action = $_GET['action'] ?? ($data['action'] ?? '');
    $settings = api_load_settings();

    if ($endpoint === 'whois' && !api_setting_enabled($settings['whois_require_api_key'] ?? '0')) {
        cfmod_handle_public_whois($settings, $method, $data);
        return;
    }

    try {
        list($ok, $auth) = api_auth();
        if (!$ok) { api_json(['error'=>$auth], 401); return; }
        $keyRow = $auth;

        list($pass, $rl) = api_rate_limit($keyRow, $settings);
        if (!$pass){
            $status = intval($rl['status_code'] ?? 429);
            $payload = $rl;
            unset($payload['status_code']);
            if (!isset($payload['error'])) {
                $payload['error'] = 'Rate limit exceeded';
            }
            api_json($payload, $status);
            return;
        }
        if ($endpoint !== 'whois' && !api_setting_enabled($settings['enable_user_api'] ?? 'on')) {
            api_json(['error' => 'API access disabled'], 403);
            return;
        }

        $result = null;
        $code = 200;

        if ($endpoint === 'whois') {
            if (strtoupper($method) !== 'GET') {
                $code = 405;
                $result = ['error' => 'method not allowed'];
            } else {
                $domainParam = $_GET['domain'] ?? ($data['domain'] ?? '');
                list($code, $payload, $whoisRecord) = cfmod_build_whois_response($domainParam, $settings);
                $result = $payload;
                if ($code === 200 && $whoisRecord) {
                    cfmod_log_whois_query($whoisRecord, 'api');
                }
            }
        } elseif ($endpoint === 'quota' && $method === 'GET') {
            $quota = api_get_user_quota($keyRow->userid, $settings);
            if ($quota) {
                $used = intval($quota->used_count ?? 0);
                $base = intval($quota->max_count ?? 0);
                $bonus = intval($quota->invite_bonus_count ?? 0);
            } else {
                $used = 0;
                $base = intval($settings['max_subdomain_per_user'] ?? 0);
                $bonus = 0;
            }
            $total = $base;
            $available = max(0, $total - $used);
            $result = [
                'success' => true,
                'quota' => [
                    'used' => $used,
                    'base' => $base,
                    'invite_bonus' => $bonus,
                    'total' => $total,
                    'available' => $available
                ]
            ];
        } elseif ($endpoint === 'subdomains') {
            if ($action === 'list' && $method === 'GET') {
                $pageRaw = $_GET['page'] ?? ($data['page'] ?? 1);
                $page = intval($pageRaw);
                if ($page <= 0) {
                    $page = 1;
                }
                $perPageRaw = $_GET['per_page'] ?? ($data['per_page'] ?? 200);
                $perPage = intval($perPageRaw);
                if ($perPage <= 0) {
                    $perPage = 200;
                }
                $perPage = max(1, min(500, $perPage));
                $offset = ($page - 1) * $perPage;
                $includeTotalRaw = $_GET['include_total'] ?? ($data['include_total'] ?? null);
                $includeTotal = false;
                if ($includeTotalRaw !== null) {
                    $includeTotal = api_setting_enabled($includeTotalRaw);
                }

                $baseQuery = Capsule::table('mod_cloudflare_subdomain')
                    ->where('userid', $keyRow->userid);
                $dataQuery = (clone $baseQuery)->orderBy('id', 'desc');
                $subsCollection = $dataQuery
                    ->offset($offset)
                    ->limit($perPage + 1)
                    ->get();
                if (!($subsCollection instanceof \Illuminate\Support\Collection)) {
                    $subsCollection = new \Illuminate\Support\Collection(is_array($subsCollection) ? $subsCollection : (array) $subsCollection);
                }
                $hasMore = $subsCollection->count() > $perPage;
                $subsLimited = $hasMore ? $subsCollection->slice(0, $perPage)->values() : $subsCollection->values();
                $rows = [];
                foreach ($subsLimited as $s) {
                    $rows[] = [
                        'id' => $s->id,
                        'subdomain' => $s->subdomain,
                        'rootdomain' => $s->rootdomain,
                        'full_domain' => $s->subdomain,
                        'status' => $s->status,
                        'created_at' => $s->created_at,
                        'updated_at' => $s->updated_at
                    ];
                }
                $meta = [
                    'page' => $page,
                    'per_page' => $perPage,
                    'has_more' => $hasMore,
                ];
                if ($hasMore) {
                    $meta['next_page'] = $page + 1;
                }
                if ($page > 1) {
                    $meta['prev_page'] = $page - 1;
                }
                if ($includeTotal) {
                    $meta['total'] = (clone $baseQuery)->count();
                }
                $result = [
                    'success' => true,
                    'count' => count($rows),
                    'subdomains' => $rows,
                    'pagination' => $meta
                ];
            } elseif ($action === 'register' && in_array($method, ['POST', 'PUT'])) {
                try {
                    api_enforce_scope_rate_limit(CfRateLimiter::SCOPE_REGISTER, $keyRow, $settings, 'api_subdomain_register');
                } catch (CfRateLimitExceededException $e) {
                    api_emit_scope_rate_limit_error($e);
                }
                list($code, $result) = api_handle_subdomain_register($data, $keyRow, $settings);
            } elseif ($action === 'renew' && in_array($method, ['POST', 'PUT'])) {
                list($code, $result) = api_handle_subdomain_renew($data, $keyRow, $settings);
            } else {
                $code = 404;
                $result = ['error' => 'unknown action'];
            }
        } elseif ($endpoint === 'dns_records') {
            if ($action === 'list' && $method === 'GET') {
                $sid = intval($_GET['subdomain_id'] ?? 0);
                $s = Capsule::table('mod_cloudflare_subdomain')
                    ->where('id', $sid)
                    ->where('userid', $keyRow->userid)
                    ->first();
                if (!$s) {
                    $code = 404;
                    $result = ['error' => 'subdomain not found'];
                } else {
                    $recs = Capsule::table('mod_cloudflare_dns_records')
                        ->where('subdomain_id', $sid)
                        ->orderBy('id', 'asc')
                        ->get();
                    $rows = [];
                    foreach ($recs as $r) {
                        $rows[] = [
                            'id' => $r->id,
                            'name' => $r->name,
                            'type' => $r->type,
                            'content' => $r->content,
                            'ttl' => intval($r->ttl),
                            'priority' => $r->priority,
                            'proxied' => boolval($r->proxied),
                            'status' => $r->status,
                            'created_at' => $r->created_at
                        ];
                    }
                    $result = ['success' => true, 'count' => count($rows), 'records' => $rows];
                }
            } elseif ($action === 'create' && in_array($method, ['POST', 'PUT'])) {
                if (api_setting_enabled($settings['maintenance_mode'] ?? '0')) {
                    $code = 503;
                    $result = ['error' => 'System under maintenance'];
                } elseif (api_setting_enabled($settings['disable_dns_write'] ?? '0')) {
                    $code = 403;
                    $result = ['error' => 'DNS modifications disabled'];
                } else {
                    try {
                        api_enforce_scope_rate_limit(CfRateLimiter::SCOPE_DNS, $keyRow, $settings, 'api_dns_create');
                    } catch (CfRateLimitExceededException $e) {
                        api_emit_scope_rate_limit_error($e);
                    }
                    $sid = intval($data['subdomain_id'] ?? 0);
                    $type = strtoupper(trim((string)($data['type'] ?? '')));
                    $content = trim((string)($data['content'] ?? ''));
                    $ttl = cfmod_normalize_ttl($data['ttl'] ?? 600);
                    $allowedTypes = ['A', 'AAAA', 'CNAME', 'TXT', 'MX'];
                    if (!in_array($type, $allowedTypes, true)) {
                        $code = 400;
                        $result = ['error' => 'invalid type'];
                    } else {
                        $s = Capsule::table('mod_cloudflare_subdomain')
                            ->where('id', $sid)
                            ->where('userid', $keyRow->userid)
                            ->first();
                        if (!$s) {
                            $code = 404;
                            $result = ['error' => 'subdomain not found'];
                        } elseif (strtolower($s->status ?? '') === 'suspended') {
                            $code = 403;
                            $result = ['error' => 'subdomain suspended'];
                        } else {
                            $limitPerSub = intval($settings['max_dns_records_per_subdomain'] ?? 0);
                            $providerContext = cfmod_acquire_provider_client_for_subdomain($s, $settings);
                            if (!$providerContext || empty($providerContext['client'])) {
                                $code = 500;
                                $result = ['error' => 'provider unavailable'];
                            } else {
                                $cf = $providerContext['client'];
                                $name = $s->subdomain;
                                if (!empty($data['name']) && $data['name'] !== '@') {
                                    $name = trim($data['name']) . '.' . $s->subdomain;
                                }
                                $priority = intval($data['priority'] ?? 10);
                                try {
                                    $creation = cf_atomic_run_with_dns_limit($sid, $limitPerSub, function () use ($cf, $s, $type, $content, $ttl, $name, $priority) {
                                        if ($type === 'MX') {
                                            $res = $cf->createMXRecord($s->cloudflare_zone_id ?: $s->rootdomain, $name, $content, $priority, $ttl);
                                        } else {
                                            $res = $cf->createDnsRecord($s->cloudflare_zone_id ?: $s->rootdomain, $name, $type, $content, $ttl, false);
                                        }
                                        if (!($res['success'] ?? false)) {
                                            $message = $res['errors'][0] ?? ($res['errors'] ?? 'create failed');
                                            if (is_array($message)) {
                                                $message = json_encode($message, JSON_UNESCAPED_UNICODE);
                                            }
                                            throw new \RuntimeException((string)$message);
                                        }
                                        $rid = $res['result']['id'] ?? null;
                                        Capsule::table('mod_cloudflare_dns_records')->insert([
                                            'subdomain_id' => $s->id,
                                            'zone_id' => $s->cloudflare_zone_id ?: $s->rootdomain,
                                            'record_id' => $rid,
                                            'name' => strtolower($name),
                                            'type' => $type,
                                            'content' => $content,
                                            'ttl' => $ttl,
                                            'proxied' => 0,
                                            'status' => 'active',
                                            'priority' => $type === 'MX' ? $priority : null,
                                            'created_at' => date('Y-m-d H:i:s'),
                                            'updated_at' => date('Y-m-d H:i:s')
                                        ]);
                                        CfSubdomainService::markHasDnsHistory($s->id);
                                        return ['record_id' => $rid];
                                    });
                                    CfSubdomainService::syncDnsHistoryFlag($s->id);
                                    $result = ['success' => true, 'message' => 'DNS record created successfully', 'record_id' => $creation['record_id']];
                                } catch (CfAtomicRecordLimitException $e) {
                                    $code = 403;
                                    $result = ['error' => 'record limit reached'];
                                } catch (\RuntimeException $e) {
                                    $code = 400;
                                    $result = ['error' => cfmod_format_provider_error($e->getMessage())];
                                } catch (\Throwable $e) {
                                    $code = 500;
                                    $result = ['error' => 'create failed'];
                                }
                            }
                        }
                    }
                }
            } elseif ($action === 'delete' && in_array($method, ['POST', 'DELETE'])) {
                if (api_setting_enabled($settings['maintenance_mode'] ?? '0')) {
                    $code = 503;
                    $result = ['error' => 'System under maintenance'];
                } elseif (api_setting_enabled($settings['disable_dns_write'] ?? '0')) {
                    $code = 403;
                    $result = ['error' => 'DNS modifications disabled'];
                } else {
                    try {
                        api_enforce_scope_rate_limit(CfRateLimiter::SCOPE_DNS, $keyRow, $settings, 'api_dns_delete');
                    } catch (CfRateLimitExceededException $e) {
                        api_emit_scope_rate_limit_error($e);
                    }
                    $recordIdentifierRaw = $data['record_id'] ?? null;
                    $recordIdentifier = null;
                    if ($recordIdentifierRaw !== null && !is_array($recordIdentifierRaw)) {
                        $recordIdentifier = trim((string) $recordIdentifierRaw);
                        if ($recordIdentifier === '') {
                            $recordIdentifier = null;
                        }
                    }
                    $localId = intval($data['id'] ?? 0);
                    $rec = null;
                    if ($recordIdentifier !== null) {
                        if (ctype_digit($recordIdentifier)) {
                            $rec = Capsule::table('mod_cloudflare_dns_records')->where('id', intval($recordIdentifier))->first();
                        }
                        if (!$rec) {
                            $rec = Capsule::table('mod_cloudflare_dns_records')->where('record_id', $recordIdentifier)->first();
                        }
                    }
                    if (!$rec && $localId > 0) {
                        $rec = Capsule::table('mod_cloudflare_dns_records')->where('id', $localId)->first();
                    }
                    if (!$rec) {
                        $code = 404;
                        $result = ['error' => 'record not found'];
                    } else {
                        $sid = intval($rec->subdomain_id);
                        $zone = $rec->zone_id;
                        $rid = $rec->record_id;
                        $s = Capsule::table('mod_cloudflare_subdomain')
                            ->where('id', $sid)
                            ->where('userid', $keyRow->userid)
                            ->first();
                        if (!$s) {
                            $code = 403;
                            $result = ['error' => 'forbidden'];
                        } elseif (strtolower($s->status ?? '') === 'suspended') {
                            $code = 403;
                            $result = ['error' => 'subdomain suspended'];
                        } else {
                            $providerContext = cfmod_acquire_provider_client_for_subdomain($s, $settings);
                            if (!$providerContext || empty($providerContext['client'])) {
                                $code = 500;
                                $result = ['error' => 'provider unavailable'];
                            } else {
                                $cf = $providerContext['client'];
                                if ($rid) {
                                    $cf->deleteSubdomain($zone ?: ($s->cloudflare_zone_id ?: $s->rootdomain), $rid);
                                }
                                Capsule::table('mod_cloudflare_dns_records')->where('id', $rec->id)->delete();
                                $result = ['success' => true, 'message' => 'DNS record deleted successfully'];
                            }
                        }
                    }
                }
            } elseif ($action === 'update' && in_array($method, ['POST', 'PUT', 'PATCH'])) {
                if (api_setting_enabled($settings['maintenance_mode'] ?? '0')) {
                    $code = 503;
                    $result = ['error' => 'System under maintenance'];
                } elseif (api_setting_enabled($settings['disable_dns_write'] ?? '0')) {
                    $code = 403;
                    $result = ['error' => 'DNS modifications disabled'];
                } else {
                    try {
                        api_enforce_scope_rate_limit(CfRateLimiter::SCOPE_DNS, $keyRow, $settings, 'api_dns_update');
                    } catch (CfRateLimitExceededException $e) {
                        api_emit_scope_rate_limit_error($e);
                    }
                    $recordId = intval($data['record_id'] ?? 0);
                    if ($recordId <= 0) {
                        $code = 400;
                        $result = ['error' => 'record_id required'];
                    } else {
                        $rec = Capsule::table('mod_cloudflare_dns_records')->where('id', $recordId)->first();
                        if (!$rec) {
                            $rec = Capsule::table('mod_cloudflare_dns_records')->where('record_id', $recordId)->first();
                        }
                        if (!$rec) {
                            $code = 404;
                            $result = ['error' => 'record not found'];
                        } else {
                            $sid = intval($rec->subdomain_id);
                            $s = Capsule::table('mod_cloudflare_subdomain')
                                ->where('id', $sid)
                                ->where('userid', $keyRow->userid)
                                ->first();
                            if (!$s) {
                                $code = 403;
                                $result = ['error' => 'forbidden'];
                            } elseif (strtolower($s->status ?? '') === 'suspended') {
                                $code = 403;
                                $result = ['error' => 'subdomain suspended'];
                            } else {
                                $zone = $rec->zone_id ?: ($s->cloudflare_zone_id ?: $s->rootdomain);
                                $updateData = [];
                                $newContent = isset($data['content']) ? trim((string)$data['content']) : null;
                                if ($newContent !== null && $newContent !== '') {
                                    $updateData['content'] = $newContent;
                                }
                                if (isset($data['ttl'])) {
                                    $updateData['ttl'] = cfmod_normalize_ttl($data['ttl']);
                                }
                                if (isset($data['priority'])) {
                                    $updateData['priority'] = intval($data['priority']);
                                }
                                if (empty($updateData)) {
                                    $code = 400;
                                    $result = ['error' => 'no updates specified'];
                                } else {
                                    $providerContext = cfmod_acquire_provider_client_for_subdomain($s, $settings);
                                    if (!$providerContext || empty($providerContext['client'])) {
                                        $code = 500;
                                        $result = ['error' => 'provider unavailable'];
                                    } else {
                                        $cf = $providerContext['client'];
                                        try {
                                            $res = $cf->updateDnsRecord($zone, $rec->record_id, [
                                                'type' => $rec->type,
                                                'name' => $rec->name,
                                                'content' => $updateData['content'] ?? $rec->content,
                                                'ttl' => $updateData['ttl'] ?? intval($rec->ttl ?? 600),
                                                'priority' => $updateData['priority'] ?? $rec->priority,
                                            ]);
                                            if (!($res['success'] ?? false)) {
                                                $message = $res['errors'][0] ?? ($res['errors'] ?? 'update failed');
                                                if (is_array($message)) {
                                                    $message = json_encode($message, JSON_UNESCAPED_UNICODE);
                                                }
                                                throw new \RuntimeException((string)$message);
                                            }
                                            $updateColumns = [
                                                'updated_at' => date('Y-m-d H:i:s'),
                                            ];
                                            if (array_key_exists('content', $updateData)) {
                                                $updateColumns['content'] = $updateData['content'];
                                            }
                                            if (array_key_exists('ttl', $updateData)) {
                                                $updateColumns['ttl'] = $updateData['ttl'];
                                            }
                                            if (array_key_exists('priority', $updateData)) {
                                                $updateColumns['priority'] = $updateData['priority'];
                                            }
                                            Capsule::table('mod_cloudflare_dns_records')->where('id', $rec->id)->update($updateColumns);
                                            $result = ['success' => true, 'message' => 'DNS record updated successfully'];
                                        } catch (\RuntimeException $e) {
                                            $code = 400;
                                            $result = ['error' => cfmod_format_provider_error($e->getMessage(), '云解析服务暂时无法更新记录，请稍后再试。')];
                                        } catch (\Throwable $e) {
                                            $code = 500;
                                            $result = ['error' => 'update failed'];
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                $code = 404;
                $result = ['error' => 'unknown action'];
            }
        } elseif ($endpoint === 'keys' && $method === 'GET' && $action === 'list') {
            $keys = Capsule::table('mod_cloudflare_api_keys')
                ->where('userid', $keyRow->userid)
                ->orderBy('id', 'desc')
                ->get();
            $rows = [];
            foreach ($keys as $k) {
                $rows[] = [
                    'id' => $k->id,
                    'key_name' => $k->key_name,
                    'api_key' => $k->api_key,
                    'status' => $k->status,
                    'request_count' => intval($k->request_count),
                    'last_used_at' => $k->last_used_at,
                    'created_at' => $k->created_at
                ];
            }
            $result = ['success' => true, 'count' => count($rows), 'keys' => $rows];
        } elseif ($endpoint === 'keys' && in_array($method, ['POST', 'PUT']) && $action === 'create') {
            if (api_setting_enabled($settings['maintenance_mode'] ?? '0')) {
                $code = 503;
                $result = ['error' => 'System under maintenance'];
            } else {
                try {
                    api_enforce_scope_rate_limit(CfRateLimiter::SCOPE_API_KEY, $keyRow, $settings, 'api_keys_create');
                } catch (CfRateLimitExceededException $e) {
                    api_emit_scope_rate_limit_error($e);
                }
                $keyName = trim((string)($data['key_name'] ?? ''));

                if ($keyName === '') {
                    $code = 400;
                    $result = ['error' => 'key_name required'];
                } else {
                    try {
                        $existingCount = Capsule::table('mod_cloudflare_api_keys')
                            ->where('userid', $keyRow->userid)
                            ->count();
                        $maxKeys = intval($settings['api_keys_per_user'] ?? 3);
                        if ($existingCount >= $maxKeys) {
                            $code = 403;
                            $result = ['error' => 'key limit exceeded'];
                        } else {
                            $apiKey = 'cfsd_' . bin2hex(random_bytes(16));
                            $apiSecret = bin2hex(random_bytes(32));
                            $hashedSecret = password_hash($apiSecret, PASSWORD_DEFAULT);
                            $now = date('Y-m-d H:i:s');
                            Capsule::table('mod_cloudflare_api_keys')->insert([
                                'userid' => $keyRow->userid,
                                'key_name' => $keyName,
                                'api_key' => $apiKey,
                                'api_secret' => $hashedSecret,
                                'status' => 'active',
                                'rate_limit' => $rateLimit,
                                'request_count' => 0,
                                'created_at' => $now,
                                'updated_at' => $now
                            ]);
                            $result = [
                                'success' => true,
                                'message' => 'API key created successfully',
                                'api_key' => $apiKey,
                                'api_secret' => $apiSecret,
                                'rate_limit' => $rateLimit
                            ];
                        }
                    } catch (\Throwable $e) {
                        $code = 500;
                        $result = ['error' => 'create failed'];
                    }
                }
            }
        } elseif ($endpoint === 'keys' && in_array($method, ['POST', 'DELETE']) && $action === 'delete') {
            try {
                api_enforce_scope_rate_limit(CfRateLimiter::SCOPE_API_KEY, $keyRow, $settings, 'api_keys_delete');
            } catch (CfRateLimitExceededException $e) {
                api_emit_scope_rate_limit_error($e);
            }
            $targetId = intval($data['id'] ?? ($data['key_id'] ?? 0));
            if ($targetId <= 0) {
                $code = 400;
                $result = ['error' => 'key id required'];
            } else {
                try {
                    $keyRowDelete = Capsule::table('mod_cloudflare_api_keys')
                        ->where('id', $targetId)
                        ->where('userid', $keyRow->userid)
                        ->first();
                    if (!$keyRowDelete) {
                        $code = 404;
                        $result = ['error' => 'key not found'];
                    } else {
                        Capsule::table('mod_cloudflare_api_keys')->where('id', $targetId)->delete();
                        $result = ['success' => true, 'message' => 'API key deleted successfully'];
                    }
                } catch (\Throwable $e) {
                    $code = 500;
                    $result = ['error' => 'delete failed'];
                }
            }
        } elseif ($endpoint === 'keys' && in_array($method, ['POST', 'PUT']) && $action === 'regenerate') {
            try {
                api_enforce_scope_rate_limit(CfRateLimiter::SCOPE_API_KEY, $keyRow, $settings, 'api_keys_regenerate');
            } catch (CfRateLimitExceededException $e) {
                api_emit_scope_rate_limit_error($e);
            }
            $targetId = intval($data['id'] ?? ($data['key_id'] ?? 0));
            if ($targetId <= 0) {
                $code = 400;
                $result = ['error' => 'key id required'];
            } else {
                try {
                    $keyRowReg = Capsule::table('mod_cloudflare_api_keys')
                        ->where('id', $targetId)
                        ->where('userid', $keyRow->userid)
                        ->first();
                    if (!$keyRowReg) {
                        $code = 404;
                        $result = ['error' => 'key not found'];
                    } else {
                        $apiSecret = bin2hex(random_bytes(32));
                        $hashedSecret = password_hash($apiSecret, PASSWORD_DEFAULT);
                        Capsule::table('mod_cloudflare_api_keys')
                            ->where('id', $targetId)
                            ->update([
                                'api_secret' => $hashedSecret,
                                'updated_at' => date('Y-m-d H:i:s')
                            ]);
                        $result = ['success' => true, 'message' => 'API key regenerated successfully', 'api_secret' => $apiSecret];
                    }
                } catch (\Throwable $e) {
                    $code = 500;
                    $result = ['error' => 'regenerate failed'];
                }
            }
        } else {
            $code = 404;
            $result = ['error' => 'Unknown endpoint'];
        }

        cfmod_log_api_request($keyRow, (string)$endpoint, (string)$method, ($data ?: ($_REQUEST ?? [])), $result, $code, $t0);
        api_json($result, $code);
    } catch (\Throwable $e) {
        api_json(['error' => 'server error'], 500);
    }
}
