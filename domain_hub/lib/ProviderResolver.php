<?php

use WHMCS\Database\Capsule;

require_once __DIR__ . '/SecurityHelpers.php';

if (!function_exists('cfmod_provider_table_exists')) {
    function cfmod_provider_table_exists(string $table): bool
    {
        static $cache = [];
        if (array_key_exists($table, $cache)) {
            return $cache[$table];
        }
        if (function_exists('cfmod_table_exists')) {
            $cache[$table] = cfmod_table_exists($table);
            return $cache[$table];
        }
        try {
            $cache[$table] = Capsule::schema()->hasTable($table);
        } catch (\Throwable $e) {
            $cache[$table] = false;
        }
        return $cache[$table];
    }
}

if (!function_exists('cfmod_provider_normalize_rootdomain')) {
    function cfmod_provider_normalize_rootdomain(?string $rootdomain): string
    {
        if (function_exists('cfmod_normalize_rootdomain')) {
            return cfmod_normalize_rootdomain((string) $rootdomain);
        }
        return strtolower(trim((string) $rootdomain));
    }
}

if (!function_exists('cfmod_get_default_provider_account_id')) {
    function cfmod_get_default_provider_account_id(?array $settings = null): ?int
    {
        if (is_array($settings) && !empty($settings['default_provider_account_id'])) {
            $candidate = (int) $settings['default_provider_account_id'];
            if ($candidate > 0) {
                return $candidate;
            }
        }

        if (function_exists('cf_get_module_settings_cached')) {
            $moduleSettings = cf_get_module_settings_cached();
            if (!empty($moduleSettings['default_provider_account_id'])) {
                $candidate = (int) $moduleSettings['default_provider_account_id'];
                if ($candidate > 0) {
                    return $candidate;
                }
            }
        } elseif (function_exists('api_load_settings')) {
            $moduleSettings = api_load_settings();
            if (!empty($moduleSettings['default_provider_account_id'])) {
                $candidate = (int) $moduleSettings['default_provider_account_id'];
                if ($candidate > 0) {
                    return $candidate;
                }
            }
        } else {
            try {
                $moduleSlug = defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
                $value = Capsule::table('tbladdonmodules')
                    ->where('module', $moduleSlug)
                    ->where('setting', 'default_provider_account_id')
                    ->value('value');
                if ($value !== null && $value !== '') {
                    $candidate = (int) $value;
                    if ($candidate > 0) {
                        return $candidate;
                    }
                }
            } catch (\Throwable $e) {
                // ignore storage errors
            }
        }

        if (function_exists('cfmod_get_default_provider_account')) {
            $account = cfmod_get_default_provider_account(false);
            if ($account && !empty($account['id'])) {
                return (int) $account['id'];
            }
        } else {
            $table = function_exists('cfmod_get_provider_table_name')
                ? cfmod_get_provider_table_name()
                : 'mod_cloudflare_provider_accounts';
            if (cfmod_provider_table_exists($table)) {
                try {
                    $row = Capsule::table($table)->where('is_default', 1)->orderBy('id', 'asc')->first();
                    if ($row && !empty($row->id)) {
                        return (int) $row->id;
                    }
                } catch (\Throwable $e) {
                    // ignore lookup errors
                }
            }
        }

        return null;
    }
}

if (!function_exists('cfmod_lookup_rootdomain_provider_id')) {
    function cfmod_lookup_rootdomain_provider_id(?string $rootdomain): ?int
    {
        $normalized = cfmod_provider_normalize_rootdomain($rootdomain);
        if ($normalized === '') {
            return null;
        }
        $table = 'mod_cloudflare_rootdomains';
        if (!cfmod_provider_table_exists($table)) {
            return null;
        }
        try {
            $value = Capsule::table($table)
                ->whereRaw('LOWER(domain) = ?', [$normalized])
                ->value('provider_account_id');
            $candidate = (int) $value;
            if ($candidate > 0) {
                return $candidate;
            }
        } catch (\Throwable $e) {
            // ignore lookup errors
        }
        return null;
    }
}

if (!function_exists('cfmod_lookup_subdomain_provider_id')) {
    function cfmod_lookup_subdomain_provider_id(?int $subdomainId): ?int
    {
        $sid = (int) $subdomainId;
        if ($sid <= 0) {
            return null;
        }
        $table = 'mod_cloudflare_subdomain';
        if (!cfmod_provider_table_exists($table)) {
            return null;
        }
        try {
            $value = Capsule::table($table)
                ->where('id', $sid)
                ->value('provider_account_id');
            $candidate = (int) $value;
            if ($candidate > 0) {
                return $candidate;
            }
        } catch (\Throwable $e) {
            // ignore lookup errors
        }
        return null;
    }
}

if (!function_exists('cfmod_filter_active_provider_id')) {
    function cfmod_filter_active_provider_id(?int $providerAccountId): ?int
    {
        $pid = (int) ($providerAccountId ?? 0);
        if ($pid <= 0) {
            return null;
        }
        $account = cfmod_get_provider_account($pid);
        if (!$account) {
            return null;
        }
        $status = strtolower($account['status'] ?? '');
        if ($status !== 'active') {
            return null;
        }
        return $pid;
    }
}

if (!function_exists('cfmod_update_subdomain_provider_reference_if_needed')) {
    function cfmod_update_subdomain_provider_reference_if_needed(int $subdomainId, int $providerAccountId, ?int $currentProviderId = null): void
    {
        if ($subdomainId <= 0 || $providerAccountId <= 0) {
            return;
        }
        if ($currentProviderId !== null && (int) $currentProviderId === $providerAccountId) {
            return;
        }
        try {
            Capsule::table('mod_cloudflare_subdomain')
                ->where('id', $subdomainId)
                ->update([
                    'provider_account_id' => $providerAccountId,
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
        } catch (\Throwable $e) {
        }
    }
}

if (!function_exists('cfmod_resolve_provider_account_id')) {
    function cfmod_resolve_provider_account_id(?int $providerAccountId = null, ?string $rootdomain = null, ?int $subdomainId = null, ?array $settings = null, bool $forceProvider = false): ?int
    {
        return CfProviderService::instance()->resolveProviderAccountId($providerAccountId, $rootdomain, $subdomainId, $settings, $forceProvider);
    }
}

if (!function_exists('cfmod_get_provider_table_name')) {
    function cfmod_get_provider_table_name(): string
    {
        return 'mod_cloudflare_provider_accounts';
    }
}

if (!function_exists('cfmod_ensure_provider_schema')) {
    function cfmod_ensure_provider_schema(): void
    {
        static $ensured = false;
        if ($ensured) {
            return;
        }
        $table = cfmod_get_provider_table_name();
        try {
            if (!Capsule::schema()->hasTable($table)) {
                Capsule::schema()->create($table, function ($table) {
                    $table->increments('id');
                    $table->string('name', 150);
                    $table->string('provider_type', 20)->default('alidns');
                    $table->string('access_key_id', 191)->nullable();
                    $table->text('access_key_secret')->nullable();
                    $table->string('status', 20)->default('active');
                    $table->boolean('is_default')->default(0);
                    $table->integer('rate_limit')->default(60);
                    $table->text('notes')->nullable();
                    $table->timestamps();
                    $table->unique('name', 'uniq_cf_provider_name');
                    $table->index('status');
                    $table->index('is_default');
                });
            }
            $ensured = true;
        } catch (\Throwable $e) {
            $ensured = false;
            throw $e;
        }
    }
}

if (!function_exists('cfmod_sync_default_provider_account')) {
    function cfmod_sync_default_provider_account(array $settings): ?int
    {
        $email = trim((string) ($settings['cloudflare_email'] ?? ''));
        $apiKey = trim((string) ($settings['cloudflare_api_key'] ?? ''));
        if ($email === '' && $apiKey === '') {
            return null;
        }
        try {
            cfmod_ensure_provider_schema();
        } catch (\Throwable $e) {
            return null;
        }
        $table = cfmod_get_provider_table_name();
        $now = date('Y-m-d H:i:s');
        try {
            $defaultRow = Capsule::table($table)->where('is_default', 1)->first();
            $rateLimit = max(1, intval($settings['api_rate_limit'] ?? 60));
            $payload = [
                'name' => 'Default Provider',
                'provider_type' => 'alidns',
                'access_key_id' => $email,
                'access_key_secret' => cfmod_encrypt_sensitive($apiKey),
                'status' => 'active',
                'is_default' => 1,
                'rate_limit' => $rateLimit,
                'notes' => null,
                'updated_at' => $now,
            ];
            if ($defaultRow) {
                $needsUpdate = false;
                $storedSecret = cfmod_decrypt_sensitive($defaultRow->access_key_secret ?? '');
                if (($defaultRow->access_key_id ?? '') !== $email) {
                    $needsUpdate = true;
                }
                if ($storedSecret !== $apiKey) {
                    $needsUpdate = true;
                }
                if (intval($defaultRow->rate_limit ?? 0) !== $rateLimit) {
                    $needsUpdate = true;
                }
                if ($needsUpdate) {
                    Capsule::table($table)->where('id', $defaultRow->id)->update($payload);
                } else {
                    Capsule::table($table)->where('id', $defaultRow->id)->update([
                        'status' => 'active',
                        'updated_at' => $now,
                    ]);
                }
                $defaultId = intval($defaultRow->id);
            } else {
                $payload['created_at'] = $now;
                $defaultId = Capsule::table($table)->insertGetId($payload);
            }
            Capsule::table('tbladdonmodules')->updateOrInsert([
                'module' => defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub',
                'setting' => 'default_provider_account_id'
            ], ['value' => $defaultId]);
            return $defaultId;
        } catch (\Throwable $e) {
            return null;
        }
    }
}

if (!function_exists('cfmod_cast_provider_account_row')) {
    function cfmod_cast_provider_account_row($row, bool $withSecret = false): array
    {
        if (!$row) {
            return [];
        }
        return [
            'id' => intval($row->id),
            'name' => $row->name,
            'provider_type' => $row->provider_type,
            'access_key_id' => $row->access_key_id,
            'access_key_secret' => $withSecret ? cfmod_decrypt_sensitive($row->access_key_secret ?? '') : ($row->access_key_secret ?? ''),
            'status' => $row->status,
            'is_default' => intval($row->is_default ?? 0),
            'rate_limit' => intval($row->rate_limit ?? 0),
            'notes' => $row->notes,
            'created_at' => $row->created_at,
            'updated_at' => $row->updated_at,
        ];
    }
}

if (!function_exists('cfmod_get_provider_account')) {
    function cfmod_get_provider_account(int $providerId, bool $withSecret = false): ?array
    {
        if ($providerId <= 0) {
            return null;
        }
        try {
            cfmod_ensure_provider_schema();
            $row = Capsule::table(cfmod_get_provider_table_name())->where('id', $providerId)->first();
            if (!$row) {
                return null;
            }
            return cfmod_cast_provider_account_row($row, $withSecret);
        } catch (\Throwable $e) {
            return null;
        }
    }
}

if (!function_exists('cfmod_get_default_provider_account')) {
    function cfmod_get_default_provider_account(bool $withSecret = false): ?array
    {
        try {
            cfmod_ensure_provider_schema();
            $table = cfmod_get_provider_table_name();
            $row = Capsule::table($table)->where('is_default', 1)->orderBy('id', 'asc')->first();
            if ($row) {
                return cfmod_cast_provider_account_row($row, $withSecret);
            }
            $fallback = Capsule::table($table)->orderBy('id', 'asc')->first();
            if ($fallback) {
                return cfmod_cast_provider_account_row($fallback, $withSecret);
            }
        } catch (\Throwable $e) {
            return null;
        }
        return null;
    }
}

if (!function_exists('cfmod_set_default_provider_account')) {
    function cfmod_set_default_provider_account(int $providerId): bool
    {
        if ($providerId <= 0) {
            return false;
        }
        try {
            cfmod_ensure_provider_schema();
            $table = cfmod_get_provider_table_name();
            $provider = Capsule::table($table)->where('id', $providerId)->first();
            if (!$provider) {
                return false;
            }
            Capsule::transaction(function () use ($table, $providerId) {
                $now = date('Y-m-d H:i:s');
                Capsule::table($table)->where('id', $providerId)->update([
                    'is_default' => 1,
                    'status' => 'active',
                    'updated_at' => $now,
                ]);
                Capsule::table($table)->where('id', '<>', $providerId)->update([
                    'is_default' => 0,
                    'updated_at' => $now,
                ]);
            });
            Capsule::table('tbladdonmodules')->updateOrInsert([
                'module' => defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub',
                'setting' => 'default_provider_account_id'
            ], ['value' => $providerId]);
            if (function_exists('cf_clear_settings_cache')) {
                cf_clear_settings_cache();
            }
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }
}

if (!function_exists('cfmod_get_active_provider_account')) {
    function cfmod_get_active_provider_account(?int $providerAccountId = null, bool $withSecret = false, bool $fallbackToDefault = true): ?array
    {
        try {
            cfmod_ensure_provider_schema();
        } catch (\Throwable $e) {
            return null;
        }
        $account = null;
        if ($providerAccountId !== null && $providerAccountId > 0) {
            $account = cfmod_get_provider_account($providerAccountId, $withSecret);
        }
        if (!$account && $fallbackToDefault) {
            $account = cfmod_get_default_provider_account($withSecret);
        }
        if (!$account) {
            return null;
        }
        $status = strtolower($account['status'] ?? '');
        if ($status !== 'active') {
            return null;
        }
        return $account;
    }
}

if (!function_exists('cfmod_make_provider_client')) {
    function cfmod_make_provider_client(?int $providerAccountId = null, ?string $rootdomain = null, ?int $subdomainId = null, ?array $settings = null, bool $forceProviderAccountId = false): ?array
    {
        $resolvedId = cfmod_resolve_provider_account_id($providerAccountId, $rootdomain, $subdomainId, $settings, $forceProviderAccountId);
        if (!$resolvedId) {
            return null;
        }
        $account = cfmod_get_active_provider_account($resolvedId, true, true);
        if (!$account) {
            return null;
        }
        $accessKeyId = trim((string)($account['access_key_id'] ?? ''));
        $accessKeySecret = trim((string)($account['access_key_secret'] ?? ''));
        if ($accessKeyId === '' || $accessKeySecret === '') {
            return null;
        }
        $providerType = strtolower($account['provider_type'] ?? 'alidns');
        try {
            switch ($providerType) {
                case 'dnspod_legacy':
                    if (!class_exists('DNSPodLegacyAPI') && file_exists(__DIR__ . '/DNSPodLegacyAPI.php')) {
                        require_once __DIR__ . '/DNSPodLegacyAPI.php';
                    }
                    $client = new DNSPodLegacyAPI($accessKeyId, $accessKeySecret);
                    break;
                case 'dnspod_intl':
                    if (!class_exists('DNSPodIntlAPI') && file_exists(__DIR__ . '/DNSPodIntlAPI.php')) {
                        require_once __DIR__ . '/DNSPodIntlAPI.php';
                    }
                    $client = new DNSPodIntlAPI($accessKeyId, $accessKeySecret);
                    break;
                case 'powerdns':
                    if (!class_exists('PowerDNSAPI') && file_exists(__DIR__ . '/PowerDNSAPI.php')) {
                        require_once __DIR__ . '/PowerDNSAPI.php';
                    }
                    // For PowerDNS: access_key_id = API URL, access_key_secret = API Key
                    // Optional: notes field can contain server_id (default: localhost)
                    $serverId = 'localhost';
                    if (!empty($account['notes'])) {
                        $noteLines = explode("\n", $account['notes']);
                        foreach ($noteLines as $line) {
                            $line = trim($line);
                            if (stripos($line, 'server_id=') === 0 || stripos($line, 'server_id:') === 0) {
                                $serverId = trim(substr($line, 10));
                                break;
                            }
                        }
                    }
                    $client = new PowerDNSAPI($accessKeyId, $accessKeySecret, $serverId);
                    break;
                case 'alidns':
                default:
                    if (!class_exists('CloudflareAPI') && file_exists(__DIR__ . '/CloudflareAPI.php')) {
                        require_once __DIR__ . '/CloudflareAPI.php';
                    }
                    $client = new CloudflareAPI($accessKeyId, $accessKeySecret);
                    break;
            }
        } catch (\Throwable $e) {
            return null;
        }
        return [
            'provider_account_id' => intval($account['id'] ?? $resolvedId),
            'account' => $account,
            'client' => $client,
        ];
    }
}

if (!function_exists('cfmod_reassign_subdomains_provider')) {
    function cfmod_reassign_subdomains_provider(string $rootdomain, ?int $providerAccountId): void
    {
        $rootdomain = strtolower(trim($rootdomain));
        if ($rootdomain === '') {
            return;
        }
        try {
            $now = date('Y-m-d H:i:s');
            Capsule::table('mod_cloudflare_subdomain')
                ->whereRaw('LOWER(rootdomain) = ?', [$rootdomain])
                ->update([
                    'provider_account_id' => $providerAccountId,
                    'updated_at' => $now,
                ]);
        } catch (\Throwable $e) {
        }
    }
}

if (!function_exists('cfmod_make_provider_client_for_subdomain')) {
    function cfmod_make_provider_client_for_subdomain($subdomainRow, ?array $settings = null, bool $forceProviderAccountId = false): ?array
    {
        if (is_array($subdomainRow)) {
            $providerId = $subdomainRow['provider_account_id'] ?? null;
            $rootdomain = $subdomainRow['rootdomain'] ?? null;
            $subId = $subdomainRow['id'] ?? null;
        } else {
            $providerId = $subdomainRow->provider_account_id ?? null;
            $rootdomain = $subdomainRow->rootdomain ?? null;
            $subId = $subdomainRow->id ?? null;
        }
        $resolvedProviderId = $providerId ? intval($providerId) : null;
        $resolvedSubId = $subId ? intval($subId) : null;
        return cfmod_make_provider_client($resolvedProviderId, $rootdomain, $resolvedSubId, $settings, $forceProviderAccountId);
    }
}

if (!function_exists('cfmod_make_provider_client_for_rootdomain')) {
    function cfmod_make_provider_client_for_rootdomain($rootdomainRow, ?array $settings = null, bool $forceProviderAccountId = false): ?array
    {
        if (is_array($rootdomainRow)) {
            $providerId = $rootdomainRow['provider_account_id'] ?? null;
            $rootdomain = $rootdomainRow['domain'] ?? null;
        } elseif (is_object($rootdomainRow)) {
            $providerId = $rootdomainRow->provider_account_id ?? null;
            $rootdomain = $rootdomainRow->domain ?? null;
        } else {
            $providerId = null;
            $rootdomain = $rootdomainRow;
        }
        $resolvedProviderId = $providerId ? intval($providerId) : null;
        return cfmod_make_provider_client($resolvedProviderId, $rootdomain, null, $settings, $forceProviderAccountId);
    }
}

if (!function_exists('cfmod_provider_resolve_settings')) {
    function cfmod_provider_resolve_settings(?array $settings = null): array
    {
        if (is_array($settings)) {
            return $settings;
        }
        if (function_exists('cf_get_module_settings_cached')) {
            return cf_get_module_settings_cached();
        }
        if (function_exists('api_load_settings')) {
            $loaded = api_load_settings();
            if (is_array($loaded)) {
                return $loaded;
            }
        }
        return [];
    }
}

if (!function_exists('cfmod_acquire_default_provider_client')) {
    function cfmod_acquire_default_provider_client(?array $settings = null): ?array
    {
        $settings = cfmod_provider_resolve_settings($settings);
        return cfmod_make_provider_client(null, null, null, $settings);
    }
}

if (!function_exists('cfmod_acquire_provider_client_for_rootdomain')) {
    function cfmod_acquire_provider_client_for_rootdomain($rootdomain, ?array $settings = null): ?array
    {
        return CfProviderService::instance()->acquireProviderClientForRootdomain($rootdomain, $settings);
    }
}

if (!function_exists('cfmod_acquire_provider_client_for_subdomain')) {
    function cfmod_acquire_provider_client_for_subdomain($subdomainRow, ?array $settings = null): ?array
    {
        return CfProviderService::instance()->acquireProviderClientForSubdomain($subdomainRow, $settings);
    }
}

if (!function_exists('cfmod_acquire_provider_client_for_subdomain_id')) {
    function cfmod_acquire_provider_client_for_subdomain_id(int $subdomainId, ?array $settings = null): ?array
    {
        if ($subdomainId <= 0) {
            return null;
        }
        try {
            $row = Capsule::table('mod_cloudflare_subdomain')->where('id', $subdomainId)->first();
        } catch (\Throwable $e) {
            return null;
        }
        if (!$row) {
            return null;
        }
        return cfmod_acquire_provider_client_for_subdomain($row, $settings);
    }
}
