<?php

use WHMCS\Database\Capsule;

require_once __DIR__ . '/ProviderResolver.php';

if (!function_exists('cfmod_admin_deep_delete_subdomain')) {
    function cfmod_admin_deep_delete_subdomain($cf, $record, string $errorMessage = '当前子域绑定的 DNS 供应商不可用，请联系管理员'): int
    {
        if (!$record) {
            return 0;
        }

        $zoneId = $record->cloudflare_zone_id ?? '';
        if (!$zoneId && !empty($record->rootdomain)) {
            $zoneId = $record->rootdomain;
        }
        $subdomainName = strtolower(trim($record->subdomain ?? ''));
        $deletedCount = 0;

        if (!$cf) {
            $settings = function_exists('cf_get_module_settings_cached') ? cf_get_module_settings_cached() : [];
            $providerContext = cfmod_acquire_provider_client_for_subdomain($record, $settings);
            if ($providerContext && !empty($providerContext['client'])) {
                $cf = $providerContext['client'];
            } else {
                $cf = null;
            }
        }

        if ($cf && $zoneId && $subdomainName !== '') {
            try {
                $res = $cf->deleteDomainRecordsDeep($zoneId, $subdomainName);
                if ($res['success'] ?? false) {
                    $deletedCount = intval($res['deleted_count'] ?? 0);
                } else {
                    $fallback = $cf->deleteDomainRecords($zoneId, $subdomainName);
                    if ($fallback['success'] ?? false) {
                        $deletedCount = intval($fallback['deleted_count'] ?? 0);
                    } elseif (!empty($record->dns_record_id)) {
                        try {
                            $cf->deleteSubdomain($zoneId, $record->dns_record_id);
                            $deletedCount = max($deletedCount, 1);
                        } catch (\Throwable $inner) {
                        }
                    }
                }
            } catch (\Throwable $e) {
                if (!empty($record->dns_record_id) && $cf) {
                    try {
                        $cf->deleteSubdomain($zoneId, $record->dns_record_id);
                        $deletedCount = max($deletedCount, 1);
                    } catch (\Throwable $inner) {
                    }
                }
            }
        }

        try {
            Capsule::table('mod_cloudflare_dns_records')->where('subdomain_id', $record->id)->delete();
        } catch (\Throwable $e) {
        }

        return $deletedCount;
    }
}
