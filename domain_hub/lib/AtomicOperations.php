<?php

use WHMCS\Database\Capsule;

require_once __DIR__ . '/PrivilegedHelpers.php';
require_once __DIR__ . '/ProviderResolver.php';

if (!class_exists('CfAtomicException')) {
    class CfAtomicException extends \RuntimeException {}
}

if (!class_exists('CfAtomicQuotaExceededException')) {
    class CfAtomicQuotaExceededException extends CfAtomicException {}
}

if (!class_exists('CfAtomicAlreadyRegisteredException')) {
    class CfAtomicAlreadyRegisteredException extends CfAtomicException {}
}

if (!class_exists('CfAtomicRecordLimitException')) {
    class CfAtomicRecordLimitException extends CfAtomicException {}
}

if (!class_exists('CfAtomicInvalidPrefixLengthException')) {
    class CfAtomicInvalidPrefixLengthException extends CfAtomicException {}
}

if (!function_exists('cf_get_prefix_length_limits')) {
    function cf_get_prefix_length_limits(array $settings = null): array
    {
        if ($settings === null) {
            if (function_exists('cf_get_module_settings_cached')) {
                $settings = cf_get_module_settings_cached();
            } else {
                $settings = [];
            }
        }

        $defaultMin = 2;
        $defaultMax = 63;

        $minRaw = $settings['subdomain_prefix_min_length'] ?? null;
        $maxRaw = $settings['subdomain_prefix_max_length'] ?? null;

        $min = is_numeric($minRaw) ? (int) $minRaw : $defaultMin;
        $max = is_numeric($maxRaw) ? (int) $maxRaw : $defaultMax;

        $min = max(1, min(63, $min));
        $max = max(1, min(63, $max));

        if ($max < $min) {
            $max = $min;
        }

        return ['min' => $min, 'max' => $max];
    }
}

if (!function_exists('cf_atomic_register_subdomain')) {
    /**
     * Register a subdomain atomically while enforcing user quota limits.
     *
     * @param int    $userid
     * @param string $fullDomain Fully qualified subdomain (lowercase recommended)
     * @param string $rootdomain Root domain part
     * @param string $zoneId     Cloudflare/AliDNS zone identifier
     * @param array  $settings   Module settings array
     * @param array  $extraData  Additional columns to merge into the new row
     *
     * @return array{id:int,used_count:int,max_count:int}
     *
     * @throws CfAtomicQuotaExceededException
     * @throws CfAtomicAlreadyRegisteredException
     * @throws CfAtomicInvalidPrefixLengthException
     * @throws \Throwable
     */
    function cf_atomic_register_subdomain(int $userid, string $fullDomain, string $rootdomain, string $zoneId, array $settings, array $extraData = []): array
    {
        return CfSubdomainService::instance()->atomicRegisterSubdomain($userid, $fullDomain, $rootdomain, $zoneId, $settings, $extraData);
    }
}

if (!function_exists('cf_atomic_run_with_dns_limit')) {
    /**
     * Execute callback while enforcing DNS record limits atomically.
     *
     * @param int      $subdomainId   ID of the subdomain
     * @param int      $limitPerSub   Maximum DNS records allowed (0 = unlimited)
     * @param callable $callback      Callback executed inside the transaction
     *
     * @return mixed
     *
     * @throws CfAtomicRecordLimitException
     * @throws \Throwable
     */
    function cf_atomic_run_with_dns_limit(int $subdomainId, int $limitPerSub, callable $callback)
    {
        return Capsule::transaction(function () use ($subdomainId, $limitPerSub, $callback) {
            if ($limitPerSub > 0) {
                $currentCount = Capsule::table('mod_cloudflare_dns_records')
                    ->where('subdomain_id', $subdomainId)
                    ->where('type', '<>', 'NS')
                    ->lockForUpdate()
                    ->count();
                if ($currentCount >= $limitPerSub) {
                    throw new CfAtomicRecordLimitException('record_limit');
                }
            } else {
                Capsule::table('mod_cloudflare_subdomain')
                    ->where('id', $subdomainId)
                    ->lockForUpdate()
                    ->select('id')
                    ->first();
            }

            return $callback();
        });
    }
}
