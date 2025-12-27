<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

require_once __DIR__ . '/../PrivilegedHelpers.php';

class CfQuotaSupport
{
    public static function syncBaseQuotaIfNeeded(int $userid, int $baseMax, $existingQuota = null)
    {
        if ($userid <= 0) {
            return $existingQuota;
        }

        $isPrivileged = function_exists('cf_is_user_privileged') && cf_is_user_privileged($userid);
        if ($isPrivileged) {
            return cf_ensure_privileged_quota($userid, $existingQuota, null);
        }

        try {
            if ($existingQuota === null) {
                $existingQuota = Capsule::table('mod_cloudflare_subdomain_quotas')
                    ->where('userid', $userid)
                    ->first();
            }
            if (!$existingQuota || $baseMax <= 0) {
                return $existingQuota;
            }
            $currentMax = intval($existingQuota->max_count ?? 0);
            $bonusCount = max(0, intval($existingQuota->invite_bonus_count ?? 0));
            $currentBase = max(0, $currentMax - $bonusCount);
            if ($currentBase < $baseMax) {
                $newMax = $baseMax + $bonusCount;
                Capsule::table('mod_cloudflare_subdomain_quotas')
                    ->where('userid', $userid)
                    ->update([
                        'max_count' => $newMax,
                        'updated_at' => date('Y-m-d H:i:s')
                    ]);
                $existingQuota->max_count = $newMax;
            }
        } catch (\Throwable $e) {
            // ignore sync exceptions
        }

        return $existingQuota;
    }

    public static function syncInviteLimitIfNeeded(int $userid, int $globalLimit, $existingQuota = null)
    {
        if ($userid <= 0 || $globalLimit <= 0) {
            return $existingQuota;
        }

        $isPrivileged = function_exists('cf_is_user_privileged') && cf_is_user_privileged($userid);
        if ($isPrivileged) {
            return cf_ensure_privileged_quota($userid, $existingQuota, $globalLimit);
        }

        try {
            if ($existingQuota === null) {
                $existingQuota = Capsule::table('mod_cloudflare_subdomain_quotas')
                    ->where('userid', $userid)
                    ->first();
            }
            if ($existingQuota) {
                $currentLimit = intval($existingQuota->invite_bonus_limit ?? 0);
                if ($currentLimit < $globalLimit) {
                    Capsule::table('mod_cloudflare_subdomain_quotas')
                        ->where('userid', $userid)
                        ->update([
                            'invite_bonus_limit' => $globalLimit,
                            'updated_at' => date('Y-m-d H:i:s')
                        ]);
                    $existingQuota->invite_bonus_limit = $globalLimit;
                }
            }
        } catch (\Throwable $e) {
            // ignore sync exceptions
        }

        return $existingQuota;
    }
}

if (!function_exists('cf_sync_user_base_quota_if_needed')) {
    function cf_sync_user_base_quota_if_needed(int $userid, int $baseMax, $existingQuota = null)
    {
        return CfQuotaSupport::syncBaseQuotaIfNeeded($userid, $baseMax, $existingQuota);
    }
}

if (!function_exists('cf_sync_user_invite_limit_if_needed')) {
    function cf_sync_user_invite_limit_if_needed(int $userid, int $globalLimit, $existingQuota = null)
    {
        return CfQuotaSupport::syncInviteLimitIfNeeded($userid, $globalLimit, $existingQuota);
    }
}
