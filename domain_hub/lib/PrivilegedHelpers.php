<?php

use WHMCS\Database\Capsule;

if (!defined('CF_PRIVILEGED_MAX_SUBDOMAIN')) {
    define('CF_PRIVILEGED_MAX_SUBDOMAIN', 99999999999);
}

if (!function_exists('cf_get_privileged_limit')) {
    function cf_get_privileged_limit(): int
    {
        return CF_PRIVILEGED_MAX_SUBDOMAIN;
    }
}

if (!function_exists('cf_clear_privileged_cache')) {
    function cf_clear_privileged_cache(): void
    {
        unset($GLOBALS['cf_privileged_user_cache']);
    }
}

if (!function_exists('cf_is_user_privileged')) {
    function cf_is_user_privileged(int $userid): bool
    {
        if ($userid <= 0) {
            return false;
        }
        if (!isset($GLOBALS['cf_privileged_user_cache']) || !is_array($GLOBALS['cf_privileged_user_cache'])) {
            $GLOBALS['cf_privileged_user_cache'] = [];
        }
        if (array_key_exists($userid, $GLOBALS['cf_privileged_user_cache'])) {
            return $GLOBALS['cf_privileged_user_cache'][$userid];
        }
        static $privilegedTableAvailable = null;
        if ($privilegedTableAvailable === false) {
            $GLOBALS['cf_privileged_user_cache'][$userid] = false;
            return false;
        }
        if ($privilegedTableAvailable === null) {
            try {
                $privilegedTableAvailable = Capsule::schema()->hasTable('mod_cloudflare_special_users');
            } catch (\Throwable $e) {
                $privilegedTableAvailable = false;
            }
        }
        if (!$privilegedTableAvailable) {
            $GLOBALS['cf_privileged_user_cache'][$userid] = false;
            return false;
        }
        try {
            $exists = Capsule::table('mod_cloudflare_special_users')
                ->where('userid', $userid)
                ->exists();
        } catch (\Throwable $e) {
            $exists = false;
        }
        $GLOBALS['cf_privileged_user_cache'][$userid] = $exists;
        return $exists;
    }
}

if (!function_exists('cf_ensure_privileged_quota')) {
    function cf_ensure_privileged_quota(int $userid, $existingQuota = null, ?int $inviteLimit = null)
    {
        $limit = cf_get_privileged_limit();
        $now = date('Y-m-d H:i:s');
        $inviteLimit = $inviteLimit === null ? 5 : max(0, $inviteLimit);
        try {
            if ($existingQuota === null) {
                $existingQuota = Capsule::table('mod_cloudflare_subdomain_quotas')
                    ->where('userid', $userid)
                    ->first();
            }
            if ($existingQuota) {
                $updates = [];
                if (intval($existingQuota->max_count ?? 0) !== $limit) {
                    $updates['max_count'] = $limit;
                    $existingQuota->max_count = $limit;
                }
                if ($inviteLimit !== null && intval($existingQuota->invite_bonus_limit ?? 0) < $inviteLimit) {
                    $updates['invite_bonus_limit'] = $inviteLimit;
                    $existingQuota->invite_bonus_limit = $inviteLimit;
                }
                if (!empty($updates)) {
                    $updates['updated_at'] = $now;
                    Capsule::table('mod_cloudflare_subdomain_quotas')
                        ->where('userid', $userid)
                        ->update($updates);
                }
                return $existingQuota;
            }
            Capsule::table('mod_cloudflare_subdomain_quotas')->insert([
                'userid' => $userid,
                'used_count' => 0,
                'max_count' => $limit,
                'invite_bonus_count' => 0,
                'invite_bonus_limit' => $inviteLimit,
                'created_at' => $now,
                'updated_at' => $now
            ]);
            return Capsule::table('mod_cloudflare_subdomain_quotas')
                ->where('userid', $userid)
                ->first();
        } catch (\Throwable $e) {
            return $existingQuota;
        }
    }
}

if (!function_exists('cf_reset_user_quota_to_base')) {
    function cf_reset_user_quota_to_base(int $userid, int $baseMax, ?int $inviteLimit = null)
    {
        $now = date('Y-m-d H:i:s');
        $inviteLimit = $inviteLimit === null ? 5 : max(0, $inviteLimit);
        try {
            $quota = Capsule::table('mod_cloudflare_subdomain_quotas')
                ->where('userid', $userid)
                ->first();
            $targetMax = $baseMax > 0
                ? max($baseMax, intval($quota->used_count ?? 0))
                : 0;
            if ($quota) {
                $updates = ['max_count' => $targetMax, 'updated_at' => $now];
                if (intval($quota->invite_bonus_limit ?? 0) < $inviteLimit) {
                    $updates['invite_bonus_limit'] = $inviteLimit;
                    $quota->invite_bonus_limit = $inviteLimit;
                }
                Capsule::table('mod_cloudflare_subdomain_quotas')
                    ->where('userid', $userid)
                    ->update($updates);
                $quota->max_count = $targetMax;
                return $quota;
            }
            Capsule::table('mod_cloudflare_subdomain_quotas')->insert([
                'userid' => $userid,
                'used_count' => 0,
                'max_count' => $targetMax,
                'invite_bonus_count' => 0,
                'invite_bonus_limit' => $inviteLimit,
                'created_at' => $now,
                'updated_at' => $now
            ]);
            return Capsule::table('mod_cloudflare_subdomain_quotas')
                ->where('userid', $userid)
                ->first();
        } catch (\Throwable $e) {
            return null;
        }
    }
}


if (!function_exists('cf_mark_user_domains_never_expires')) {
    function cf_mark_user_domains_never_expires(int $userid): void
    {
        if ($userid <= 0) {
            return;
        }
        try {
            $now = date('Y-m-d H:i:s');
            Capsule::table('mod_cloudflare_subdomain')
                ->where('userid', $userid)
                ->update([
                    'never_expires' => 1,
                    'expires_at' => null,
                    'auto_deleted_at' => null,
                    'updated_at' => $now
                ]);
        } catch (\Throwable $e) {
            // 忽略标记失败
        }
    }
}
