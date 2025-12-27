<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfQuotaRepository
{
    private static ?self $instance = null;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public function getQuotaForUpdate(int $userid)
    {
        return Capsule::table('mod_cloudflare_subdomain_quotas')
            ->where('userid', $userid)
            ->lockForUpdate()
            ->first();
    }

    public function createQuota(int $userid, int $maxCount, int $inviteLimit, string $now): void
    {
        Capsule::table('mod_cloudflare_subdomain_quotas')->insert([
            'userid' => $userid,
            'used_count' => 0,
            'max_count' => $maxCount,
            'invite_bonus_count' => 0,
            'invite_bonus_limit' => $inviteLimit,
            'created_at' => $now,
            'updated_at' => $now
        ]);
    }

    public function updateQuota(int $userid, array $data): void
    {
        Capsule::table('mod_cloudflare_subdomain_quotas')
            ->where('userid', $userid)
            ->update($data);
    }
}
