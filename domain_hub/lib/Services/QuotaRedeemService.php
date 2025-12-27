<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfQuotaRedeemException extends \RuntimeException
{
    private string $reason;
    private array $payload;

    public function __construct(string $reason, string $message = '', array $payload = [], ?\Throwable $previous = null)
    {
        $this->reason = $reason;
        $this->payload = $payload;
        parent::__construct($message !== '' ? $message : $reason, 0, $previous);
    }

    public function getReason(): string
    {
        return $this->reason;
    }

    public function getPayload(): array
    {
        return $this->payload;
    }
}

class CfQuotaRedeemService
{
    private const CLIENT_HISTORY_PER_PAGE = 5;

    private static ?self $instance = null;

    private CfQuotaRepository $quotaRepository;

    private function __construct()
    {
        $this->quotaRepository = CfQuotaRepository::instance();
    }

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Redeem a quota code for the specified user.
     */
    public function redeemCode(int $userid, string $codeInput, string $clientIp = '', ?array $moduleSettings = null): array
    {
        if ($userid <= 0) {
            throw new CfQuotaRedeemException('invalid_user');
        }

        $code = strtoupper(trim($codeInput));
        if ($code === '') {
            throw new CfQuotaRedeemException('empty_code');
        }

        self::ensureTables();
        $moduleSettings = $this->resolveModuleSettings($moduleSettings);

        $now = time();
        $nowStr = date('Y-m-d H:i:s', $now);

        $result = Capsule::connection()->transaction(function () use ($code, $userid, $clientIp, $now, $nowStr, $moduleSettings) {
            $codeRow = Capsule::table('mod_cloudflare_quota_codes')
                ->where('code', $code)
                ->lockForUpdate()
                ->first();

            if (!$codeRow) {
                throw new CfQuotaRedeemException('code_not_found');
            }

            $status = strtolower((string) ($codeRow->status ?? 'active'));
            if ($status !== 'active') {
                throw new CfQuotaRedeemException('code_inactive');
            }

            $validFrom = $codeRow->valid_from ? strtotime((string) $codeRow->valid_from) : null;
            if ($validFrom !== null && $now < $validFrom) {
                throw new CfQuotaRedeemException('code_not_started');
            }

            $validTo = $codeRow->valid_to ? strtotime((string) $codeRow->valid_to) : null;
            if ($validTo !== null && $now > $validTo) {
                Capsule::table('mod_cloudflare_quota_codes')
                    ->where('id', $codeRow->id)
                    ->update([
                        'status' => 'expired',
                        'updated_at' => $nowStr,
                    ]);
                throw new CfQuotaRedeemException('code_expired');
            }

            $grantAmount = max(1, (int) ($codeRow->grant_amount ?? 0));
            if ($grantAmount <= 0) {
                throw new CfQuotaRedeemException('grant_invalid');
            }

            $maxTotalUses = max(0, (int) ($codeRow->max_total_uses ?? 0));
            $redeemedTotal = max(0, (int) ($codeRow->redeemed_total ?? 0));
            if ($maxTotalUses > 0 && $redeemedTotal >= $maxTotalUses) {
                Capsule::table('mod_cloudflare_quota_codes')
                    ->where('id', $codeRow->id)
                    ->update([
                        'status' => 'exhausted',
                        'updated_at' => $nowStr,
                    ]);
                throw new CfQuotaRedeemException('code_exhausted');
            }

            $perUserLimit = max(1, (int) ($codeRow->per_user_limit ?? 1));
            $userRedeemCount = Capsule::table('mod_cloudflare_quota_redemptions')
                ->where('code_id', $codeRow->id)
                ->where('userid', $userid)
                ->where('status', 'success')
                ->count();
            if ($userRedeemCount >= $perUserLimit) {
                throw new CfQuotaRedeemException('per_user_limit');
            }

            $quota = $this->quotaRepository->getQuotaForUpdate($userid);
            if (!$quota) {
                [$defaultMax, $defaultInviteLimit] = $this->resolveDefaultQuota($moduleSettings);
                $this->quotaRepository->createQuota($userid, $defaultMax, $defaultInviteLimit, $nowStr);
                $quota = $this->quotaRepository->getQuotaForUpdate($userid);
            }
            if (!$quota) {
                throw new CfQuotaRedeemException('quota_unavailable');
            }

            $beforeQuota = (int) ($quota->max_count ?? 0);
            $afterQuota = $beforeQuota + $grantAmount;

            $this->quotaRepository->updateQuota($userid, [
                'max_count' => $afterQuota,
                'updated_at' => $nowStr,
            ]);

            Capsule::table('mod_cloudflare_quota_redemptions')->insert([
                'code_id' => $codeRow->id,
                'code' => $codeRow->code,
                'userid' => $userid,
                'grant_amount' => $grantAmount,
                'status' => 'success',
                'message' => null,
                'before_quota' => $beforeQuota,
                'after_quota' => $afterQuota,
                'client_ip' => $clientIp !== '' ? $clientIp : null,
                'created_at' => $nowStr,
                'updated_at' => $nowStr,
            ]);

            $newTotal = $redeemedTotal + 1;
            $newStatus = ($maxTotalUses > 0 && $newTotal >= $maxTotalUses) ? 'exhausted' : $status;
            Capsule::table('mod_cloudflare_quota_codes')
                ->where('id', $codeRow->id)
                ->update([
                    'redeemed_total' => $newTotal,
                    'status' => $newStatus,
                    'updated_at' => $nowStr,
                ]);

            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('client_quota_redeem', [
                    'code' => $codeRow->code,
                    'grant_amount' => $grantAmount,
                    'after_quota' => $afterQuota,
                ], $userid, null);
            }

            return [
                'code' => $codeRow->code,
                'grant' => $grantAmount,
                'after' => $afterQuota,
            ];
        });

        return $result;
    }

    public function getUserHistory(int $userid, int $page = 1, int $perPage = self::CLIENT_HISTORY_PER_PAGE): array
    {
        self::ensureTables();
        $page = max(1, $page);
        $perPage = max(1, $perPage);

        $query = Capsule::table('mod_cloudflare_quota_redemptions')
            ->where('userid', $userid)
            ->orderBy('id', 'desc');

        $total = $query->count();
        $totalPages = max(1, (int) ceil($total / $perPage));
        if ($page > $totalPages) {
            $page = $totalPages;
        }
        $rows = $query
            ->offset(($page - 1) * $perPage)
            ->limit($perPage)
            ->get();

        $items = [];
        foreach ($rows as $row) {
            $items[] = [
                'id' => (int) $row->id,
                'code' => (string) $row->code,
                'grant_amount' => (int) $row->grant_amount,
                'status' => (string) $row->status,
                'message' => $row->message ? (string) $row->message : '',
                'created_at' => $row->created_at ? date('Y-m-d H:i', strtotime($row->created_at)) : '',
            ];
        }

        return [
            'items' => $items,
            'page' => $page,
            'perPage' => $perPage,
            'total' => $total,
            'totalPages' => $totalPages,
        ];
    }

    public static function ensureTables(): void
    {
        try {
            if (!Capsule::schema()->hasTable('mod_cloudflare_quota_codes')) {
                Capsule::schema()->create('mod_cloudflare_quota_codes', function ($table) {
                    $table->increments('id');
                    $table->string('code', 191)->unique();
                    $table->integer('grant_amount')->unsigned()->default(1);
                    $table->string('mode', 20)->default('single_use');
                    $table->integer('max_total_uses')->unsigned()->default(1);
                    $table->integer('per_user_limit')->unsigned()->default(1);
                    $table->integer('redeemed_total')->unsigned()->default(0);
                    $table->dateTime('valid_from')->nullable();
                    $table->dateTime('valid_to')->nullable();
                    $table->string('status', 20)->default('active');
                    $table->string('batch_tag', 64)->nullable();
                    $table->integer('created_by_admin_id')->unsigned()->nullable();
                    $table->text('notes')->nullable();
                    $table->timestamps();
                    $table->index('status');
                    $table->index('valid_to');
                    $table->index('batch_tag');
                });
            }

            if (!Capsule::schema()->hasTable('mod_cloudflare_quota_redemptions')) {
                Capsule::schema()->create('mod_cloudflare_quota_redemptions', function ($table) {
                    $table->increments('id');
                    $table->integer('code_id')->unsigned();
                    $table->string('code', 191);
                    $table->integer('userid')->unsigned();
                    $table->integer('grant_amount')->unsigned()->default(1);
                    $table->string('status', 20)->default('success');
                    $table->text('message')->nullable();
                    $table->bigInteger('before_quota')->default(0);
                    $table->bigInteger('after_quota')->default(0);
                    $table->string('client_ip', 45)->nullable();
                    $table->timestamps();
                    $table->index('code_id');
                    $table->index('userid');
                    $table->index('code');
                    $table->index('status');
                    $table->index('created_at');
                });
            }
        } catch (\Throwable $e) {
            // ignore schema errors to avoid blocking runtime
        }
    }

    public static function randomCode(int $length = 12): string
    {
        if (function_exists('cfmod_generate_quota_redeem_code')) {
            return cfmod_generate_quota_redeem_code($length);
        }

        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $result = '';
        for ($i = 0; $i < $length; $i++) {
            $result .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        return $result;
    }

    private function resolveModuleSettings(?array $settings = null): array
    {
        if (is_array($settings) && !empty($settings)) {
            return $settings;
        }
        if (function_exists('cf_get_module_settings_cached')) {
            $cached = cf_get_module_settings_cached();
            if (is_array($cached)) {
                return $cached;
            }
        }
        try {
            $rows = Capsule::table('tbladdonmodules')->where('module', 'domain_hub')->get();
            $resolved = [];
            foreach ($rows as $row) {
                $resolved[$row->setting] = $row->value;
            }
            return $resolved;
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function resolveDefaultQuota(array $moduleSettings): array
    {
        $max = (int) ($moduleSettings['max_subdomain_per_user'] ?? 5);
        if ($max <= 0) {
            $max = 5;
        }
        $inviteLimit = (int) ($moduleSettings['invite_bonus_limit_global'] ?? 5);
        if ($inviteLimit <= 0) {
            $inviteLimit = 5;
        }
        return [$max, $inviteLimit];
    }
}
