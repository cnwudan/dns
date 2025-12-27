<?php
// phpcs:ignoreFile

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfRateLimitExceededException extends RuntimeException
{
    private int $retryAfterSeconds;
    private string $scope;
    private array $context;

    public function __construct(string $scope, int $retryAfterSeconds, array $context = [])
    {
        parent::__construct('Rate limit exceeded');
        $this->scope = $scope;
        $this->retryAfterSeconds = max(1, $retryAfterSeconds);
        $this->context = $context;
    }

    public function getRetryAfterSeconds(): int
    {
        return $this->retryAfterSeconds;
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function getContext(): array
    {
        return $this->context;
    }
}

class CfRateLimiter
{
    private const TABLE = 'mod_cloudflare_rate_limits';
    private const WINDOW_SECONDS = 3600;

    public const SCOPE_REGISTER = 'client_register';
    public const SCOPE_DNS = 'dns_write';
    public const SCOPE_API_KEY = 'api_key_ops';
    public const SCOPE_QUOTA_GIFT = 'quota_gift_ops';
    public const SCOPE_AJAX_SENSITIVE = 'ajax_sensitive';
    public const SCOPE_DNS_UNLOCK = 'dns_unlock';

    private const SETTING_KEYS = [
        self::SCOPE_REGISTER => 'rate_limit_register_per_hour',
        self::SCOPE_DNS => 'rate_limit_dns_per_hour',
        self::SCOPE_API_KEY => 'rate_limit_api_key_per_hour',
        self::SCOPE_QUOTA_GIFT => 'rate_limit_quota_gift_per_hour',
        self::SCOPE_AJAX_SENSITIVE => 'rate_limit_ajax_per_hour',
        self::SCOPE_DNS_UNLOCK => 'rate_limit_dns_unlock_per_hour',
    ];

    private const DEFAULT_LIMITS = [
        self::SCOPE_REGISTER => 30,
        self::SCOPE_DNS => 120,
        self::SCOPE_API_KEY => 20,
        self::SCOPE_QUOTA_GIFT => 20,
        self::SCOPE_AJAX_SENSITIVE => 60,
        self::SCOPE_DNS_UNLOCK => 10,
    ];

    private static ?bool $tableReady = null;
    private static int $lastCleanupTs = 0;

    public static function resolveLimit(string $scope, array $settings): int
    {
        $key = self::SETTING_KEYS[$scope] ?? null;
        if ($key === null) {
            return self::DEFAULT_LIMITS[$scope] ?? 0;
        }
        $value = $settings[$key] ?? null;
        if ($value === null || $value === '') {
            return self::DEFAULT_LIMITS[$scope] ?? 0;
        }
        return max(0, (int) $value);
    }

    public static function enforce(string $scope, int $limit, array $context): void
    {
        if ($limit <= 0) {
            return;
        }
        if (!self::isTableReady()) {
            return;
        }

        $buckets = self::buildBuckets($context);
        $now = time();
        $windowSeconds = self::WINDOW_SECONDS;

        foreach ($buckets as $bucket) {
            $result = self::incrementBucket($scope, $bucket, $windowSeconds);
            if ($result === null) {
                continue;
            }
            if (($result['hits'] ?? 0) > $limit) {
                $retryAfter = max(1, ($result['reset_at'] ?? ($now + $windowSeconds)) - $now);
                throw new CfRateLimitExceededException($scope, $retryAfter, [
                    'bucket' => $bucket,
                    'limit' => $limit,
                ]);
            }
        }
    }

    public static function formatRetryMinutes(int $retryAfterSeconds): int
    {
        return max(1, (int) ceil($retryAfterSeconds / 60));
    }

    private static function buildBuckets(array $context): array
    {
        $buckets = [];
        $userId = isset($context['userid']) ? (int) $context['userid'] : 0;
        $identifier = trim((string) ($context['identifier'] ?? 'generic'));
        $ip = trim((string) ($context['ip'] ?? ''));

        if ($userId > 0) {
            $buckets[] = 'user:' . $userId;
        }
        if ($ip !== '') {
            $buckets[] = 'ip:' . substr(sha1($ip), 0, 16);
        }
        if (empty($buckets)) {
            $buckets[] = 'anon:' . substr(sha1($identifier . microtime(true)), 0, 16);
        }
        return $buckets;
    }

    private static function incrementBucket(string $scope, string $bucket, int $windowSeconds): ?array
    {
        $now = time();
        $windowStart = $now - ($now % $windowSeconds);
        $windowEnd = $windowStart + $windowSeconds;
        $nowStr = date('Y-m-d H:i:s', $now);
        $expiresAt = date('Y-m-d H:i:s', $windowEnd);

        try {
            Capsule::statement(
                'INSERT INTO `' . self::TABLE . '` (`scope`, `bucket`, `hits`, `expires_at`, `created_at`, `updated_at`)
                 VALUES (?, ?, 1, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE `hits` = `hits` + 1, `expires_at` = VALUES(`expires_at`), `updated_at` = VALUES(`updated_at`)',
                [$scope, $bucket, $expiresAt, $nowStr, $nowStr]
            );

            $hits = (int) Capsule::table(self::TABLE)
                ->where('scope', $scope)
                ->where('bucket', $bucket)
                ->value('hits');

            self::maybeCleanup($now);

            return [
                'hits' => $hits,
                'reset_at' => $windowEnd,
            ];
        } catch (\Throwable $e) {
            error_log('[domain_hub][CfRateLimiter] ' . $e->getMessage());
            self::$tableReady = false;
            return null;
        }
    }

    private static function isTableReady(): bool
    {
        if (self::$tableReady !== null) {
            return self::$tableReady;
        }
        try {
            self::$tableReady = Capsule::schema()->hasTable(self::TABLE);
        } catch (\Throwable $e) {
            self::$tableReady = false;
        }
        return self::$tableReady;
    }

    private static function maybeCleanup(int $now): void
    {
        if (($now - self::$lastCleanupTs) < 60) {
            return;
        }
        self::$lastCleanupTs = $now;
        try {
            Capsule::table(self::TABLE)
                ->where('expires_at', '<', date('Y-m-d H:i:s', $now - 60))
                ->limit(500)
                ->delete();
        } catch (\Throwable $e) {
            // ignore cleanup errors
        }
    }
}
