<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfSubdomainService
{
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

    public function atomicRegisterSubdomain(int $userid, string $fullDomain, string $rootdomain, string $zoneId, array $settings, array $extraData = []): array
    {
        $baseMax = max(0, intval($settings['max_subdomain_per_user'] ?? 0));
        $inviteLimit = intval($settings['invite_bonus_limit_global'] ?? 5);
        if ($inviteLimit <= 0) {
            $inviteLimit = 5;
        }
        $isPrivileged = function_exists('cf_is_user_privileged') && cf_is_user_privileged($userid);
        $privilegedLimit = cf_get_privileged_limit();
        if ($isPrivileged) {
            $baseMax = $privilegedLimit;
        }
        $now = date('Y-m-d H:i:s');
        $fullLower = strtolower($fullDomain);
        $rootLower = strtolower($rootdomain);

        $resolvedProviderAccountId = $extraData['provider_account_id'] ?? null;
        if (!is_numeric($resolvedProviderAccountId) || (int) $resolvedProviderAccountId <= 0) {
            $resolvedProviderAccountId = cfmod_resolve_provider_account_id(null, $rootLower, null, $settings);
        }
        if (is_numeric($resolvedProviderAccountId) && (int) $resolvedProviderAccountId > 0) {
            $extraData['provider_account_id'] = (int) $resolvedProviderAccountId;
        } else {
            unset($extraData['provider_account_id']);
        }

        $lengthLimits = cf_get_prefix_length_limits($settings);
        $prefixMin = $lengthLimits['min'];
        $prefixMax = $lengthLimits['max'];

        $termYearsRaw = $settings['domain_registration_term_years'] ?? 1;
        $termYears = is_numeric($termYearsRaw) ? (int) $termYearsRaw : 1;
        if ($termYears < 0) {
            $termYears = 0;
        }
        $termYears = $this->applyRootdomainTermOverride($rootLower, $termYears);
        if ($isPrivileged) {
            $termYears = 0;
        }
        $neverExpiresFlag = 0;
        $expiresAt = null;
        if ($termYears > 0) {
            $baseTs = strtotime($now) ?: time();
            $expiryTs = strtotime('+' . $termYears . ' years', $baseTs);
            if ($expiryTs === false) {
                $expiryTs = $baseTs;
            }
            $expiresAt = date('Y-m-d H:i:s', $expiryTs);
        } else {
            $neverExpiresFlag = 1;
        }

        $labelPart = $fullLower;
        if ($rootLower !== '' && substr($fullLower, - (strlen($rootLower) + 1)) === '.' . $rootLower) {
            $labelPart = substr($fullLower, 0, - (strlen($rootLower) + 1));
        }
        if (strpos($labelPart, '.') !== false) {
            $labelParts = explode('.', $labelPart, 2);
            $labelPart = $labelParts[0] ?? $labelPart;
        }
        $labelLength = strlen($labelPart);

        if ($labelLength < $prefixMin || $labelLength > $prefixMax) {
            throw new CfAtomicInvalidPrefixLengthException('prefix_length_invalid');
        }

        try {
            return Capsule::transaction(function () use ($userid, $fullLower, $rootLower, $zoneId, $baseMax, $inviteLimit, $extraData, $now, $expiresAt, $neverExpiresFlag, $isPrivileged, $privilegedLimit) {
                $quota = $this->quotaRepository->getQuotaForUpdate($userid);

                if (!$quota) {
                    $this->quotaRepository->createQuota($userid, $isPrivileged ? $privilegedLimit : $baseMax, $inviteLimit, $now);
                    $quota = $this->quotaRepository->getQuotaForUpdate($userid);
                }

                if ($isPrivileged) {
                    $updates = [];
                    if (intval($quota->max_count ?? 0) !== $privilegedLimit) {
                        $updates['max_count'] = $privilegedLimit;
                        $quota->max_count = $privilegedLimit;
                    }
                    if (intval($quota->invite_bonus_limit ?? 0) < $inviteLimit) {
                        $updates['invite_bonus_limit'] = $inviteLimit;
                        $quota->invite_bonus_limit = $inviteLimit;
                    }
                    if (!empty($updates)) {
                        $updates['updated_at'] = $now;
                        $this->quotaRepository->updateQuota($userid, $updates);
                    }
                } elseif ($baseMax > 0) {
                    $currentMax = intval($quota->max_count ?? 0);
                    $bonusCount = max(0, intval($quota->invite_bonus_count ?? 0));
                    $currentBase = max(0, $currentMax - $bonusCount);
                    if ($currentBase < $baseMax) {
                        $newMax = $baseMax + $bonusCount;
                        $this->quotaRepository->updateQuota($userid, [
                            'max_count' => $newMax,
                            'updated_at' => $now,
                        ]);
                        $quota->max_count = $newMax;
                    }
                }

                $maxCount = intval($quota->max_count ?? ($isPrivileged ? $privilegedLimit : 0));
                $usedCount = intval($quota->used_count ?? 0);

                if (!$isPrivileged && $maxCount > 0 && $usedCount >= $maxCount) {
                    throw new CfAtomicQuotaExceededException('quota_exceeded');
                }

                $exists = Capsule::table('mod_cloudflare_subdomain')
                    ->whereRaw('LOWER(subdomain)=?', [$fullLower])
                    ->lockForUpdate()
                    ->exists();
                if ($exists) {
                    throw new CfAtomicAlreadyRegisteredException('already_registered');
                }

                $data = array_merge([
                    'userid' => $userid,
                    'subdomain' => $fullLower,
                    'rootdomain' => $rootLower,
                    'cloudflare_zone_id' => $zoneId,
                    'status' => 'active',
                    'expires_at' => $expiresAt,
                    'renewed_at' => $neverExpiresFlag ? null : $now,
                    'auto_deleted_at' => null,
                    'never_expires' => $neverExpiresFlag,
                    'created_at' => $now,
                    'updated_at' => $now
                ], $extraData);

                $id = Capsule::table('mod_cloudflare_subdomain')->insertGetId($data);

                $this->quotaRepository->updateQuota($userid, [
                    'used_count' => $usedCount + 1,
                    'updated_at' => $now,
                ]);
                $quota->used_count = $usedCount + 1;

                $reportedMax = intval($quota->max_count ?? ($isPrivileged ? $privilegedLimit : $baseMax));

                return [
                    'id' => $id,
                    'used_count' => $usedCount + 1,
                    'max_count' => $reportedMax
                ];
            });
        } catch (\Illuminate\Database\QueryException $e) {
            $message = strtolower($e->getMessage());
            if (strpos($message, 'duplicate') !== false || strpos($message, 'unique') !== false) {
                throw new CfAtomicAlreadyRegisteredException('already_registered', 0, $e);
            }
            throw $e;
        }
    }

    public function loadSubdomainsPaginated(int $userid, int $page, int $pageSize, string $searchTerm = ''): array
    {
        $page = max(1, $page);
        $pageSize = max(1, $pageSize);

        try {
            $baseQuery = Capsule::table('mod_cloudflare_subdomain')
                ->where('userid', $userid)
                ->where('status', 'active');

            if ($searchTerm !== '') {
                $like = '%' . $searchTerm . '%';
                $baseQuery->where(function ($query) use ($like) {
                    $query->where('subdomain', 'like', $like)
                        ->orWhere('rootdomain', 'like', $like);
                });
            }

            $total = (clone $baseQuery)->count();
            $totalPages = max(1, (int) ceil($total / $pageSize));
            if ($page > $totalPages) {
                $page = $totalPages;
            }

            $records = $baseQuery->orderBy('created_at', 'desc')
                ->offset(($page - 1) * $pageSize)
                ->limit($pageSize)
                ->get();

            if ($records instanceof \Illuminate\Support\Collection) {
                $records = $records->all();
            }
            if (!is_array($records)) {
                $records = [];
            }

            return [$records, $total, $totalPages, $page];
        } catch (\Throwable $e) {
            return [[], 0, 1, max(1, $page)];
        }
    }

    public function checkRootdomainUserLimit(int $userid, string $rootdomain, int $expectedNewDomains = 1): array
    {
        $limit = cfmod_get_rootdomain_limit($rootdomain);
        $rootdomainLower = strtolower(trim($rootdomain));
        if ($userid <= 0 || $rootdomainLower === '' || $limit <= 0) {
            return [
                'allowed' => true,
                'limit' => $limit,
                'current' => 0,
                'remaining' => $limit > 0 ? $limit : null,
            ];
        }

        $expectedNewDomains = max(0, $expectedNewDomains);
        $current = 0;
        try {
            if (Capsule::schema()->hasTable('mod_cloudflare_subdomain')) {
                $ignoredStatuses = ['deleted', 'cancelled', 'canceled', 'pending_delete', 'pending_remove'];
                $current = Capsule::table('mod_cloudflare_subdomain')
                    ->where('userid', $userid)
                    ->whereRaw('LOWER(rootdomain) = ?', [$rootdomainLower])
                    ->whereNotIn('status', $ignoredStatuses)
                    ->count();
            }
        } catch (\Throwable $e) {
            $current = 0;
        }

        $allowed = ($expectedNewDomains === 0)
            ? ($current < $limit)
            : (($current + $expectedNewDomains) <= $limit);

        return [
            'allowed' => $allowed,
            'limit' => $limit,
            'current' => $current,
            'remaining' => $limit > 0 ? max(0, $limit - $current) : null,
        ];
    }

    private function applyRootdomainTermOverride(string $rootLower, int $globalTerm): int
    {
        $override = $this->getRootdomainDefaultTerm($rootLower);
        if ($override !== null && $override > 0) {
            return $override;
        }
        return $globalTerm;
    }

    private function getRootdomainDefaultTerm(string $rootLower): ?int
    {
        static $cache = [];
        if ($rootLower === '') {
            return null;
        }
        if (array_key_exists($rootLower, $cache)) {
            return $cache[$rootLower];
        }
        try {
            $row = Capsule::table('mod_cloudflare_rootdomains')
                ->select('default_term_years')
                ->whereRaw('LOWER(domain) = ?', [$rootLower])
                ->first();
            if ($row !== null) {
                $value = (int) ($row->default_term_years ?? 0);
                if ($value < 0) {
                    $value = 0;
                }
                $cache[$rootLower] = $value;
                return $value;
            }
        } catch (\Throwable $e) {
        }
        $cache[$rootLower] = null;
        return null;
    }

    private static function dnsHistoryColumnAvailable(): bool
    {
        static $available = null;
        if ($available !== null) {
            return $available;
        }
        try {
            $available = Capsule::schema()->hasColumn('mod_cloudflare_subdomain', 'has_dns_history');
        } catch (\Throwable $e) {
            $available = false;
        }
        return $available;
    }

    public static function markHasDnsHistory(int $subdomainId): void
    {
        if ($subdomainId <= 0 || !self::dnsHistoryColumnAvailable()) {
            return;
        }
        try {
            Capsule::table('mod_cloudflare_subdomain')
                ->where('id', $subdomainId)
                ->where(function ($query) {
                    $query->whereNull('has_dns_history')->orWhere('has_dns_history', 0);
                })
                ->update([
                    'has_dns_history' => 1,
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
        } catch (\Throwable $e) {
        }
    }

    public static function syncDnsHistoryFlag(int $subdomainId): void
    {
        if ($subdomainId <= 0 || !self::dnsHistoryColumnAvailable()) {
            return;
        }
        try {
            $exists = Capsule::table('mod_cloudflare_dns_records')
                ->where('subdomain_id', $subdomainId)
                ->exists();
        } catch (\Throwable $e) {
            return;
        }
        if ($exists) {
            self::markHasDnsHistory($subdomainId);
        }
    }
}
