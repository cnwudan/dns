<?php
// phpcs:ignoreFile

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfDnsUnlockService
{
    private const CODE_LENGTH = 10;

    public static function ensureProfile(int $userId): array
    {
        if ($userId <= 0) {
            throw new \InvalidArgumentException('Invalid user');
        }
        $row = Capsule::table('mod_cloudflare_dns_unlock_codes')->where('userid', $userId)->first();
        if (!$row) {
            $row = self::createProfile($userId);
        }
        return self::normalizeRow($row);
    }

    public static function userHasUnlocked(int $userId): bool
    {
        if ($userId <= 0) {
            return false;
        }
        $row = Capsule::table('mod_cloudflare_dns_unlock_codes')
            ->select('unlocked_at')
            ->where('userid', $userId)
            ->first();
        if (!$row) {
            return false;
        }
        return !empty($row->unlocked_at);
    }

    public static function unlockForUser(int $userId, string $inputCode, int $usedByUserId, string $usedEmail, string $ipAddress = ''): void
    {
        $cleanCode = strtoupper(trim($inputCode));
        if ($cleanCode === '') {
            throw new \InvalidArgumentException('invalid_code');
        }
        $ownerProfile = self::findProfileByCode($cleanCode);
        if (!$ownerProfile) {
            throw new \InvalidArgumentException('invalid_code');
        }
        $ownerId = (int) ($ownerProfile['userid'] ?? 0);
        if ($ownerId === $userId) {
            throw new \InvalidArgumentException('self_code');
        }
        if (!self::ownerCanShareUnlockCode($ownerId)) {
            throw new \InvalidArgumentException('owner_banned');
        }
        $profile = self::ensureProfile($userId);
        if (!empty($profile['unlocked_at'])) {
            throw new \InvalidArgumentException('already_unlocked');
        }

        Capsule::table('mod_cloudflare_dns_unlock_codes')
            ->where('id', $profile['id'])
            ->update([
                'unlocked_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);

        Capsule::table('mod_cloudflare_dns_unlock_logs')->insert([
            'unlock_code_id' => $ownerProfile['id'],
            'owner_userid' => $ownerProfile['userid'],
            'used_userid' => $usedByUserId,
            'used_email' => strtolower(trim($usedEmail ?? '')),
            'used_ip' => $ipAddress,
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s'),
        ]);

        self::rotateUnlockCode((int) ($ownerProfile['id'] ?? 0));
    }

    public static function unlockByPurchase(int $userId, string $usedEmail = '', string $ipAddress = ''): void
    {
        $profile = self::ensureProfile($userId);
        if (!empty($profile['unlocked_at'])) {
            throw new \InvalidArgumentException('already_unlocked');
        }
        Capsule::table('mod_cloudflare_dns_unlock_codes')
            ->where('id', $profile['id'])
            ->update([
                'unlocked_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
        Capsule::table('mod_cloudflare_dns_unlock_logs')->insert([
            'unlock_code_id' => $profile['id'],
            'owner_userid' => $userId,
            'used_userid' => $userId,
            'used_email' => strtolower(trim($usedEmail ?? '')),
            'used_ip' => $ipAddress,
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s'),
        ]);

        self::rotateUnlockCode((int) ($profile['id'] ?? 0));
    }

    public static function fetchAdminLogs(string $search, int $page, int $perPage = 20): array
    {
        $page = max(1, $page);
        $perPage = max(1, $perPage);
        $search = trim($search);
        try {
            $query = Capsule::table('mod_cloudflare_dns_unlock_logs as l')
                ->leftJoin('mod_cloudflare_dns_unlock_codes as c', 'l.unlock_code_id', '=', 'c.id')
                ->leftJoin('tblclients as owner', 'l.owner_userid', '=', 'owner.id')
                ->leftJoin('tblclients as used', 'l.used_userid', '=', 'used.id')
                ->select('l.*', 'c.unlock_code', 'owner.email as owner_email', 'owner.id as owner_id', 'used.email as used_account_email');
            if ($search !== '') {
                if (strpos($search, '@') !== false) {
                    $like = '%' . $search . '%';
                    $query->where(function ($q) use ($like) {
                        $q->where('l.used_email', 'like', $like)
                            ->orWhere('owner.email', 'like', $like)
                            ->orWhere('used.email', 'like', $like);
                    });
                } else {
                    $query->whereRaw('UPPER(c.unlock_code) LIKE ?', [strtoupper($search) . '%']);
                }
            }
            $total = $query->count();
            $totalPages = max(1, (int) ceil($total / $perPage));
            if ($page > $totalPages) {
                $page = $totalPages;
            }
            $rows = $query
                ->orderBy('l.id', 'desc')
                ->offset(($page - 1) * $perPage)
                ->limit($perPage)
                ->get();
            $items = [];
            foreach ($rows as $row) {
                $items[] = [
                    'id' => (int) ($row->id ?? 0),
                    'unlock_code' => strtoupper((string) ($row->unlock_code ?? '')),
                    'owner_userid' => (int) ($row->owner_userid ?? 0),
                    'owner_email' => (string) ($row->owner_email ?? ''),
                    'used_userid' => (int) ($row->used_userid ?? 0),
                    'used_email' => (string) ($row->used_email ?? ($row->used_account_email ?? '')),
                    'used_ip' => (string) ($row->used_ip ?? ''),
                    'used_at' => $row->created_at ?? '',
                ];
            }
            return [
                'items' => $items,
                'search' => $search,
                'pagination' => [
                    'page' => $page,
                    'perPage' => $perPage,
                    'total' => $total,
                    'totalPages' => $totalPages,
                ],
            ];
        } catch (\Throwable $e) {
            return [
                'items' => [],
                'search' => $search,
                'pagination' => [
                    'page' => $page,
                    'perPage' => $perPage,
                    'total' => 0,
                    'totalPages' => 1,
                ],
            ];
        }
    }

    public static function fetchLogs(int $userId, int $page, int $perPage): array
    {
        $page = max(1, $page);
        $perPage = max(1, $perPage);
        $query = Capsule::table('mod_cloudflare_dns_unlock_logs as l')
            ->leftJoin('tblclients as c', 'l.used_userid', '=', 'c.id')
            ->select('l.*', 'c.email as joined_email')
            ->where('l.owner_userid', $userId);
        $total = $query->count();
        $totalPages = max(1, (int) ceil($total / $perPage));
        if ($page > $totalPages) {
            $page = $totalPages;
        }
        $logs = $query
            ->orderBy('l.id', 'desc')
            ->offset(($page - 1) * $perPage)
            ->limit($perPage)
            ->get();
        $items = [];
        foreach ($logs as $log) {
            $email = $log->used_email ?: ($log->joined_email ?? '');
            $items[] = [
                'id' => (int) $log->id,
                'email' => $email,
                'email_masked' => self::maskEmail($email),
                'used_at' => $log->created_at,
            ];
        }
        return [
            'items' => $items,
            'pagination' => [
                'page' => $page,
                'perPage' => $perPage,
                'total' => $total,
                'totalPages' => $totalPages,
            ],
        ];
    }

    public static function getLastUsedUnlockInfo(int $userId): ?array
    {
        if ($userId <= 0) {
            return null;
        }
        try {
            $row = Capsule::table('mod_cloudflare_dns_unlock_logs as l')
                ->leftJoin('mod_cloudflare_dns_unlock_codes as c', 'l.unlock_code_id', '=', 'c.id')
                ->select('l.created_at', 'l.owner_userid', 'c.unlock_code')
                ->where('l.used_userid', $userId)
                ->orderBy('l.id', 'desc')
                ->first();
            if (!$row || empty($row->unlock_code)) {
                return null;
            }
            return [
                'code' => strtoupper((string) $row->unlock_code),
                'owner_userid' => (int)($row->owner_userid ?? 0),
                'used_at' => $row->created_at ?? null,
            ];
        } catch (\Throwable $e) {
            return null;
        }
    }

    public static function maskEmail(?string $email): string
    {
        $email = trim((string) $email);
        if ($email === '' || strpos($email, '@') === false) {
            return $email !== '' ? $email : '-';
        }
        [$user, $domain] = explode('@', $email, 2);
        $userLen = strlen($user);
        if ($userLen <= 2) {
            $maskedUser = substr($user, 0, 1) . '*';
        } else {
            $maskedUser = substr($user, 0, 2) . str_repeat('*', max(1, $userLen - 3)) . substr($user, -1);
        }
        $domainParts = explode('.', $domain);
        $maskedDomainParts = array_map(function ($part) {
            $len = strlen($part);
            if ($len <= 2) {
                return substr($part, 0, 1) . '*';
            }
            return substr($part, 0, 1) . str_repeat('*', max(1, $len - 2)) . substr($part, -1);
        }, $domainParts);
        return $maskedUser . '@' . implode('.', $maskedDomainParts);
    }

    private static function createProfile(int $userId)
    {
        $code = self::generateUniqueCode();
        $now = date('Y-m-d H:i:s');
        $id = Capsule::table('mod_cloudflare_dns_unlock_codes')->insertGetId([
            'userid' => $userId,
            'unlock_code' => $code,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        return Capsule::table('mod_cloudflare_dns_unlock_codes')->where('id', $id)->first();
    }

    private static function findProfileByCode(string $code): ?array
    {
        $code = strtoupper(trim($code));
        if ($code === '') {
            return null;
        }
        try {
            $row = Capsule::table('mod_cloudflare_dns_unlock_codes')->where('unlock_code', $code)->first();
            return $row ? self::normalizeRow($row) : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    private static function rotateUnlockCode(int $profileId): ?string
    {
        if ($profileId <= 0) {
            return null;
        }
        try {
            $newCode = self::generateUniqueCode();
            Capsule::table('mod_cloudflare_dns_unlock_codes')
                ->where('id', $profileId)
                ->update([
                    'unlock_code' => $newCode,
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
            return $newCode;
        } catch (\Throwable $e) {
            return null;
        }
    }

    private static function generateUniqueCode(): string
    {
        do {
            $bytes = max(4, (int) ceil(self::CODE_LENGTH / 2));
            $code = strtoupper(substr(bin2hex(random_bytes($bytes)), 0, self::CODE_LENGTH));
            $exists = Capsule::table('mod_cloudflare_dns_unlock_codes')->where('unlock_code', $code)->exists();
        } while ($exists);
        return $code;
    }

    private static function normalizeRow($row): array
    {
        if (!$row) {
            return [
                'id' => 0,
                'userid' => 0,
                'unlock_code' => '',
                'unlocked_at' => null,
            ];
        }
        return [
            'id' => (int) ($row->id ?? 0),
            'userid' => (int) ($row->userid ?? 0),
            'unlock_code' => strtoupper((string) ($row->unlock_code ?? '')),
            'unlocked_at' => $row->unlocked_at ?? null,
            'created_at' => $row->created_at ?? null,
            'updated_at' => $row->updated_at ?? null,
        ];
    }

    private static function ownerCanShareUnlockCode(int $ownerId): bool
    {
        if ($ownerId <= 0) {
            return false;
        }
        try {
            $status = Capsule::table('tblclients')->where('id', $ownerId)->value('status');
            if ($status !== null && strtolower((string) $status) !== 'active') {
                return false;
            }
        } catch (\Throwable $e) {
            // ignore status lookup errors, default to allowing
        }
        try {
            if (function_exists('cfmod_resolve_user_ban_state')) {
                $banState = cfmod_resolve_user_ban_state($ownerId);
                if (!empty($banState['is_banned'])) {
                    return false;
                }
            }
        } catch (\Throwable $e) {
            // ignore ban lookup errors
        }
        return true;
    }
}
