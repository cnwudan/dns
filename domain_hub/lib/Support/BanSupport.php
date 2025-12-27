<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfBanSupport
{
    private static array $cache = [];

    public static function resolveState(int $userId): array
    {
        if ($userId <= 0) {
            return ['is_banned' => false, 'reason' => ''];
        }

        if (isset(self::$cache[$userId])) {
            return self::$cache[$userId];
        }

        $state = ['is_banned' => false, 'reason' => ''];
        $reasonParts = [];
        $languageMeta = function_exists('cfmod_resolve_language_preference') ? cfmod_resolve_language_preference() : ['normalized' => 'english'];
        $isChinese = strtolower($languageMeta['normalized'] ?? '') === 'chinese';
        $labels = [
            'reason' => $isChinese ? '原因：' : 'Reason: ',
            'none' => $isChinese ? '无' : 'N/A',
            'banned_at_prefix' => $isChinese ? '（封禁时间：' : ' (Banned at: ',
            'banned_at_suffix' => $isChinese ? '）' : ')',
            'unban_prefix' => $isChinese ? '，预计解封时间：' : ', Estimated unban: ',
            'weekly_prefix' => $isChinese ? '，预计解封：' : ', Estimated unban: ',
            'separator' => $isChinese ? '；' : '; ',
        ];

        try {
            if (Capsule::schema()->hasTable('mod_cloudflare_user_bans')) {
                $banRecord = Capsule::table('mod_cloudflare_user_bans')
                    ->where('userid', $userId)
                    ->where('status', 'banned')
                    ->orderBy('id', 'desc')
                    ->first();
                if ($banRecord) {
                    $state['is_banned'] = true;
                    $banReason = trim((string)($banRecord->ban_reason ?? ''));
                    if ($banReason === '') {
                        $banReason = $labels['none'];
                    }
                    $reason = $labels['reason'] . $banReason;
                    $bannedAt = $banRecord->banned_at ?? null;
                    $bannedAtTs = $bannedAt ? strtotime($bannedAt) : false;
                    if ($bannedAtTs !== false) {
                        $reason .= $labels['banned_at_prefix'] . date('Y-m-d H:i', $bannedAtTs) . $labels['banned_at_suffix'];
                    }
                    $banType = $banRecord->ban_type ?? 'permanent';
                    $banExpires = $banRecord->ban_expires_at ?? null;
                    $banExpiresTs = $banExpires ? strtotime($banExpires) : false;
                    if ($banType !== 'permanent') {
                        if ($banExpiresTs !== false) {
                            $reason .= $labels['unban_prefix'] . date('Y-m-d H:i', $banExpiresTs);
                        } elseif ($banType === 'weekly' && $bannedAtTs !== false) {
                            $reason .= $labels['weekly_prefix'] . date('Y-m-d H:i', strtotime('+7 days', $bannedAtTs));
                        }
                    }
                    $reasonParts[] = $reason;
                }
            }
        } catch (\Throwable $e) {
            // Ignore ban resolution errors
        }

        if (!empty($reasonParts)) {
            $state['reason'] = implode($labels['separator'], $reasonParts);
        }

        return self::$cache[$userId] = $state;
    }
}

if (!function_exists('cfmod_resolve_user_ban_state')) {
    function cfmod_resolve_user_ban_state(int $userId): array
    {
        return CfBanSupport::resolveState($userId);
    }
}
