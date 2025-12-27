<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfHookRegistrar
{
    private static bool $registered = false;

    private static function assetBasePath(): string
    {
        $moduleSlug = defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
        $relative = 'modules/addons/' . $moduleSlug . '/assets';
        return '/' . ltrim($relative, '/');
    }

    public static function registerAll(): void
    {
        if (self::$registered) {
            return;
        }
        self::$registered = true;

        self::registerClientHooks();
        self::registerAdminHooks();
        self::registerCronHooks();
    }

    private static function registerClientHooks(): void
    {
        add_hook('ClientAreaPage', 1, function ($vars) {
            if (cf_is_module_request()) {
                if (CfApiRouter::isApiRequest()) {
                    CfApiRouter::dispatch();
                }

                if (!isset($_SESSION['uid'])) {
                    $target = 'index.php?m=' . CF_MODULE_NAME;
                    if (!cf_is_legacy_module_entry()) {
                        $target = 'clientarea.php?action=addon&module=' . CF_MODULE_NAME;
                    }
                    $requestUri = $_SERVER['REQUEST_URI'] ?? '';
                    if (is_string($requestUri) && $requestUri !== '') {
                        $relative = ltrim($requestUri, '/');
                        if ($relative !== '' && stripos($relative, 'login.php') !== 0) {
                            $target = $relative;
                        }
                    }
                    header('Location: login.php?returnurl=' . urlencode($target));
                    exit;
                }
            }
        });

        add_hook('ClientAreaPage', 999, function ($vars) {
            if (!cf_is_module_request() || !cf_is_legacy_module_entry()) {
                return;
            }
            domain_hub_handle_clientarea_page($vars, true);
        });

        add_hook('ClientAreaHeadOutput', 1, function ($vars) {
            if (cf_is_module_request()) {
                $assetBase = htmlspecialchars(self::assetBasePath(), ENT_QUOTES, 'UTF-8');
                return '<link rel="stylesheet" href="' . $assetBase . '/css/bootstrap.min.css">'
                    . '<link rel="stylesheet" href="' . $assetBase . '/css/fontawesome-all.min.css">';
            }
        });

        add_hook('ClientAreaFooterOutput', 1, function ($vars) {
            if (cf_is_module_request()) {
                $assetBase = htmlspecialchars(self::assetBasePath(), ENT_QUOTES, 'UTF-8');
                return '<script src="' . $assetBase . '/js/bootstrap.bundle.min.js"></script>';
            }
        });
    }

    private static function registerAdminHooks(): void
    {
        add_hook('AdminAreaHeadOutput', 1, function ($vars) {
            if (cf_is_module_request('module')) {
                $assetBase = htmlspecialchars(self::assetBasePath(), ENT_QUOTES, 'UTF-8');
                return '<link rel="stylesheet" href="' . $assetBase . '/css/bootstrap.min.css">'
                    . '<link rel="stylesheet" href="' . $assetBase . '/css/fontawesome-all.min.css">';
            }
        });

        add_hook('AdminAreaFooterOutput', 1, function ($vars) {
            if (cf_is_module_request('module')) {
                $assetBase = htmlspecialchars(self::assetBasePath(), ENT_QUOTES, 'UTF-8');
                return '<script src="' . $assetBase . '/js/bootstrap.bundle.min.js"></script>';
            }
        });
    }

    private static function registerCronHooks(): void
    {
        add_hook('AfterCronJob', 2, function($vars) {
            try {
                cf_ensure_module_settings_migrated();
                $settings = cf_get_module_settings_cached();
                $enabled = (($settings['enable_invite_leaderboard'] ?? 'on') === 'on') || (($settings['enable_invite_leaderboard'] ?? '1') == '1');
                if (!$enabled) { return; }
                $topN = max(1, intval($settings['invite_leaderboard_top'] ?? 5));
                $periodDays = max(1, intval($settings['invite_leaderboard_period_days'] ?? 7));
                $cycleStart = trim($settings['invite_cycle_start'] ?? '');
                if ($cycleStart !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $cycleStart)) {
                    $todayYmd = date('Y-m-d');
                    $startTs = strtotime($cycleStart);
                    $todayTs = strtotime($todayYmd);
                    if ($todayTs <= $startTs) { return; }
                    $maxK = (int) floor( ($todayTs - $startTs) / 86400 / $periodDays );
                    for ($k = 0; $k <= $maxK; $k++) {
                        $periodStart = date('Y-m-d', strtotime('+' . ($k * $periodDays) . ' days', $startTs));
                        $periodEnd   = date('Y-m-d', strtotime($periodStart . ' +' . ($periodDays - 1) . ' days'));
                        if ($todayYmd <= $periodEnd) { continue; }
                        $exists = Capsule::table('mod_cloudflare_invite_leaderboard')
                            ->where('period_start',$periodStart)->where('period_end',$periodEnd)->count();
                        if ($exists) { continue; }

                        $winners = Capsule::table('mod_cloudflare_invitation_claims as ic')
                            ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as cnt'))
                            ->whereBetween('ic.created_at', [$periodStart.' 00:00:00', $periodEnd.' 23:59:59'])
                            ->groupBy('ic.inviter_userid')
                            ->orderBy('cnt', 'desc')
                            ->limit($topN)
                            ->get();
                        $winnersArray = cfmod_iterable_to_array($winners);

                        $userIds = array_map(function($w) { return $w->inviter_userid; }, $winnersArray);
                        $codes = [];
                        if (!empty($userIds)) {
                            $codeRows = Capsule::table('mod_cloudflare_invitation_codes')
                                ->select('userid', 'code')
                                ->whereIn('userid', $userIds)
                                ->get();
                            foreach ($codeRows as $cr) {
                                $codes[$cr->userid] = $cr->code;
                            }
                        }

                        $top = [];
                        foreach ($winnersArray as $idx => $w) {
                            $top[] = [
                                'rank' => $idx + 1,
                                'inviter_userid' => intval($w->inviter_userid),
                                'code' => $codes[$w->inviter_userid] ?? '',
                                'count' => intval($w->cnt)
                            ];
                        }
                        Capsule::table('mod_cloudflare_invite_leaderboard')->insert([
                            'period_start' => $periodStart,
                            'period_end' => $periodEnd,
                            'top_json' => json_encode($top, JSON_UNESCAPED_UNICODE),
                            'created_at' => date('Y-m-d H:i:s'),
                            'updated_at' => date('Y-m-d H:i:s')
                        ]);
                        foreach ($top as $row) {
                            $existsReward = Capsule::table('mod_cloudflare_invite_rewards')
                                ->where('period_start',$periodStart)->where('period_end',$periodEnd)
                                ->where('inviter_userid',$row['inviter_userid'])->count();
                            if (!$existsReward) {
                                Capsule::table('mod_cloudflare_invite_rewards')->insert([
                                    'period_start' => $periodStart,
                                    'period_end' => $periodEnd,
                                    'inviter_userid' => $row['inviter_userid'],
                                    'code' => $row['code'] ?? '',
                                    'rank' => $row['rank'] ?? 0,
                                    'count' => $row['count'] ?? 0,
                                    'status' => 'eligible',
                                    'created_at' => date('Y-m-d H:i:s'),
                                    'updated_at' => date('Y-m-d H:i:s')
                                ]);
                            }
                        }
                    }
                    return;
                } else {
                    if (intval(date('N')) !== 1) { return; }
                    $periodEnd = date('Y-m-d', strtotime('yesterday'));
                    $periodStart = date('Y-m-d', strtotime($periodEnd . ' -' . ($periodDays - 1) . ' days'));
                }
                $exists = Capsule::table('mod_cloudflare_invite_leaderboard')->where('period_start',$periodStart)->where('period_end',$periodEnd)->count();
                if ($exists) { return; }
                $winners = Capsule::table('mod_cloudflare_invitation_claims as ic')
                    ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as cnt'))
                    ->whereBetween('ic.created_at', [$periodStart.' 00:00:00', $periodEnd.' 23:59:59'])
                    ->groupBy('ic.inviter_userid')
                    ->orderBy('cnt', 'desc')
                    ->limit($topN)
                    ->get();
                $winnersArray = cfmod_iterable_to_array($winners);
                $codes = [];
                if (!empty($winnersArray)) {
                    $userIds = array_map(function ($row) {
                        return intval(is_array($row) ? ($row['inviter_userid'] ?? 0) : ($row->inviter_userid ?? 0));
                    }, $winnersArray);
                    $userIds = array_filter($userIds);
                    if (!empty($userIds)) {
                        $codeRows = Capsule::table('mod_cloudflare_invitation_codes')
                            ->select('userid', 'code')
                            ->whereIn('userid', $userIds)
                            ->get();
                        foreach ($codeRows as $cr) {
                            $codes[$cr->userid] = $cr->code;
                        }
                    }
                }
                $top = [];
                foreach ($winnersArray as $idx => $w) {
                    $inviterId = is_array($w) ? intval($w['inviter_userid'] ?? 0) : intval($w->inviter_userid ?? 0);
                    $countValue = is_array($w) ? intval($w['cnt'] ?? 0) : intval($w->cnt ?? 0);
                    $top[] = [
                        'rank' => $idx + 1,
                        'inviter_userid' => $inviterId,
                        'code' => $inviterId && isset($codes[$inviterId]) ? $codes[$inviterId] : '',
                        'count' => $countValue
                    ];
                }
                Capsule::table('mod_cloudflare_invite_leaderboard')->insert([
                    'period_start' => $periodStart,
                    'period_end' => $periodEnd,
                    'top_json' => json_encode($top, JSON_UNESCAPED_UNICODE),
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                foreach ($top as $row) {
                    $existsReward = Capsule::table('mod_cloudflare_invite_rewards')
                        ->where('period_start',$periodStart)->where('period_end',$periodEnd)
                        ->where('inviter_userid',$row['inviter_userid'])->count();
                    if (!$existsReward) {
                        Capsule::table('mod_cloudflare_invite_rewards')->insert([
                            'period_start' => $periodStart,
                            'period_end' => $periodEnd,
                            'inviter_userid' => $row['inviter_userid'],
                            'code' => $row['code'] ?? '',
                            'rank' => $row['rank'] ?? 0,
                            'count' => $row['count'] ?? 0,
                            'status' => 'eligible',
                            'created_at' => date('Y-m-d H:i:s'),
                            'updated_at' => date('Y-m-d H:i:s')
                        ]);
                    }
                }
            } catch (\Throwable $e) {}
        });
    }

}
