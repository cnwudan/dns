<?php
use WHMCS\Database\Capsule;

require_once __DIR__ . '/lib/autoload.php';
CfModuleSettings::bootstrap();



if (!function_exists('cfmod_should_run_inline_queue')) {
    function cfmod_should_run_inline_queue(array $settings): bool {
        $raw = strtolower((string)($settings['run_inline_worker'] ?? 'auto'));
        if (in_array($raw, ['0', 'off', 'no', 'false', 'disabled'], true)) {
            return false;
        }
        if (in_array($raw, ['auto', 'default', ''], true)) {
            return true;
        }
        return in_array($raw, ['1', 'on', 'yes', 'true', 'enabled'], true);
    }
}

// Auto sync via WHMCS cron
add_hook('AfterCronJob', 1, function($vars) {
    try {
        // Load addon settings
        $rows = Capsule::table('tbladdonmodules')->where('module', CF_MODULE_NAME)->get();
        if (count($rows) === 0) {
            $rows = Capsule::table('tbladdonmodules')->where('module', CF_MODULE_NAME_LEGACY)->get();
        }
        $settings = [];
        foreach ($rows as $r) { $settings[$r->setting] = $r->value; }

        $enabled = ($settings['enable_auto_sync'] ?? 'on') === 'on' || ($settings['enable_auto_sync'] ?? '1') == '1';
        if (!$enabled) { return; }
        $intervalMin = intval($settings['sync_interval'] ?? 60);
        $intervalMin = max(5, min(1440, $intervalMin));

        $now = date('Y-m-d H:i:s');
        $last = Capsule::table('mod_cloudflare_jobs')
            ->where('type','calibrate_all')
            ->orderBy('id','desc')->first();

        $shouldEnqueue = false;
        if (!$last) { $shouldEnqueue = true; }
        else {
            if (in_array($last->status, ['failed','done','cancelled'])) {
                $lastTime = $last->updated_at ?? $last->created_at;
                if (!$lastTime || strtotime($lastTime) <= time() - $intervalMin * 60) {
                    $shouldEnqueue = true;
                }
            }
        }

        if ($shouldEnqueue) {
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'calibrate_all',
                'payload_json' => json_encode(['mode' => 'fix'], JSON_UNESCAPED_UNICODE),
                'priority' => 10,
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => $now,
                'updated_at' => $now
            ]);
        }

        // Risk scan enqueue
        $scanEnabled = ($settings['risk_scan_enabled'] ?? 'on') === 'on' || ($settings['risk_scan_enabled'] ?? '1') == '1';
        if ($scanEnabled) {
            $scanIntervalMin = intval($settings['risk_scan_interval'] ?? 120);
            $scanIntervalMin = max(15, min(1440, $scanIntervalMin));
            $lastRisk = Capsule::table('mod_cloudflare_jobs')
                ->where('type','risk_scan_all')
                ->orderBy('id','desc')->first();
            $shouldRisk = false;
            if (!$lastRisk) { $shouldRisk = true; }
            else {
                if (in_array($lastRisk->status, ['failed','done','cancelled'])) {
                    $lastTime = $lastRisk->updated_at ?? $lastRisk->created_at;
                    if (!$lastTime || strtotime($lastTime) <= time() - $scanIntervalMin * 60) {
                        $shouldRisk = true;
                    }
                }
            }
            if ($shouldRisk) {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'risk_scan_all',
                    'payload_json' => json_encode([], JSON_UNESCAPED_UNICODE),
                    'priority' => 20,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => $now,
                    'updated_at' => $now
                ]);
            }
        }

        // Try to execute a couple of jobs each cron pass（可选）
        if (cfmod_should_run_inline_queue($settings)) {
            $worker = __DIR__ . '/worker.php';
            if (file_exists($worker)) {
                require_once $worker;
                if (function_exists('run_cf_queue_once')) {
                    $maxJobs = intval($settings['cron_max_jobs_per_pass'] ?? 2);
                    if ($maxJobs <= 0) {
                        $maxJobs = 2;
                    }
                    $maxJobs = max(1, min(50, $maxJobs));
                    run_cf_queue_once($maxJobs);
                }
            }
        }
        
        // 检查是否需要创建风险事件清理任务（优化查询）
        $lastCleanup = Capsule::table('mod_cloudflare_jobs')
            ->where('type','cleanup_risk_events')
            ->whereIn('status', ['failed','done','cancelled'])
            ->orderBy('id','desc')
            ->first();
        
        $shouldCleanup = false;
        if (!$lastCleanup) { 
            $shouldCleanup = true; 
        } else {
            $lastTime = $lastCleanup->updated_at ?? $lastCleanup->created_at;
            // 每24小时清理一次
            if (!$lastTime || strtotime($lastTime) <= time() - 24 * 60 * 60) {
                $shouldCleanup = true;
            }
        }
        if ($shouldCleanup) {
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'cleanup_risk_events',
                'payload_json' => json_encode(['auto' => true], JSON_UNESCAPED_UNICODE),
                'priority' => 5,
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => $now,
                'updated_at' => $now
            ]);
        }

        // 检查是否需要创建 API 日志清理任务（每日一次）
        $apiRetention = intval($settings['api_logs_retention_days'] ?? 30);
        if ($apiRetention > 0) {
            $lastApiCleanup = Capsule::table('mod_cloudflare_jobs')
                ->where('type','cleanup_api_logs')
                ->whereIn('status', ['failed','done','cancelled'])
                ->orderBy('id','desc')
                ->first();
            $shouldApiCleanup = false;
            if (!$lastApiCleanup) { $shouldApiCleanup = true; }
            else {
                $lastTime = $lastApiCleanup->updated_at ?? $lastApiCleanup->created_at;
                if (!$lastTime || strtotime($lastTime) <= time() - 24 * 60 * 60) { $shouldApiCleanup = true; }
            }
            if ($shouldApiCleanup) {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_api_logs',
                    'payload_json' => json_encode([
                        'retention_days' => $apiRetention,
                        'auto' => true
                    ], JSON_UNESCAPED_UNICODE),
                    'priority' => 5,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => $now,
                    'updated_at' => $now
                ]);
            }
        }

        $generalRetention = intval($settings['general_logs_retention_days'] ?? 0);
        if ($generalRetention > 0) {
            $lastGeneralCleanup = Capsule::table('mod_cloudflare_jobs')
                ->where('type', 'cleanup_general_logs')
                ->whereIn('status', ['failed','done','cancelled'])
                ->orderBy('id','desc')
                ->first();
            $shouldGeneralCleanup = false;
            if (!$lastGeneralCleanup) {
                $shouldGeneralCleanup = true;
            } else {
                $lastTime = $lastGeneralCleanup->updated_at ?? $lastGeneralCleanup->created_at;
                if (!$lastTime || strtotime($lastTime) <= time() - 24 * 60 * 60) {
                    $shouldGeneralCleanup = true;
                }
            }
            if ($shouldGeneralCleanup) {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_general_logs',
                    'payload_json' => json_encode([
                        'retention_days' => $generalRetention,
                        'batch_limit' => 2000,
                        'auto' => true,
                    ], JSON_UNESCAPED_UNICODE),
                    'priority' => 5,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => $now,
                    'updated_at' => $now
                ]);
            }
        }

        $syncRetention = intval($settings['sync_logs_retention_days'] ?? 0);
        if ($syncRetention > 0) {
            $lastSyncCleanup = Capsule::table('mod_cloudflare_jobs')
                ->where('type', 'cleanup_sync_logs')
                ->whereIn('status', ['failed','done','cancelled'])
                ->orderBy('id','desc')
                ->first();
            $shouldSyncCleanup = false;
            if (!$lastSyncCleanup) {
                $shouldSyncCleanup = true;
            } else {
                $lastTime = $lastSyncCleanup->updated_at ?? $lastSyncCleanup->created_at;
                if (!$lastTime || strtotime($lastTime) <= time() - 24 * 60 * 60) {
                    $shouldSyncCleanup = true;
                }
            }
            if ($shouldSyncCleanup) {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_sync_logs',
                    'payload_json' => json_encode([
                        'retention_days' => $syncRetention,
                        'batch_limit' => 2000,
                        'auto' => true,
                    ], JSON_UNESCAPED_UNICODE),
                    'priority' => 6,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => $now,
                    'updated_at' => $now
                ]);
            }
        }

        $giftEnabledValue = strtolower(trim((string)($settings['enable_domain_gift'] ?? '0')));
        $giftEnabled = in_array($giftEnabledValue, ['1','on','yes','true','enabled'], true);
        if ($giftEnabled) {
            $lastGiftCleanup = Capsule::table('mod_cloudflare_jobs')
                ->where('type', 'cleanup_domain_gifts')
                ->whereIn('status', ['failed','done','cancelled'])
                ->orderBy('id','desc')
                ->first();
            $giftInterval = 60; // minutes
            $shouldGiftCleanup = false;
            if (!$lastGiftCleanup) {
                $shouldGiftCleanup = true;
            } else {
                $lastTime = $lastGiftCleanup->updated_at ?? $lastGiftCleanup->created_at;
                if (!$lastTime || strtotime($lastTime) <= time() - $giftInterval * 60) {
                    $shouldGiftCleanup = true;
                }
            }
            if ($shouldGiftCleanup) {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_domain_gifts',
                    'payload_json' => json_encode([
                        'batch_size' => 200,
                        'auto' => true
                    ], JSON_UNESCAPED_UNICODE),
                    'priority' => 5,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => $now,
                    'updated_at' => $now
                ]);
            }
        }

        $gracePeriodRaw = $settings['domain_grace_period_days'] ?? ($settings['domain_auto_delete_grace_days'] ?? 45);
        $cleanupGraceDays = is_numeric($gracePeriodRaw) ? intval($gracePeriodRaw) : 45;

        if ($cleanupGraceDays < 0) {
            $cleanupGraceDays = 0;
        }
        if ($cleanupGraceDays >= 0) {
            $cleanupBatch = intval($settings['domain_cleanup_batch_size'] ?? 50);
            if ($cleanupBatch <= 0) { $cleanupBatch = 50; }
            $cleanupBatch = max(1, min(500, $cleanupBatch));
            $cleanupDeep = in_array(($settings['domain_cleanup_deep_delete'] ?? 'yes'), ['1','on','yes','true'], true);
            $cleanupIntervalHoursRaw = $settings['domain_cleanup_interval_hours'] ?? 24;
            $cleanupIntervalHours = is_numeric($cleanupIntervalHoursRaw) ? (int) $cleanupIntervalHoursRaw : 24;
            if ($cleanupIntervalHours < 1) {
                $cleanupIntervalHours = 1;
            } elseif ($cleanupIntervalHours > 168) {
                $cleanupIntervalHours = 168;
            }
            $cleanupIntervalSeconds = $cleanupIntervalHours * 3600;

            $lastExpiredCleanup = Capsule::table('mod_cloudflare_jobs')
                ->where('type', 'cleanup_expired_subdomains')
                ->whereIn('status', ['failed','done','cancelled'])
                ->orderBy('id', 'desc')
                ->first();

            $shouldExpiredCleanup = false;
            if (!$lastExpiredCleanup) {
                $shouldExpiredCleanup = true;
            } else {
                $lastTime = $lastExpiredCleanup->updated_at ?? $lastExpiredCleanup->created_at;
                if (!$lastTime || strtotime($lastTime) <= time() - $cleanupIntervalSeconds) {
                    $shouldExpiredCleanup = true;
                }
            }

            if ($shouldExpiredCleanup) {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_expired_subdomains',
                    'payload_json' => json_encode([
                        'batch_size' => $cleanupBatch,
                        'deep_delete' => $cleanupDeep ? 1 : 0,
                        'auto' => true,
                    ], JSON_UNESCAPED_UNICODE),
                    'priority' => 15,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => $now,
                    'updated_at' => $now
                ]);
            }
        }
    } catch (\Throwable $e) {
        cfmod_report_exception('after_cron_job', $e);
    }
});

