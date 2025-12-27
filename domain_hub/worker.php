<?php
if (!defined('WHMCS')) {
    // Try to bootstrap WHMCS when run via CLI
    $cwd = getcwd();
    $dirs = [
        $cwd,
        dirname($cwd),
        dirname(dirname($cwd)),
        dirname(dirname(dirname($cwd)))
    ];
    foreach ($dirs as $dir) {
        if (file_exists($dir . '/init.php')) {
            require_once $dir . '/init.php';
            break;
        }
    }
}

use WHMCS\Database\Capsule;
use Illuminate\Support\Collection;

require_once __DIR__ . '/lib/autoload.php';
CfModuleSettings::bootstrap();
require_once __DIR__ . '/lib/CloudflareAPI.php';
require_once __DIR__ . '/lib/ExternalRiskAPI.php';
require_once __DIR__ . '/lib/TtlHelper.php';
require_once __DIR__ . '/lib/RootDomainLimitHelper.php';
require_once __DIR__ . '/lib/CollectionHelper.php';
require_once __DIR__ . '/lib/ProviderResolver.php';
require_once __DIR__ . '/lib/AdminMaintenance.php';


// PHP 7.4 兼容：提供 ends_with 辅助函数
if (!function_exists('cf_str_ends_with')) {
    function cf_str_ends_with(string $haystack, string $needle): bool {
        if ($needle === '') { return true; }
        $len = strlen($needle);
        if (strlen($haystack) < $len) { return false; }
        return substr($haystack, -$len) === $needle;
    }
}

function cfmod_get_settings(): array {
    static $settingsCache = null;
    
    // 使用静态缓存，避免重复查询
    if ($settingsCache !== null) {
        return $settingsCache;
    }
    
    $settings = [];
    $moduleSlug = CF_MODULE_NAME;
    $legacySlug = CF_MODULE_NAME_LEGACY;
    try {
        $rows = Capsule::table('tbladdonmodules')->where('module', $moduleSlug)->get();
        if (count($rows) === 0 && $legacySlug !== $moduleSlug) {
            $rows = Capsule::table('tbladdonmodules')->where('module', $legacySlug)->get();
            foreach ($rows as $row) {
                Capsule::table('tbladdonmodules')->updateOrInsert(
                    ['module' => $moduleSlug, 'setting' => $row->setting],
                    ['value' => $row->value]
                );
            }
            $rows = Capsule::table('tbladdonmodules')->where('module', $moduleSlug)->get();
        }
        foreach ($rows as $row) {
            $settings[$row->setting] = $row->value;
        }
        $settingsCache = $settings; // 缓存结果
    } catch (\Exception $e) {
        $settings = [];
        $settingsCache = $settings;
    }
    return $settings;
}


function cfmod_job_metrics_supported(): bool {
    static $supported = null;
    if ($supported !== null) {
        return $supported;
    }
    try {
        $supported = Capsule::schema()->hasTable('mod_cloudflare_jobs')
            && Capsule::schema()->hasColumn('mod_cloudflare_jobs', 'started_at')
            && Capsule::schema()->hasColumn('mod_cloudflare_jobs', 'finished_at')
            && Capsule::schema()->hasColumn('mod_cloudflare_jobs', 'duration_seconds')
            && Capsule::schema()->hasColumn('mod_cloudflare_jobs', 'stats_json');
    } catch (\Throwable $e) {
        $supported = false;
    }
    return $supported;
}

function cfmod_build_stats_summary(array $stats): string {
    if (empty($stats)) {
        return 'OK';
    }
    $parts = [];
    if (isset($stats['processed_subdomains'])) {
        $parts[] = 'processed ' . intval($stats['processed_subdomains']) . ' subs';
    }
    if (isset($stats['processed_records'])) {
        $parts[] = 'records ' . intval($stats['processed_records']);
    }
    if (!empty($stats['differences_total'])) {
        $parts[] = 'diff ' . intval($stats['differences_total']);
    }
    if (!empty($stats['records_updated_local'])) {
        $parts[] = 'upd_local ' . intval($stats['records_updated_local']);
    }
    if (!empty($stats['records_imported_local'])) {
        $parts[] = 'add_local ' . intval($stats['records_imported_local']);
    }
    if (!empty($stats['records_updated_on_cf'])) {
        $parts[] = 'cf_upd ' . intval($stats['records_updated_on_cf']);
    }
    if (!empty($stats['records_created_on_cf'])) {
        $parts[] = 'cf_add ' . intval($stats['records_created_on_cf']);
    }
    if (!empty($stats['records_deleted_on_cf'])) {
        $parts[] = 'cf_del ' . intval($stats['records_deleted_on_cf']);
    }
    if (!empty($stats['unbanned'])) {
        $parts[] = 'unbanned ' . intval($stats['unbanned']);
    }
    if (!empty($stats['deleted'])) {
        $parts[] = 'deleted ' . intval($stats['deleted']);
    }
    if (!empty($stats['high_risk_deleted'])) {
        $parts[] = 'high_del ' . intval($stats['high_risk_deleted']);
    }
    if (!empty($stats['duplicate_deleted'])) {
        $parts[] = 'dup_del ' . intval($stats['duplicate_deleted']);
    }
    if (!empty($stats['warnings'])) {
        $warnings = is_array($stats['warnings']) ? $stats['warnings'] : [$stats['warnings']];
        $normalized = [];
        foreach ($warnings as $warning) {
            if (is_array($warning) || is_object($warning)) {
                $warning = json_encode($warning, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            }
            $warning = trim((string) $warning);
            if ($warning === '') {
                continue;
            }
            if (function_exists('mb_strlen')) {
                if (mb_strlen($warning, 'UTF-8') > 80) {
                    $warning = mb_substr($warning, 0, 77, 'UTF-8') . '…';
                }
            } elseif (strlen($warning) > 80) {
                $warning = substr($warning, 0, 77) . '…';
            }
            $normalized[] = $warning;
        }
        $warnCount = max(1, count($normalized));
        $parts[] = 'warnings ' . $warnCount;
        if (!empty($normalized)) {
            $preview = array_slice($normalized, 0, 2);
            $parts[] = 'warn ' . implode('; ', $preview) . ($warnCount > 2 ? '; …' : '');
        }
    }
    if (!empty($stats['has_more'])) {
        $parts[] = 'continuation queued';
    }
    if (!empty($stats['message'])) {
        $parts[] = trim((string)$stats['message']);
    }
    $parts = array_filter(array_map('trim', $parts));
    if (empty($parts)) {
        return 'OK';
    }
    return 'OK: ' . implode(', ', $parts);
}

function cfmod_track_sync_stat(array &$stats, string $kind, string $action): void {
    $stats['differences_total'] = ($stats['differences_total'] ?? 0) + 1;
    if (!isset($stats['difference_breakdown'][$kind])) {
        $stats['difference_breakdown'][$kind] = 0;
    }
    $stats['difference_breakdown'][$kind]++;
    if (!isset($stats['action_breakdown'][$action])) {
        $stats['action_breakdown'][$action] = 0;
    }
    $stats['action_breakdown'][$action]++;
    if ($action === 'created_on_cf') {
        $stats['records_created_on_cf'] = ($stats['records_created_on_cf'] ?? 0) + 1;
    } elseif ($action === 'updated_on_cf') {
        $stats['records_updated_on_cf'] = ($stats['records_updated_on_cf'] ?? 0) + 1;
    } elseif ($action === 'imported_local') {
        $stats['records_imported_local'] = ($stats['records_imported_local'] ?? 0) + 1;
    } elseif ($action === 'deleted_on_cf') {
        $stats['records_deleted_on_cf'] = ($stats['records_deleted_on_cf'] ?? 0) + 1;
    }
}

function cfmod_worker_resolve_provider_account_id_for_subdomain($subdomainRow, array $settings): ?int
{
    if (is_array($subdomainRow)) {
        $providerId = $subdomainRow['provider_account_id'] ?? null;
        $rootdomain = $subdomainRow['rootdomain'] ?? null;
        $subId = $subdomainRow['id'] ?? null;
    } else {
        $providerId = $subdomainRow->provider_account_id ?? null;
        $rootdomain = $subdomainRow->rootdomain ?? null;
        $subId = $subdomainRow->id ?? null;
    }
    return cfmod_resolve_provider_account_id($providerId, $rootdomain, $subId, $settings);
}

function cfmod_worker_resolve_provider_account_id_for_rootdomain($rootdomainRow, array $settings): ?int
{
    if (is_array($rootdomainRow)) {
        $providerId = $rootdomainRow['provider_account_id'] ?? null;
        $rootdomain = $rootdomainRow['domain'] ?? ($rootdomainRow['rootdomain'] ?? null);
    } elseif (is_object($rootdomainRow)) {
        $providerId = $rootdomainRow->provider_account_id ?? null;
        $rootdomain = $rootdomainRow->domain ?? ($rootdomainRow->rootdomain ?? null);
    } else {
        $providerId = null;
        $rootdomain = $rootdomainRow;
    }
    return cfmod_resolve_provider_account_id($providerId, $rootdomain, null, $settings);
}

function cfmod_worker_acquire_provider_client_cached($providerAccountId, array $settings, array &$cache, array &$stats, string $context): ?array
{
    $key = $providerAccountId ?: 0;
    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }
    try {
        $clientContext = cfmod_make_provider_client($providerAccountId, null, null, $settings);
    } catch (\Throwable $e) {
        $clientContext = null;
    }
    if (!$clientContext || empty($clientContext['client'])) {
        $cache[$key] = null;
        $stats['warnings'][] = $context . '_provider_unavailable:' . $key;
        return null;
    }
    $cache[$key] = $clientContext;
    return $clientContext;
}

function run_cf_queue_once(int $maxJobs = 3): void {
    $now = date('Y-m-d H:i:s');
    $metricsSupported = cfmod_job_metrics_supported();
    $jobs = Capsule::table('mod_cloudflare_jobs')
        ->where('status', 'pending')
        ->where(function($q) use ($now) { $q->whereNull('next_run_at')->orWhere('next_run_at', '<=', $now); })
        ->orderBy('priority', 'asc')
        ->orderBy('attempts', 'asc')
        ->orderBy('id', 'asc')
        ->limit($maxJobs)
        ->get();

    foreach ($jobs as $job) {
        $jobStartMicro = microtime(true);
        $jobStartAt = date('Y-m-d H:i:s');
        $stats = [];
        try {
            // 原子抢占：仅当任务仍为 pending 时才能抢占
            $claimData = [
                'status' => 'running',
                'attempts' => $job->attempts + 1,
                'updated_at' => $jobStartAt,
            ];
            if ($metricsSupported) {
                $claimData['started_at'] = $jobStartAt;
                $claimData['finished_at'] = null;
                $claimData['duration_seconds'] = null;
                $claimData['stats_json'] = null;
            }
            $claimed = Capsule::table('mod_cloudflare_jobs')
                ->where('id', $job->id)
                ->where('status', 'pending')
                ->update($claimData);
            if ($claimed === 0) { continue; }

            $payload = json_decode($job->payload_json ?? '{}', true) ?: [];
            $type = $job->type;

            switch ($type) {
                case 'calibrate_all':
                    $stats = cfmod_job_calibrate_all($job, $payload) ?: [];
                    break;
                case 'auto_unban_due':
                    $stats = cfmod_job_auto_unban_due($job, $payload) ?: [];
                    break;
                case 'risk_scan_all':
                    $stats = cfmod_job_risk_scan_all($job, $payload) ?: [];
                    break;
                case 'cleanup_risk_events':
                    $stats = cfmod_job_cleanup_risk_events($job, $payload) ?: [];
                    break;
                case 'cleanup_expired_subdomains':
                    $stats = cfmod_job_cleanup_expired_subdomains($job, $payload) ?: [];
                    break;
                case 'cleanup_api_logs':
                    $stats = cfmod_job_cleanup_api_logs($job, $payload) ?: [];
                    break;
                case 'cleanup_general_logs':
                    $stats = cfmod_job_cleanup_general_logs($job, $payload) ?: [];
                    break;
                case 'cleanup_sync_logs':
                    $stats = cfmod_job_cleanup_sync_logs($job, $payload) ?: [];
                    break;
                case 'cleanup_user_subdomains':
                    $stats = cfmod_job_cleanup_user_subdomains($job, $payload) ?: [];
                    break;
                case 'cleanup_domain_gifts':
                    $stats = cfmod_job_cleanup_domain_gifts($job, $payload) ?: [];
                    break;
                case 'cleanup_orphan_dns':
                    $stats = cfmod_job_cleanup_orphan_dns($job, $payload) ?: [];
                    break;
                case 'replace_root_domain':
                    $stats = cfmod_job_replace_root($job, $payload) ?: [];
                    break;
                case 'transfer_root_provider':
                    $stats = cfmod_job_transfer_root_provider($job, $payload) ?: [];
                    break;
                case 'purge_root_local':
                    $stats = cfmod_job_purge_root_local($job, $payload) ?: [];
                    break;
                case 'reconcile_all':
                    $stats = cfmod_job_reconcile_all($job, $payload) ?: [];
                    break;
                case 'enforce_ban_dns':
                    $stats = cfmod_job_enforce_ban_dns($job, $payload) ?: [];
                    break;
                case 'client_dns_operation':
                    $stats = cfmod_job_client_dns_operation($job, $payload) ?: [];
                    break;
                default:
                    throw new \RuntimeException('Unknown job type: ' . $type);
            }


            $summary = cfmod_build_stats_summary($stats);
            $finishedAt = date('Y-m-d H:i:s');
            $durationSeconds = (int) max(0, round(microtime(true) - $jobStartMicro));

            $updateData = [
                'status' => 'done',
                'next_run_at' => null,
                'updated_at' => $finishedAt,
                'last_error' => substr($summary, 0, 1000),
            ];
            if ($metricsSupported) {
                $updateData['finished_at'] = $finishedAt;
                $updateData['duration_seconds'] = $durationSeconds;
                $updateData['stats_json'] = !empty($stats) ? json_encode($stats, JSON_UNESCAPED_UNICODE) : null;
            }
            Capsule::table('mod_cloudflare_jobs')->where('id', $job->id)->update($updateData);
        } catch (\Throwable $e) {
            $durationSeconds = (int) max(0, round(microtime(true) - $jobStartMicro));
            $attempts = ($job->attempts ?? 0) + 1;
            $backoffMinutes = min(60, pow(2, min(6, $attempts - 1))); // 1,2,4,8,16,32,64->cap 60
            $nextRunAt = ($attempts >= 5) ? null : date('Y-m-d H:i:s', time() + $backoffMinutes * 60);
            $updateData = [
                'status' => ($attempts >= 5 ? 'failed' : 'pending'),
                'next_run_at' => $nextRunAt,
                'last_error' => substr($e->getMessage(), 0, 1000),
                'updated_at' => date('Y-m-d H:i:s'),
                'attempts' => $attempts,
            ];
            if ($metricsSupported) {
                $updateData['finished_at'] = date('Y-m-d H:i:s');
                $updateData['duration_seconds'] = $durationSeconds;
                $updateData['stats_json'] = null;
            }
            Capsule::table('mod_cloudflare_jobs')->where('id', $job->id)->update($updateData);
            cfmod_report_exception('job_' . ($job->type ?? 'unknown'), $e);
        }
    }
}

function cfmod_job_calibrate_all($job, array $payload): array {
    $jobId = intval($job->id);
    $settings = cfmod_get_settings();
    $mode = ($payload['mode'] ?? 'dry') === 'fix' ? 'fix' : 'dry';
    $payloadBatch = intval($payload['batch_size'] ?? 0);
    if ($payloadBatch > 0) {
        $batchSize = $payloadBatch;
    } else {
        $configBatch = intval($settings['calibration_batch_size'] ?? 150);
        if ($configBatch <= 0) { $configBatch = 150; }
        $batchSize = $configBatch;
    }
    $batchSize = max(50, min(500, $batchSize));
    $cursor = intval($payload['cursor_id'] ?? 0);
    $targetRoot = strtolower(trim((string) ($payload['rootdomain'] ?? '')));

    $subsQuery = Capsule::table('mod_cloudflare_subdomain')
        ->orderBy('id', 'asc');
    if ($cursor > 0) {
        $subsQuery->where('id', '>', $cursor);
    }
    if ($targetRoot !== '') {
        $subsQuery->whereRaw('LOWER(rootdomain) = ?', [$targetRoot]);
    }
    $subsCollection = $subsQuery
        ->limit($batchSize + 1)
        ->get();

    if (!($subsCollection instanceof \Illuminate\Support\Collection)) {
        $subsCollection = new \Illuminate\Support\Collection(is_array($subsCollection) ? $subsCollection : (array) $subsCollection);
    }

    if ($subsCollection->count() === 0) {
        $emptyStats = [
            'mode' => $mode,
            'batch_size' => $batchSize,
            'cursor_start' => $cursor,
            'processed_subdomains' => 0,
            'differences_total' => 0,
            'warnings' => ['no_subdomains']
        ];
        if ($targetRoot !== '') {
            $emptyStats['rootdomain'] = $targetRoot;
        }
        return $emptyStats;
    }

    $hasMore = $subsCollection->count() > $batchSize;
    $subs = $hasMore ? $subsCollection->slice(0, $batchSize)->values() : $subsCollection->values();

    $priority = strtolower($settings['sync_authoritative_source'] ?? 'local');
    if (!in_array($priority, ['local', 'aliyun'], true)) { $priority = 'local'; }

    $stats = [
        'mode' => $mode,
        'batch_size' => $batchSize,
        'cursor_start' => $cursor,
        'processed_subdomains' => 0,
        'processed_records' => 0,
        'differences_total' => 0,
        'difference_breakdown' => [],
        'action_breakdown' => [],
        'warnings' => [],
        'priority' => $priority,
    ];
    if ($targetRoot !== '') {
        $stats['rootdomain'] = $targetRoot;
    }

    $providerClients = [];
    $groupedSubs = [];
    foreach ($subs as $s) {
        $stats['processed_subdomains']++;
        $providerId = cfmod_worker_resolve_provider_account_id_for_subdomain($s, $settings);
        $groupKey = $providerId ?: 0;
        if (!isset($groupedSubs[$groupKey])) {
            $groupedSubs[$groupKey] = [];
        }
        $groupedSubs[$groupKey][] = $s;
    }

    foreach ($groupedSubs as $providerKey => $groupSubs) {
        $providerAccountId = $providerKey ?: null;
        $providerContext = cfmod_worker_acquire_provider_client_cached($providerAccountId, $settings, $providerClients, $stats, 'calibrate');
        if (!$providerContext) {
            foreach ($groupSubs as $failedSub) {
                $stats['warnings'][] = 'calibrate_provider_missing_sub:' . $failedSub->id;
            }
            continue;
        }
        $cf = $providerContext['client'];
        $zoneCache = [];

        foreach ($groupSubs as $s) {
            $zoneId = $s->cloudflare_zone_id ?: ($s->rootdomain ?? null);
            if (!$zoneId) {
                $stats['warnings'][] = 'missing_zone:' . $s->id;
                continue;
            }

            try {
                cfmod_calibrate_subdomain($jobId, $mode, $cf, $s, $zoneCache, $zoneId, $stats, $priority);
            } catch (\Throwable $e) {
                $stats['warnings'][] = 'calibrate_error:' . $s->id;
                cfmod_report_exception('calibrate_subdomain', $e);
            }
        }
    }

    $lastProcessedId = $subs->last()->id ?? $cursor;

    if ($hasMore && $lastProcessedId) {
        $newPayload = $payload;
        $newPayload['cursor_id'] = $lastProcessedId;
        $newPayload['batch_size'] = $batchSize;
        $newPayload['mode'] = $mode;
        $newPayload['origin_job_id'] = $payload['origin_job_id'] ?? $jobId;
        if ($targetRoot !== '') {
            $newPayload['rootdomain'] = $targetRoot;
        }

        try {
            $continuationId = Capsule::table('mod_cloudflare_jobs')->insertGetId([
                'type' => 'calibrate_all',
                'payload_json' => json_encode($newPayload, JSON_UNESCAPED_UNICODE),
                'priority' => intval($job->priority ?? 10),
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ]);
            $stats['has_more'] = true;
            $stats['next_cursor'] = $lastProcessedId;
            $stats['continuation_job_id'] = $continuationId;
        } catch (\Throwable $e) {
            $stats['has_more'] = true;
            $stats['warnings'][] = 'enqueue_failed:' . $lastProcessedId;
            cfmod_report_exception('calibrate_enqueue', $e);
        }
    } else {
        $stats['has_more'] = false;
    }

    return $stats;
}

/**
 * @param CloudflareAPI|DNSPodLegacyAPI|DNSPodIntlAPI|mixed $cf
 */
function cfmod_calibrate_subdomain(int $jobId, string $mode, $cf, $sub, array &$zoneCache, string $zoneId, array &$stats, string $priority): void {
    if (!is_object($cf) || !method_exists($cf, 'getDnsRecords')) {
        throw new \InvalidArgumentException('calibrate_subdomain requires a provider client supporting getDnsRecords');
    }
    $nameSub = strtolower($sub->subdomain);
    $locals = Capsule::table('mod_cloudflare_dns_records')->where('subdomain_id', $sub->id)->get();
    $stats['processed_records'] = ($stats['processed_records'] ?? 0) + count($locals);

    $localMap = [];
    foreach ($locals as $lr) {
        $n = strtolower($lr->name);
        $t = strtoupper($lr->type);
        $localMap[$n][$t][] = $lr;
    }

    $remoteIndex = cfmod_worker_build_remote_index_for_subdomain($cf, $zoneId, $sub, $locals, $zoneCache, $stats);

    foreach ($locals as $lr) {
        $normalizedTtl = cfmod_normalize_ttl($lr->ttl ?? 600);
        if (!isset($lr->ttl) || intval($lr->ttl) !== $normalizedTtl) {
            Capsule::table('mod_cloudflare_dns_records')
                ->where('id', $lr->id)
                ->update([
                    'ttl' => $normalizedTtl,
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
        }
        $lr->ttl = $normalizedTtl;

        $n = strtolower($lr->name);
        $t = strtoupper($lr->type);
        $cfList = $remoteIndex[$n][$t] ?? [];
        $matched = null;
        foreach ($cfList as $cr) {
            if (($cr['content'] ?? '') === $lr->content) {
                $matched = $cr;
                break;
            }
        }
        if (!$matched) {
            $action = 'noop';
            if ($mode === 'fix') {
                $res = $cf->createDnsRecord($zoneId, $lr->name, $t, $lr->content, $lr->ttl, boolval($lr->proxied));
                if ($res['success'] ?? false) {
                    $action = 'created_on_cf';
                    $newId = $res['result']['id'] ?? null;
                    Capsule::table('mod_cloudflare_dns_records')->where('id', $lr->id)->update([
                        'record_id' => $newId,
                        'updated_at' => date('Y-m-d H:i:s')
                    ]);
                    if (isset($res['result'])) {
                        $remoteIndex[strtolower($lr->name)][strtoupper($t)][] = $res['result'];
                    }
                }
            }
            cfmod_sync_result($jobId, $sub->id, 'missing_on_cf', $action, [
                'name' => $lr->name,
                'type' => $t,
                'content' => $lr->content
            ]);
            cfmod_track_sync_stat($stats, 'missing_on_cf', $action);
            continue;
        }

        $needUpdate = false;
        $update = [];
        if (intval($matched['ttl'] ?? 0) !== $lr->ttl) {
            $needUpdate = true;
            $update['ttl'] = $lr->ttl;
        }
        if ($needUpdate) {
            $action = 'noop';
            if ($mode === 'fix') {
                $res = $cf->updateDnsRecord($zoneId, $matched['id'], array_merge([
                    'type' => $t,
                    'content' => $lr->content,
                    'name' => $lr->name
                ], $update));
                if ($res['success'] ?? false) {
                    $action = 'updated_on_cf';
                }
            }
            cfmod_sync_result($jobId, $sub->id, 'mismatch', $action, [
                'name' => $lr->name,
                'type' => $t,
                'from' => ['ttl' => ($matched['ttl'] ?? null)],
                'to' => $update
            ]);
            cfmod_track_sync_stat($stats, 'mismatch', $action);
        }
    }

    foreach ($remoteIndex as $n => $typeToList) {
        if (!($n === $nameSub || cf_str_ends_with($n, '.' . $nameSub))) {
            continue;
        }
        foreach ($typeToList as $t => $list) {
            foreach ($list as $idx => $cr) {
                $hasLocal = !empty(($localMap[$n][$t] ?? []));
                if ($hasLocal) {
                    continue;
                }

                $action = 'noop';
                if ($priority === 'local') {
                    if ($mode === 'fix' && !empty($cr['id'])) {
                        $res = $cf->deleteSubdomain($zoneId, $cr['id']);
                        if ($res['success'] ?? false) {
                            $action = 'deleted_on_cf';
                            unset($remoteIndex[$n][$t][$idx]);
                            $remoteIndex[$n][$t] = array_values($remoteIndex[$n][$t]);
                        } else {
                            $action = 'delete_failed';
                            $stats['warnings'][] = 'delete_failed:' . ($cr['id'] ?? '');
                        }
                    }
                    cfmod_sync_result($jobId, $sub->id, 'extra_on_cf', $action, [
                        'name' => $n,
                        'type' => $t,
                        'content' => ($cr['content'] ?? ''),
                        'record_id' => ($cr['id'] ?? null)
                    ]);
                    cfmod_track_sync_stat($stats, 'extra_on_cf', $action);
                    continue;
                }

                if ($mode === 'fix') {
                    try {
                        Capsule::table('mod_cloudflare_dns_records')->insert([
                            'subdomain_id' => $sub->id,
                            'zone_id' => $zoneId,
                            'record_id' => ($cr['id'] ?? null),
                            'name' => $n,
                            'type' => $t,
                            'content' => ($cr['content'] ?? ''),
                            'ttl' => intval($cr['ttl'] ?? 600),
                            'proxied' => 0,
                            'status' => 'active',
                            'priority' => null,
                            'line' => null,
                            'created_at' => date('Y-m-d H:i:s'),
                            'updated_at' => date('Y-m-d H:i:s')
                        ]);
                        CfSubdomainService::markHasDnsHistory($sub->id);
                        $action = 'imported_local';
                    } catch (\Throwable $e) {
                        cfmod_report_exception('calibrate_import', $e);
                    }
                }

                cfmod_sync_result($jobId, $sub->id, 'extra_on_cf', $action, [
                    'name' => $n,
                    'type' => $t,
                    'content' => ($cr['content'] ?? '')
                ]);
                cfmod_track_sync_stat($stats, 'extra_on_cf', $action);
            }
        }
    }
}

/**
 * @param CloudflareAPI|DNSPodLegacyAPI|DNSPodIntlAPI|mixed $cf
 */
function cfmod_worker_build_remote_index_for_subdomain($cf, string $zoneId, $sub, $locals, array &$zoneCache, array &$stats): array {
    $nameSub = strtolower($sub->subdomain ?? '');
    $names = [$nameSub];
    foreach ($locals as $lr) {
        $candidate = strtolower($lr->name ?? '');
        if ($candidate !== '' && !in_array($candidate, $names, true)) {
            $names[] = $candidate;
        }
    }
    $index = [];
    foreach ($names as $name) {
        if ($name === '') {
            continue;
        }
        $records = cfmod_worker_fetch_remote_records_by_name($cf, $zoneId, $name, $zoneCache, $stats);
        foreach ($records as $rec) {
            $recordName = strtolower($rec['name'] ?? $name);
            $recordType = strtoupper($rec['type'] ?? '');
            if ($recordName === '' || $recordType === '') {
                continue;
            }
            $index[$recordName][$recordType][] = $rec;
        }
    }
    return $index;
}

/**
 * @param CloudflareAPI|DNSPodLegacyAPI|DNSPodIntlAPI|mixed $cf
 */
function cfmod_worker_fetch_remote_records_by_name($cf, string $zoneId, string $name, array &$zoneCache, array &$stats): array {
    $cacheKey = strtolower($zoneId);
    if (!isset($zoneCache[$cacheKey])) {
        $zoneCache[$cacheKey] = [];
    }
    $nameKey = strtolower($name);
    if (!array_key_exists($nameKey, $zoneCache[$cacheKey])) {
        $res = $cf->getDnsRecords($zoneId, $name, ['per_page' => 500]);
        if (!($res['success'] ?? false)) {
            $stats['warnings'][] = 'fetch_failed:' . $zoneId . ':' . $name;
            $zoneCache[$cacheKey][$nameKey] = [];
        } else {
            $zoneCache[$cacheKey][$nameKey] = $res['result'] ?? [];
        }
    }
    return $zoneCache[$cacheKey][$nameKey];
}

function cfmod_sync_result(int $jobId, ?int $subId, string $kind, string $action, array $detail): void {
    try {
        Capsule::table('mod_cloudflare_sync_results')->insert([
            'job_id' => $jobId,
            'subdomain_id' => $subId,
            'kind' => $kind,
            'action' => $action,
            'detail' => json_encode($detail, JSON_UNESCAPED_UNICODE),
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s')
        ]);
    } catch (\Exception $e) {}
}

function cfmod_job_auto_unban_due($job, array $payload = []): array {
    $jobId = intval($job->id);
    $now = date('Y-m-d H:i:s');
    $due = Capsule::table('mod_cloudflare_user_bans')
        ->where('status','banned')
        ->whereNotNull('ban_expires_at')
        ->where('ban_expires_at','<=',$now)
        ->get();

    $stats = [
        'unbanned' => 0,
        'warnings' => [],
        'processed_subdomains' => 0,
    ];

    foreach ($due as $b) {
        try {
            Capsule::table('mod_cloudflare_user_bans')->where('id', $b->id)->update([
                'status' => 'unbanned',
                'unbanned_at' => $now,
                'updated_at' => $now
            ]);
            Capsule::table('tblclients')->where('id', $b->userid)->update(['status' => 'Active']);
            $stats['unbanned']++;
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('auto_unban_user', ['userid' => $b->userid, 'ban_id' => $b->id]);
            }
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'user:' . $b->userid;
            cfmod_report_exception('auto_unban_due', $e);
        }
    }

    $stats['processed_subdomains'] = count($due);
    if (empty($due)) {
        $stats['message'] = 'no bans to lift';
    }
    return $stats;
}

function cfmod_job_risk_scan_all($job, array $payload = []): array {
    $jobId = intval($job->id);
    $settings = cfmod_get_settings();
    $endpoint = trim($settings['risk_api_endpoint'] ?? '');
    $apiKey = trim($settings['risk_api_key'] ?? '');
    if ($endpoint === '') {
        throw new \RuntimeException('risk_api_endpoint not configured');
    }
    $client = new ExternalRiskAPI($endpoint, $apiKey !== '' ? $apiKey : null);

    $stats = [
        'scanned' => 0,
        'high_risk' => 0,
        'warnings' => [],
    ];

    $batchSize = intval($payload['batch_size'] ?? ($settings['risk_scan_batch_size'] ?? 50));
    if ($batchSize <= 0) {
        $batchSize = 50;
    }
    $batchSize = max(10, min(1000, $batchSize));
    $cursor = intval($payload['cursor_id'] ?? 0);

    $now = date('Y-m-d H:i:s');
    $auto = $settings['risk_auto_action'] ?? 'none';
    $threshold = max(0, min(100, intval($settings['risk_auto_threshold'] ?? 80)));

    $kwRaw = (string)($settings['risk_keywords'] ?? '');
    $keywords = [];
    if ($kwRaw !== '') {
        $parts = preg_split('/[，,]+/u', $kwRaw);
        $parts = array_map('trim', $parts ?: []);
        foreach ($parts as $p) {
            if ($p !== '') {
                $keywords[] = $p;
            }
        }
    }

    $includeRecords = (($settings['risk_include_records'] ?? 'off') === 'on' || ($settings['risk_include_records'] ?? '0') == '1');
    $recordTypesRaw = (string)($settings['risk_record_types'] ?? 'A,CNAME');
    $typeSet = [];
    foreach (array_map('trim', explode(',', $recordTypesRaw)) as $t) {
        if ($t !== '') {
            $typeSet[strtoupper($t)] = true;
        }
    }
    $recordLimit = max(0, intval($settings['risk_record_limit'] ?? 10));
    $parallel = intval($settings['risk_parallel_requests'] ?? 5);
    $parallel = max(1, min(10, $parallel));

    $subs = Capsule::table('mod_cloudflare_subdomain')
        ->where('id', '>', $cursor)
        ->orderBy('id', 'asc')
        ->limit($batchSize)
        ->get();
    $subsArray = cfmod_iterable_to_array($subs);
    if (empty($subsArray)) {
        $stats['processed_subdomains'] = 0;
        $stats['cursor_start'] = $cursor;
        $stats['message'] = $cursor > 0 ? 'scan_completed' : 'no_subdomains';
        return $stats;
    }

    $nextCursor = 0;
    $subdomainIds = [];
    foreach ($subsArray as $row) {
        $sid = is_object($row) ? (int) ($row->id ?? 0) : (int) ($row['id'] ?? 0);
        if ($sid > 0) {
            $subdomainIds[] = $sid;
            $nextCursor = $sid;
        }
    }

    $allRecords = [];
    if (!empty($subdomainIds) && $includeRecords) {
        $recordsQuery = Capsule::table('mod_cloudflare_dns_records')
            ->whereIn('subdomain_id', $subdomainIds)
            ->orderBy('subdomain_id', 'asc')
            ->orderBy('id', 'asc')
            ->get();
        foreach ($recordsQuery as $r) {
            if (!isset($allRecords[$r->subdomain_id])) {
                $allRecords[$r->subdomain_id] = [];
            }
            $allRecords[$r->subdomain_id][] = $r;
        }
    }

    $requests = [];
    $metas = [];
    foreach ($subsArray as $s) {
        $rowObj = is_object($s) ? $s : (object) $s;
        $name = strtolower($rowObj->subdomain ?? '');
        if ($name === '') {
            $stats['warnings'][] = 'sub_missing_name:' . ($rowObj->id ?? '');
            continue;
        }
        $extras = [];
        if (!empty($keywords)) {
            $extras['keywords'] = $keywords;
        }
        if ($includeRecords) {
            $targets = [];
            $records = $allRecords[$rowObj->id] ?? [];
            foreach ($records as $r) {
                $rt = strtoupper($r->type ?? '');
                if (!isset($typeSet[$rt])) {
                    continue;
                }
                $host = strtolower($r->name ?? '');
                if ($host !== '' && $host !== $name) {
                    $targets[] = $host;
                }
                if ($recordLimit > 0 && count($targets) >= $recordLimit) {
                    break;
                }
            }
            if (!empty($targets)) {
                $extras['targets'] = array_values(array_unique($targets));
            }
        }
        $requests[] = ['subdomain' => $name, 'extras' => $extras];
        $metas[] = ['sub' => $rowObj, 'name' => $name];
    }

    if (!empty($requests)) {
        if ($parallel === 1 || count($requests) === 1) {
            $responses = [];
            foreach ($requests as $req) {
                $responses[] = $client->scanSubdomain($req['subdomain'], $req['extras']);
            }
        } else {
            $responses = $client->scanBatch($requests, $parallel);
        }

        foreach ($metas as $idx => $meta) {
            $s = $meta['sub'];
            $response = $responses[$idx] ?? ['success' => false, 'errors' => ['missing_response' => true]];
            try {
                if (!is_array($response)) {
                    throw new \RuntimeException('invalid response');
                }
                $ok = (bool)($response['success'] ?? false);
                $data = $response['result'] ?? $response['data'] ?? [];
                if (!$ok || !is_array($data)) {
                    throw new \RuntimeException('scan failed');
                }

                $riskScore = max(0, min(100, intval($data['risk_score'] ?? 0)));
                $riskLevel = (string)($data['risk_level'] ?? ($riskScore >= $threshold ? 'high' : 'low'));
                $reasons = is_array($data['reasons'] ?? null) ? ($data['reasons'] ?? []) : [];
                $events = is_array($data['events'] ?? null) ? ($data['events'] ?? []) : [];

                $stats['scanned']++;
                if ($riskLevel === 'high' || $riskScore >= $threshold) {
                    $stats['high_risk']++;
                }

                $reasonsJson = json_encode($reasons, JSON_UNESCAPED_UNICODE);
                $exists = Capsule::table('mod_cloudflare_domain_risk')->where('subdomain_id', $s->id)->first();
                if ($exists) {
                    Capsule::table('mod_cloudflare_domain_risk')->where('subdomain_id', $s->id)->update([
                        'risk_score' => $riskScore,
                        'risk_level' => $riskLevel,
                        'reasons_json' => $reasonsJson,
                        'last_checked_at' => $now,
                        'updated_at' => $now,
                    ]);
                } else {
                    Capsule::table('mod_cloudflare_domain_risk')->insert([
                        'subdomain_id' => $s->id,
                        'risk_score' => $riskScore,
                        'risk_level' => $riskLevel,
                        'reasons_json' => $reasonsJson,
                        'last_checked_at' => $now,
                        'created_at' => $now,
                        'updated_at' => $now,
                    ]);
                }

                $highRiskEvents = [];
                foreach ($events as $ev) {
                    $lvl = strtolower(trim((string)($ev['level'] ?? 'low')));
                    $score = intval($ev['score'] ?? 0);
                    if ($lvl === 'high' || $score >= $threshold) {
                        $src = substr(trim((string)($ev['source'] ?? 'external')), 0, 32);
                        $reason = substr(trim((string)($ev['reason'] ?? '')), 0, 255);
                        $detailsJson = json_encode($ev['details'] ?? [], JSON_UNESCAPED_UNICODE);
                        $highRiskEvents[] = [
                            'subdomain_id' => $s->id,
                            'source' => $src,
                            'score' => $score,
                            'level' => 'high',
                            'reason' => $reason,
                            'details_json' => $detailsJson,
                            'created_at' => $now,
                            'updated_at' => $now,
                        ];
                    }
                }

                if (!empty($highRiskEvents)) {
                    Capsule::table('mod_cloudflare_risk_events')->insert($highRiskEvents);
                }

                if ($riskLevel === 'high' || $riskScore >= $threshold) {
                    $todaySummary = Capsule::table('mod_cloudflare_risk_events')
                        ->where('subdomain_id', $s->id)
                        ->where('source', 'summary')
                        ->whereRaw('DATE(created_at) = CURDATE()')
                        ->first();
                    if (!$todaySummary) {
                        try {
                            Capsule::table('mod_cloudflare_risk_events')->insert([
                                'subdomain_id' => $s->id,
                                'source' => 'summary',
                                'score' => $riskScore,
                                'level' => 'high',
                                'reason' => 'scan summary',
                                'details_json' => json_encode([
                                    'events_count' => count($highRiskEvents),
                                    'total_events' => count($events),
                                    'reasons_count' => count($reasons),
                                    'last_checked_at' => $now,
                                ], JSON_UNESCAPED_UNICODE),
                                'created_at' => $now,
                                'updated_at' => $now,
                            ]);
                        } catch (\Throwable $e) {}
                    }
                }

                $acted = false;
                if ($auto === 'suspend' && $riskScore >= $threshold) {
                    Capsule::table('mod_cloudflare_subdomain')->where('id', $s->id)->update([
                        'status' => 'suspended',
                        'updated_at' => $now,
                    ]);
                    $acted = true;
                }

                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('risk_scan', [
                        'subdomain' => $meta['name'],
                        'score' => $riskScore,
                        'level' => $riskLevel,
                        'auto_action' => ($acted ? 'suspend' : 'none'),
                    ], intval($s->userid ?? 0), $s->id);
                }
            } catch (\Throwable $e) {
                error_log("Risk scan error for subdomain {$s->subdomain}: " . $e->getMessage());
                $stats['warnings'][] = 'sub:' . ($s->id ?? '');
                cfmod_report_exception('risk_scan', $e);
            }
        }
    }

    $processedCount = count($subsArray);
    $stats['processed_subdomains'] = $processedCount;
    $stats['cursor_start'] = $cursor;
    $stats['cursor_end'] = $nextCursor;
    $stats['message'] = 'scanned ' . $processedCount . ' domains';

    if ($processedCount === $batchSize && $nextCursor > 0) {
        $stats['has_more'] = true;
        try {
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'risk_scan_all',
                'payload_json' => json_encode([
                    'cursor_id' => $nextCursor,
                    'batch_size' => $batchSize,
                    'auto' => !empty($payload['auto'])
                ], JSON_UNESCAPED_UNICODE),
                'priority' => intval($job->priority ?? 20),
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => $now,
                'updated_at' => $now
            ]);
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'requeue_failed';
            cfmod_report_exception('risk_scan_requeue', $e);
        }
        $stats['message'] .= ' (continuation queued)';
    }

    return $stats;
}

function cfmod_job_replace_root($job, array $payload = []): array {
    $jobId = intval($job->id ?? 0);
    $fromRoot = trim((string)($payload['from_root'] ?? ''));
    $toRoot = trim((string)($payload['to_root'] ?? ''));
    $deleteOld = !!($payload['delete_old'] ?? false);
    if ($fromRoot === '' || $toRoot === '' || $fromRoot === $toRoot) { throw new \InvalidArgumentException('invalid root domains'); }

    $batchSize = intval($payload['batch_size'] ?? 200);
    if ($batchSize <= 0) { $batchSize = 200; }
    $batchSize = max(25, min(500, $batchSize));
    $cursor = intval($payload['cursor_id'] ?? 0);

    $settings = cfmod_get_settings();
    $targetProviderContext = cfmod_acquire_provider_client_for_rootdomain($toRoot, $settings);
    if (!$targetProviderContext || empty($targetProviderContext['client'])) {
        throw new \RuntimeException('No active provider account available for target root');
    }
    $targetCf = $targetProviderContext['client'];

    $toZone = $targetCf->getZoneId($toRoot);
    if (!$toZone) { throw new \RuntimeException('new root zone not found: '.$toRoot); }

    $stats = [
        'processed_subdomains' => 0,
        'records_updated_on_cf' => 0,
        'records_updated_local' => 0,
        'records_imported_local' => 0,
        'warnings' => [],
        'batch_size' => $batchSize,
        'cursor_start' => $cursor,
    ];

    $fromLo = strtolower($fromRoot);
    $subsQuery = Capsule::table('mod_cloudflare_subdomain')
        ->where(function($outer) use ($fromLo) {
            $outer->whereRaw('LOWER(rootdomain) = ?', [$fromLo])
                  ->orWhere(function($inner) use ($fromLo) {
                      $inner->whereRaw('LOWER(subdomain) = ?', [$fromLo])
                            ->orWhereRaw('LOWER(subdomain) LIKE ?', ['%.' . $fromLo]);
                  });
        })
        ->orderBy('id','asc');
    if ($cursor > 0) {
        $subsQuery->where('id', '>', $cursor);
    }
    $subsRaw = $subsQuery->limit($batchSize + 1)->get();
    if (!($subsRaw instanceof \Illuminate\Support\Collection)) {
        $subsRaw = new \Illuminate\Support\Collection(is_array($subsRaw) ? $subsRaw : (array) $subsRaw);
    }
    if ($subsRaw->count() === 0) {
        $stats['cursor_end'] = $cursor;
        $stats['message'] = 'no subdomains matched ' . $fromRoot . ($cursor > 0 ? ' after cursor ' . $cursor : '');
        return $stats;
    }

    $hasMore = $subsRaw->count() > $batchSize;
    $batch = $hasMore ? $subsRaw->slice(0, $batchSize)->values() : $subsRaw->values();

    $subdomainIds = [];
    $lastId = $cursor;
    foreach ($batch as $row) {
        $sid = intval($row->id ?? 0);
        if ($sid > 0) {
            $subdomainIds[] = $sid;
            $lastId = $sid;
        }
    }
    if (empty($subdomainIds)) {
        $stats['cursor_end'] = $cursor;
        $stats['message'] = 'no subdomain IDs resolved for ' . $fromRoot;
        return $stats;
    }

    $allLocalRecords = [];
    try {
        $localRecords = Capsule::table('mod_cloudflare_dns_records')
            ->whereIn('subdomain_id', $subdomainIds)
            ->orderBy('subdomain_id', 'asc')
            ->orderBy('id', 'asc')
            ->get();
        foreach ($localRecords as $r) {
            if (!isset($allLocalRecords[$r->subdomain_id])) {
                $allLocalRecords[$r->subdomain_id] = [];
            }
            $allLocalRecords[$r->subdomain_id][] = $r;
        }
    } catch (\Throwable $e) {
        cfmod_report_exception('replace_root_local_records', $e);
    }

    $providerClients = [];
    $now = date('Y-m-d H:i:s');
    foreach ($batch as $s) {
        try {
            $stats['processed_subdomains']++;
            $oldFull = strtolower($s->subdomain);
            if (cf_str_ends_with($oldFull, '.' . strtolower($fromRoot))) {
                $prefix = substr($oldFull, 0, - (strlen($fromRoot) + 1));
                $newFull = ($prefix !== '' ? ($prefix . '.') : '') . $toRoot;
            } elseif ($oldFull === strtolower($fromRoot)) {
                $newFull = $toRoot;
            } else {
                $newFull = str_ireplace($fromRoot, $toRoot, $oldFull);
            }

            $sourceProviderId = cfmod_worker_resolve_provider_account_id_for_subdomain($s, $settings);
            $sourceContext = cfmod_worker_acquire_provider_client_cached($sourceProviderId, $settings, $providerClients, $stats, 'replace_root_source');
            if (!$sourceContext) {
                $stats['warnings'][] = 'source_provider_missing:' . $s->id;
                continue;
            }
            $sourceCf = $sourceContext['client'];

            $local = $allLocalRecords[$s->id] ?? [];
            $records = [];
            if (count($local) > 0) {
                foreach ($local as $r) {
                    $records[] = [
                        'id' => $r->id,
                        'name' => strtolower($r->name ?? ''),
                        'record_id' => $r->record_id,
                        'type' => strtoupper($r->type ?? ''),
                        'content' => $r->content ?? '',
                        'ttl' => intval($r->ttl ?? 600),
                        'priority' => isset($r->priority) ? intval($r->priority) : null,
                    ];
                }
            } else {
                $remote = $sourceCf->getDnsRecords($s->cloudflare_zone_id ?: $fromRoot, $oldFull, ['per_page' => 500]);
                if (($remote['success'] ?? false)) {
                    foreach (($remote['result'] ?? []) as $rr) {
                        $records[] = [
                            'id' => null,
                            'name' => strtolower($rr['name'] ?? ''),
                            'record_id' => $rr['id'] ?? null,
                            'type' => strtoupper($rr['type'] ?? ''),
                            'content' => $rr['content'] ?? '',
                            'ttl' => intval($rr['ttl'] ?? 600),
                            'priority' => null,
                        ];
                    }
                }
            }

            $dnsRowsToUpdate = [];
            $primaryRecordId = null;
            foreach ($records as $rec) {
                $oldName = $rec['name'];
                if (cf_str_ends_with($oldName, '.' . strtolower($fromRoot))) {
                    $prefix = substr($oldName, 0, - (strlen($fromRoot) + 1));
                    $newName = ($prefix !== '' ? ($prefix . '.') : '') . $toRoot;
                } elseif ($oldName === strtolower($fromRoot)) {
                    $newName = $toRoot;
                } else {
                    $newName = str_ireplace($fromRoot, $toRoot, $oldName);
                }

                $createdId = null;
                $res = $targetCf->createDnsRecord($toZone, $newName, $rec['type'], $rec['content'], $rec['ttl'] ?: 600, false);
                if (!($res['success'] ?? false)) {
                    $existing = $targetCf->getDnsRecords($toZone, $newName, ['type' => $rec['type']]);
                    if (($existing['success'] ?? false) && !empty($existing['result'])) {
                        $existOne = $existing['result'][0];
                        $eid = $existOne['id'] ?? null;
                        if ($eid) {
                            $upd = $targetCf->updateDnsRecord($toZone, $eid, [
                                'type' => $rec['type'],
                                'name' => $newName,
                                'content' => $rec['content'],
                                'ttl' => $rec['ttl'] ?: 600,
                                'priority' => $rec['priority']
                            ]);
                            if (($upd['success'] ?? false)) { $createdId = $eid; }
                        }
                    }
                } else {
                    $createdId = $res['result']['RecordId'] ?? ($res['result']['id'] ?? null);
                    if ($rec['type'] === 'MX' && $rec['priority'] !== null && $createdId) {
                        $targetCf->updateDnsRecord($toZone, $createdId, [
                            'type' => 'MX',
                            'name' => $newName,
                            'content' => $rec['content'],
                            'ttl' => $rec['ttl'] ?: 600,
                            'priority' => $rec['priority']
                        ]);
                    }
                }

                if ($createdId) {
                    $dnsRowsToUpdate[] = [ 'local_id' => $rec['id'], 'new_name' => $newName, 'new_record_id' => $createdId ];
                    if ($newName === $newFull) { $primaryRecordId = $createdId; }
                }
            }

            foreach ($dnsRowsToUpdate as $u) {
                if ($u['local_id']) {
                    Capsule::table('mod_cloudflare_dns_records')->where('id', $u['local_id'])->update([
                        'name' => strtolower($u['new_name']),
                        'zone_id' => $toZone,
                        'record_id' => $u['new_record_id'],
                        'updated_at' => $now,
                    ]);
                }
            }

            if ($deleteOld) {
                try { $sourceCf->deleteDomainRecordsDeep($s->cloudflare_zone_id ?: $fromRoot, $oldFull); } catch (\Throwable $e) {}
            }

            $upd = [ 'subdomain' => $newFull, 'rootdomain' => $toRoot, 'cloudflare_zone_id' => $toZone, 'updated_at' => $now ];
            if ($primaryRecordId) { $upd['dns_record_id'] = $primaryRecordId; }
            Capsule::table('mod_cloudflare_subdomain')->where('id', $s->id)->update($upd);

            try { Capsule::table('mod_cloudflare_forbidden_domains')->where('rootdomain', $fromRoot)->update(['rootdomain' => $toRoot]); } catch (\Throwable $e) {}

            try {
                $fresh = $targetCf->getDnsRecords($toZone, $newFull, ['per_page' => 1000]);
                if (($fresh['success'] ?? false)) {
                    foreach (($fresh['result'] ?? []) as $fr) {
                        $name = strtolower($fr['name'] ?? '');
                        $type = strtoupper($fr['type'] ?? '');
                        $content = (string)($fr['content'] ?? '');
                        $ttl = intval($fr['ttl'] ?? 600);
                        $rid = $fr['id'] ?? null;
                        $exists = Capsule::table('mod_cloudflare_dns_records')
                            ->where('subdomain_id', $s->id)
                            ->where('name', $name)
                            ->where('type', $type)
                            ->first();
                        if ($exists) {
                            Capsule::table('mod_cloudflare_dns_records')->where('id', $exists->id)->update([
                                'zone_id' => $toZone,
                                'record_id' => $rid,
                                'content' => $content,
                                'ttl' => $ttl,
                                'updated_at' => $now
                            ]);
                            $stats['records_updated_local']++;
                        } else {
                            Capsule::table('mod_cloudflare_dns_records')->insert([
                                'subdomain_id' => $s->id,
                                'zone_id' => $toZone,
                                'record_id' => $rid,
                                'name' => $name,
                                'type' => $type,
                                'content' => $content,
                                'ttl' => $ttl,
                                'proxied' => 0,
                                'priority' => null,
                                'line' => null,
                                'created_at' => $now,
                                'updated_at' => $now
                            ]);
                            CfSubdomainService::markHasDnsHistory($s->id);
                            $stats['records_imported_local']++;
                        }
                    }
                }
            } catch (\Throwable $e) {}

            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('job_replace_root_progress', [ 'from' => $fromRoot, 'to' => $toRoot, 'subdomain' => $oldFull, 'new' => $newFull ]);
            }
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'sub:' . $s->id;
            cfmod_report_exception('replace_root', $e);
        }
    }

    $stats['cursor_end'] = $lastId;
    $stats['message'] = 'replaced ' . $fromRoot . ' -> ' . $toRoot . ' (batch ' . $stats['processed_subdomains'] . ')';
    if ($hasMore && $lastId > 0) {
        $stats['has_more'] = true;
        try {
            $nextPayload = [
                'from_root' => $fromRoot,
                'to_root' => $toRoot,
                'delete_old' => $deleteOld,
                'batch_size' => $batchSize,
                'cursor_id' => $lastId,
            ];
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'replace_root_domain',
                'payload_json' => json_encode($nextPayload, JSON_UNESCAPED_UNICODE),
                'priority' => intval($job->priority ?? 5),
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => $now,
                'updated_at' => $now
            ]);
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'enqueue_failed';
            cfmod_report_exception('replace_root_enqueue', $e);
        }
    } else {
        $stats['has_more'] = false;
    }

    if (function_exists('cfmod_clear_rootdomain_limits_cache')) {
        cfmod_clear_rootdomain_limits_cache();
    }
    return $stats;
}

function cfmod_job_transfer_root_provider($job, array $payload = []): array {
    $rootdomain = strtolower(trim((string)($payload['rootdomain'] ?? '')));
    if ($rootdomain === '') {
        throw new \InvalidArgumentException('rootdomain required');
    }

    $targetProviderId = intval($payload['target_provider_id'] ?? 0);
    if ($targetProviderId <= 0) {
        throw new \InvalidArgumentException('target provider required');
    }

    $settings = cfmod_get_settings();
    $batchSize = intval($payload['batch_size'] ?? 200);
    if ($batchSize <= 0) { $batchSize = 200; }
    $batchSize = max(25, min(500, $batchSize));
    $cursor = intval($payload['cursor_id'] ?? 0);
    $deleteOld = !empty($payload['delete_old_records']);
    $autoResume = !empty($payload['auto_resume']);
    $resumeStatus = isset($payload['resume_status']) ? (string)$payload['resume_status'] : null;
    $targetZone = trim((string)($payload['target_zone_identifier'] ?? ''));
    $now = date('Y-m-d H:i:s');

    $targetContext = cfmod_make_provider_client($targetProviderId, $rootdomain, null, $settings, true);
    if (!$targetContext || empty($targetContext['client'])) {
        throw new \RuntimeException('target provider unavailable');
    }
    $targetCf = $targetContext['client'];
    if ($targetZone === '') {
        $targetZone = $targetCf->getZoneId($rootdomain);
        if (!$targetZone) {
            throw new \RuntimeException('target zone not found');
        }
    }

    $stats = [
        'rootdomain' => $rootdomain,
        'target_provider_id' => $targetProviderId,
        'batch_size' => $batchSize,
        'cursor_start' => $cursor,
        'processed_subdomains' => 0,
        'records_created_on_cf' => 0,
        'records_updated_on_cf' => 0,
        'records_deleted_on_cf' => 0,
        'records_updated_local' => 0,
        'records_imported_local' => 0,
        'warnings' => [],
    ];

    $subsQuery = Capsule::table('mod_cloudflare_subdomain')
        ->whereRaw('LOWER(rootdomain) = ?', [$rootdomain])
        ->orderBy('id', 'asc');
    if ($cursor > 0) {
        $subsQuery->where('id', '>', $cursor);
    }
    $subsRaw = $subsQuery->limit($batchSize + 1)->get();
    if (!($subsRaw instanceof \Illuminate\Support\Collection)) {
        $subsRaw = new \Illuminate\Support\Collection(is_array($subsRaw) ? $subsRaw : (array) $subsRaw);
    }

    $hasMore = $subsRaw->count() > $batchSize;
    $batch = $hasMore ? $subsRaw->slice(0, $batchSize)->values() : $subsRaw->values();
    $subdomainIds = [];
    $lastId = $cursor;
    foreach ($batch as $row) {
        $sid = intval($row->id ?? 0);
        if ($sid > 0) {
            $subdomainIds[] = $sid;
            $lastId = $sid;
        }
    }

    $allLocalRecords = [];
    if (!empty($subdomainIds)) {
        try {
            $localRecords = Capsule::table('mod_cloudflare_dns_records')
                ->whereIn('subdomain_id', $subdomainIds)
                ->orderBy('subdomain_id', 'asc')
                ->orderBy('id', 'asc')
                ->get();
            foreach ($localRecords as $record) {
                $sid = intval($record->subdomain_id ?? 0);
                if ($sid <= 0) {
                    continue;
                }
                if (!isset($allLocalRecords[$sid])) {
                    $allLocalRecords[$sid] = [];
                }
                $allLocalRecords[$sid][] = $record;
            }
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'load_local_records_failed';
            cfmod_report_exception('transfer_root_provider_local_records', $e);
        }
    }

    $providerClients = [];

    foreach ($batch as $s) {
        try {
            $sid = intval($s->id ?? 0);
            if ($sid <= 0) {
                continue;
            }
            $stats['processed_subdomains']++;
            $subdomainName = strtolower($s->subdomain ?? '');
            if ($subdomainName === '') {
                $stats['warnings'][] = 'missing_subdomain:' . $sid;
                continue;
            }

            $sourceProviderId = cfmod_worker_resolve_provider_account_id_for_subdomain($s, $settings);
            $sourceContext = null;
            $sourceCf = null;
            if ($sourceProviderId !== null) {
                $sourceContext = cfmod_worker_acquire_provider_client_cached($sourceProviderId, $settings, $providerClients, $stats, 'transfer_root_source');
                if ($sourceContext) {
                    $sourceCf = $sourceContext['client'] ?? null;
                }
            }

            $records = [];
            if (!empty($allLocalRecords[$sid])) {
                foreach ($allLocalRecords[$sid] as $recordRow) {
                    $records[] = [
                        'name' => strtolower($recordRow->name ?? $subdomainName),
                        'type' => strtoupper($recordRow->type ?? ''),
                        'content' => (string) ($recordRow->content ?? ''),
                        'ttl' => intval($recordRow->ttl ?? 600),
                        'priority' => isset($recordRow->priority) ? intval($recordRow->priority) : null,
                    ];
                }
            } elseif ($sourceCf) {
                try {
                    $remote = $sourceCf->getDnsRecords($s->cloudflare_zone_id ?: $rootdomain, $subdomainName, ['per_page' => 1000]);
                    if (($remote['success'] ?? false)) {
                        foreach (($remote['result'] ?? []) as $rr) {
                            $records[] = [
                                'name' => strtolower($rr['name'] ?? $subdomainName),
                                'type' => strtoupper($rr['type'] ?? ''),
                                'content' => (string) ($rr['content'] ?? ''),
                                'ttl' => intval($rr['ttl'] ?? 600),
                                'priority' => isset($rr['priority']) ? intval($rr['priority']) : null,
                            ];
                        }
                    } else {
                        $stats['warnings'][] = 'remote_records_unavailable:' . $sid;
                    }
                } catch (\Throwable $e) {
                    $stats['warnings'][] = 'remote_records_error:' . $sid;
                    cfmod_report_exception('transfer_root_provider_remote_fetch', $e);
                }
            }

            if (empty($records)) {
                $stats['warnings'][] = 'no_records:' . $sid;
            }

            foreach ($records as $rec) {
                $name = $rec['name'] ?: $subdomainName;
                $type = $rec['type'] ?: 'A';
                $ttl = intval($rec['ttl'] ?? 600);
                if ($ttl <= 0) {
                    $ttl = 600;
                }
                try {
                    $res = $targetCf->createDnsRecord($targetZone, $name, $type, $rec['content'], $ttl, false);
                    if ($res['success'] ?? false) {
                        $stats['records_created_on_cf']++;
                        continue;
                    }
                    $existing = $targetCf->getDnsRecords($targetZone, $name, ['type' => $type]);
                    if (($existing['success'] ?? false) && !empty($existing['result'])) {
                        $existingId = $existing['result'][0]['id'] ?? null;
                        if ($existingId) {
                            $updatePayload = [
                                'type' => $type,
                                'name' => $name,
                                'content' => $rec['content'],
                                'ttl' => $ttl,
                            ];
                            if ($type === 'MX' && $rec['priority'] !== null) {
                                $updatePayload['priority'] = intval($rec['priority']);
                            }
                            $update = $targetCf->updateDnsRecord($targetZone, $existingId, $updatePayload);
                            if ($update['success'] ?? false) {
                                $stats['records_updated_on_cf']++;
                            } else {
                                $stats['warnings'][] = 'update_failed:' . $sid;
                            }
                        }
                    } else {
                        $stats['warnings'][] = 'create_failed:' . $sid;
                    }
                } catch (\Throwable $e) {
                    $stats['warnings'][] = 'write_failed:' . $sid;
                    cfmod_report_exception('transfer_root_provider_write', $e);
                }
            }

            $primaryRecordId = null;
            try {
                $fresh = $targetCf->getDnsRecords($targetZone, $subdomainName, ['per_page' => 1000]);
                if (($fresh['success'] ?? false)) {
                    foreach (($fresh['result'] ?? []) as $fr) {
                        $name = strtolower($fr['name'] ?? '');
                        $type = strtoupper($fr['type'] ?? '');
                        $content = (string) ($fr['content'] ?? '');
                        $ttl = intval($fr['ttl'] ?? 600);
                        $rid = $fr['id'] ?? null;
                        if ($name === $subdomainName && $rid && $primaryRecordId === null) {
                            $primaryRecordId = $rid;
                        }
                        $existing = Capsule::table('mod_cloudflare_dns_records')
                            ->where('subdomain_id', $sid)
                            ->where('name', $name)
                            ->where('type', $type)
                            ->first();
                        if ($existing) {
                            Capsule::table('mod_cloudflare_dns_records')->where('id', $existing->id)->update([
                                'zone_id' => $targetZone,
                                'record_id' => $rid,
                                'content' => $content,
                                'ttl' => $ttl,
                                'updated_at' => $now,
                            ]);
                            $stats['records_updated_local']++;
                        } else {
                            Capsule::table('mod_cloudflare_dns_records')->insert([
                                'subdomain_id' => $sid,
                                'zone_id' => $targetZone,
                                'record_id' => $rid,
                                'name' => $name,
                                'type' => $type,
                                'content' => $content,
                                'ttl' => $ttl,
                                'proxied' => 0,
                                'priority' => null,
                                'line' => null,
                                'created_at' => $now,
                                'updated_at' => $now,
                            ]);
                            CfSubdomainService::markHasDnsHistory($sid);
                            $stats['records_imported_local']++;
                        }
                    }
                }
            } catch (\Throwable $e) {
                $stats['warnings'][] = 'refresh_local_failed:' . $sid;
                cfmod_report_exception('transfer_root_provider_refresh_local', $e);
            }

            if ($deleteOld) {
                if ($sourceProviderId && $sourceProviderId !== $targetProviderId && $sourceCf) {
                    try {
                        $sourceZone = $s->cloudflare_zone_id ?: $rootdomain;
                        $deleted = $sourceCf->deleteDomainRecordsDeep($sourceZone, $subdomainName);
                        if (($deleted['success'] ?? false)) {
                            $stats['records_deleted_on_cf'] += intval($deleted['deleted_count'] ?? 0);
                        }
                    } catch (\Throwable $e) {
                        $stats['warnings'][] = 'delete_old_failed:' . $sid;
                        cfmod_report_exception('transfer_root_provider_delete_old', $e);
                    }
                } elseif ($sourceProviderId === $targetProviderId) {
                    $stats['warnings'][] = 'skip_delete_same_provider:' . $sid;
                } else {
                    $stats['warnings'][] = 'delete_source_missing:' . $sid;
                }
            }

            $updatePayload = [
                'provider_account_id' => $targetProviderId,
                'cloudflare_zone_id' => $targetZone,
                'updated_at' => $now,
            ];
            if ($primaryRecordId) {
                $updatePayload['dns_record_id'] = $primaryRecordId;
            }
            Capsule::table('mod_cloudflare_subdomain')->where('id', $sid)->update($updatePayload);

            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('job_transfer_root_provider_progress', [
                    'rootdomain' => $rootdomain,
                    'subdomain' => $subdomainName,
                    'source_provider_id' => $sourceProviderId,
                    'target_provider_id' => $targetProviderId,
                ], intval($s->userid ?? 0), $sid);
            }
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'sub:' . ($s->id ?? 'unknown');
            cfmod_report_exception('transfer_root_provider_subdomain', $e);
        }
    }

    $stats['cursor_end'] = $lastId;
    $stats['message'] = $stats['processed_subdomains'] > 0
        ? ('migrated ' . $stats['processed_subdomains'] . ' subdomains to provider #' . $targetProviderId)
        : ('no subdomains matched ' . $rootdomain);

    if ($hasMore && $lastId > 0) {
        $stats['has_more'] = true;
        try {
            $nextPayload = $payload;
            $nextPayload['cursor_id'] = $lastId;
            $nextPayload['target_zone_identifier'] = $targetZone;
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'transfer_root_provider',
                'payload_json' => json_encode($nextPayload, JSON_UNESCAPED_UNICODE),
                'priority' => intval($job->priority ?? 5),
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'enqueue_failed';
            cfmod_report_exception('transfer_root_provider_enqueue', $e);
        }
    } else {
        $stats['has_more'] = false;
        try {
            $update = [
                'provider_account_id' => $targetProviderId,
                'cloudflare_zone_id' => $targetZone,
                'updated_at' => $now,
            ];
            if ($autoResume && $resumeStatus !== null && $resumeStatus !== '') {
                $update['status'] = $resumeStatus;
            }
            Capsule::table('mod_cloudflare_rootdomains')
                ->whereRaw('LOWER(domain) = ?', [$rootdomain])
                ->update($update);
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'root_update_failed';
            cfmod_report_exception('transfer_root_provider_finalize', $e);
        }
        if (function_exists('cloudflare_subdomain_log')) {
            cloudflare_subdomain_log('job_transfer_root_provider_done', [
                'rootdomain' => $rootdomain,
                'target_provider_id' => $targetProviderId,
                'processed_subdomains' => $stats['processed_subdomains'],
            ]);
        }
    }

    if (function_exists('cfmod_clear_rootdomain_limits_cache')) {
        cfmod_clear_rootdomain_limits_cache();
    }

    return $stats;
}

function cfmod_job_purge_root_local($job, array $payload = []): array {
    $jobId = intval($job->id);
    $rootdomain = strtolower(trim((string)($payload['rootdomain'] ?? '')));
    if ($rootdomain === '') {
        throw new \InvalidArgumentException('rootdomain required');
    }

    $batchSize = intval($payload['batch_size'] ?? 200);
    if ($batchSize <= 0) {
        $batchSize = 200;
    }
    $batchSize = max(20, min(500, $batchSize));

    $cursor = intval($payload['cursor_id'] ?? 0);

    $query = Capsule::table('mod_cloudflare_subdomain')
        ->whereRaw('LOWER(rootdomain) = ?', [$rootdomain])
        ->orderBy('id', 'asc');
    if ($cursor > 0) {
        $query->where('id', '>', $cursor);
    }

    $rowsRaw = $query->limit($batchSize + 1)->get();
    if (!($rowsRaw instanceof \Illuminate\Support\Collection)) {
        $rowsRaw = new \Illuminate\Support\Collection(is_array($rowsRaw) ? $rowsRaw : (array) $rowsRaw);
    }

    if ($rowsRaw->count() === 0) {
        return [
            'rootdomain' => $rootdomain,
            'processed_subdomains' => 0,
            'deleted' => 0,
            'deleted_total' => intval($payload['deleted_total'] ?? 0),
            'message' => 'no local subdomains matched ' . $rootdomain,
        ];
    }

    $hasMore = $rowsRaw->count() > $batchSize;
    $batch = $hasMore ? $rowsRaw->slice(0, $batchSize)->values() : $rowsRaw->values();

    $subdomainIds = [];
    $userCounts = [];
    $lastId = 0;
    $now = date('Y-m-d H:i:s');

    foreach ($batch as $row) {
        $sid = intval($row->id);
        $subdomainIds[] = $sid;
        $lastId = $sid;
        $uid = intval($row->userid ?? 0);
        if ($uid > 0) {
            if (!isset($userCounts[$uid])) {
                $userCounts[$uid] = 0;
            }
            $userCounts[$uid]++;
        }
    }

    $warnings = [];

    if (!empty($subdomainIds)) {
        try {
            Capsule::table('mod_cloudflare_dns_records')->whereIn('subdomain_id', $subdomainIds)->delete();
        } catch (\Throwable $e) {
            $warnings[] = 'dns_records_delete_failed';
            cfmod_report_exception('purge_root_local_dns_records', $e);
        }
        try {
            Capsule::table('mod_cloudflare_domain_risk')->whereIn('subdomain_id', $subdomainIds)->delete();
        } catch (\Throwable $e) {
            $warnings[] = 'domain_risk_delete_failed';
            cfmod_report_exception('purge_root_local_domain_risk', $e);
        }
        try {
            Capsule::table('mod_cloudflare_risk_events')->whereIn('subdomain_id', $subdomainIds)->delete();
        } catch (\Throwable $e) {
            $warnings[] = 'risk_events_delete_failed';
            cfmod_report_exception('purge_root_local_risk_events', $e);
        }
        try {
            Capsule::table('mod_cloudflare_sync_results')->whereIn('subdomain_id', $subdomainIds)->delete();
        } catch (\Throwable $e) {
            $warnings[] = 'sync_results_delete_failed';
            cfmod_report_exception('purge_root_local_sync_results', $e);
        }
        try {
            Capsule::table('mod_cloudflare_subdomain')->whereIn('id', $subdomainIds)->delete();
        } catch (\Throwable $e) {
            $warnings[] = 'subdomain_delete_failed';
            cfmod_report_exception('purge_root_local_subdomains', $e);
        }
    }

    $affectedUsers = 0;
    foreach ($userCounts as $uid => $count) {
        if ($uid <= 0) {
            continue;
        }
        try {
            $quota = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $uid)->first();
            if ($quota) {
                $used = max(0, intval($quota->used_count ?? 0) - $count);
                Capsule::table('mod_cloudflare_subdomain_quotas')
                    ->where('userid', $uid)
                    ->update([
                        'used_count' => $used,
                        'updated_at' => $now,
                    ]);
                $affectedUsers++;
            }
        } catch (\Throwable $e) {
            $warnings[] = 'quota_update_failed:' . $uid;
            cfmod_report_exception('purge_root_local_quota', $e);
        }
    }

    if (function_exists('cloudflare_subdomain_log')) {
        try {
            $logPayload = [
                'rootdomain' => $rootdomain,
                'deleted_count' => count($subdomainIds),
                'subdomain_ids' => array_slice(array_map('intval', $subdomainIds), 0, 20),
                'total_deleted_so_far' => intval($payload['deleted_total'] ?? 0) + count($subdomainIds),
            ];
            if (isset($payload['initiator'])) {
                $logPayload['initiator'] = $payload['initiator'];
            }
            if (!empty($payload['admin_id'])) {
                $logPayload['admin_id'] = intval($payload['admin_id']);
            }
            cloudflare_subdomain_log('admin_purge_rootdomain_local_batch', $logPayload);
        } catch (\Throwable $e) {}
    }

    $deletedCount = count($subdomainIds);
    $totalDeleted = intval($payload['deleted_total'] ?? 0) + $deletedCount;

    $stats = [
        'rootdomain' => $rootdomain,
        'processed_subdomains' => $deletedCount,
        'deleted' => $deletedCount,
        'deleted_total' => $totalDeleted,
        'affected_users' => $affectedUsers,
    ];
    if (!empty($warnings)) {
        $stats['warnings'] = array_values(array_unique($warnings));
    }
    $stats['message'] = 'purged ' . $deletedCount . ' local subdomains for ' . $rootdomain;

    if ($hasMore && $lastId) {
        $stats['has_more'] = true;
        $stats['next_cursor'] = $lastId;
        try {
            $nextPayload = [
                'rootdomain' => $rootdomain,
                'batch_size' => $batchSize,
                'cursor_id' => $lastId,
                'deleted_total' => $totalDeleted,
            ];
            if (isset($payload['initiator'])) {
                $nextPayload['initiator'] = $payload['initiator'];
            }
            if (isset($payload['admin_id'])) {
                $nextPayload['admin_id'] = $payload['admin_id'];
            }
            Capsule::table('mod_cloudflare_jobs')->insert([
                'type' => 'purge_root_local',
                'payload_json' => json_encode($nextPayload, JSON_UNESCAPED_UNICODE),
                'priority' => intval($job->priority ?? 8),
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => $now,
                'updated_at' => $now
            ]);
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'enqueue_failed';
            cfmod_report_exception('purge_root_local_enqueue', $e);
        }
    } else {
        $stats['has_more'] = false;
    }

    return $stats;
}

function cfmod_job_reconcile_all($job, array $payload = []): array {
    $jobId = intval($job->id);
    $settings = cfmod_get_settings();
    $mode = (($payload['mode'] ?? 'dry') === 'fix') ? 'fix' : 'dry';
    $batchSize = intval($payload['batch_size'] ?? 150);
    if ($batchSize <= 0) { $batchSize = 150; }
    $batchSize = max(50, min(500, $batchSize));
    $cursor = intval($payload['cursor_id'] ?? 0);
    $now = date('Y-m-d H:i:s');

    $priority = strtolower($settings['sync_authoritative_source'] ?? 'local');
    if (!in_array($priority, ['local', 'aliyun'], true)) { $priority = 'local'; }

    $stats = [
        'mode' => $mode,
        'batch_size' => $batchSize,
        'cursor_start' => $cursor,
        'processed_subdomains' => 0,
        'records_updated_local' => 0,
        'records_imported_local' => 0,
        'differences_total' => 0,
        'difference_breakdown' => [],
        'action_breakdown' => [],
        'warnings' => [],
        'priority' => $priority,
    ];

    $subsCollection = Capsule::table('mod_cloudflare_subdomain')
        ->where('id', '>', $cursor)
        ->orderBy('id', 'asc')
        ->limit($batchSize + 1)
        ->get();

    if (!($subsCollection instanceof \Illuminate\Support\Collection)) {
        $subsCollection = new \Illuminate\Support\Collection(is_array($subsCollection) ? $subsCollection : (array) $subsCollection);
    }

    if ($subsCollection->count() === 0) {
        $stats['message'] = 'no subdomains to reconcile';
        return $stats;
    }

    $hasMore = $subsCollection->count() > $batchSize;
    $subs = $hasMore ? $subsCollection->slice(0, $batchSize)->values() : $subsCollection->values();

    $providerClients = [];
    $groupedSubs = [];
    foreach ($subs as $s) {
        $stats['processed_subdomains']++;
        $providerId = cfmod_worker_resolve_provider_account_id_for_subdomain($s, $settings);
        $groupKey = $providerId ?: 0;
        if (!isset($groupedSubs[$groupKey])) {
            $groupedSubs[$groupKey] = [];
        }
        $groupedSubs[$groupKey][] = $s;
    }

    foreach ($groupedSubs as $providerKey => $groupSubs) {
        $providerAccountId = $providerKey ?: null;
        $providerContext = cfmod_worker_acquire_provider_client_cached($providerAccountId, $settings, $providerClients, $stats, 'reconcile');
        if (!$providerContext) {
            foreach ($groupSubs as $failedSub) {
                $stats['warnings'][] = 'reconcile_provider_missing_sub:' . $failedSub->id;
            }
            continue;
        }
        $cf = $providerContext['client'];

        foreach ($groupSubs as $s) {
            try {
                $zone = $s->cloudflare_zone_id ?: $s->rootdomain;
                $name = strtolower($s->subdomain);
                $remote = $cf->getDnsRecords($zone, $name, ['per_page' => 1000]);
                if (!($remote['success'] ?? false)) { throw new \RuntimeException('list failed'); }
                $cloud = $remote['result'] ?? [];
                $local = Capsule::table('mod_cloudflare_dns_records')->where('subdomain_id', $s->id)->orderBy('id','asc')->get();
                $localKey = [];
                foreach ($local as $lr) {
                    $k = strtolower($lr->name).'|'.strtoupper($lr->type);
                    $localKey[$k] = $lr;
                }
                $cloudKey = [];
                foreach ($cloud as $cr) {
                    $k = strtolower($cr['name'] ?? '').'|'.strtoupper($cr['type'] ?? '');
                    $cloudKey[$k] = $cr;
                }

                foreach ($cloudKey as $k => $cr) {
                    if (!isset($localKey[$k])) {
                        if ($priority === 'local') {
                            $action = ($mode === 'fix') ? 'deleted_on_cf' : 'diff_cloud_extra';
                            if ($mode === 'fix' && !empty($cr['id'])) {
                                $res = $cf->deleteSubdomain($zone, $cr['id']);
                                if (!($res['success'] ?? false)) {
                                    $action = 'delete_failed';
                                    $stats['warnings'][] = 'delete_failed:' . ($cr['id'] ?? '');
                                }
                            }
                            cfmod_sync_result($jobId, $s->id, 'reconcile', $action, [
                                'name' => $cr['name'] ?? '',
                                'type' => $cr['type'] ?? '',
                                'record_id' => $cr['id'] ?? null
                            ]);
                            cfmod_track_sync_stat($stats, 'reconcile', $action);
                            continue;
                        }

                        $action = ($mode === 'fix') ? 'insert_local' : 'diff_insert_local';
                        if ($mode === 'fix') {
                            Capsule::table('mod_cloudflare_dns_records')->insert([
                                'subdomain_id' => $s->id,
                                'zone_id' => $zone,
                                'record_id' => $cr['id'] ?? null,
                                'name' => strtolower($cr['name'] ?? ''),
                                'type' => strtoupper($cr['type'] ?? ''),
                                'content' => (string)($cr['content'] ?? ''),
                                'ttl' => intval($cr['ttl'] ?? 600),
                                'proxied' => 0,
                                'priority' => null,
                                'line' => null,
                                'created_at' => $now,
                                'updated_at' => $now
                            ]);
                            CfSubdomainService::markHasDnsHistory($s->id);
                            $stats['records_imported_local']++;
                        }
                        cfmod_sync_result($jobId, $s->id, 'reconcile', $action, ['name'=>$cr['name']??'','type'=>$cr['type']??'']);
                        cfmod_track_sync_stat($stats, 'reconcile', $action);
                    }
                }

                foreach ($localKey as $k => $lr) {
                    if (isset($cloudKey[$k])) {
                        $cr = $cloudKey[$k];
                        $need = ((string)$lr->content !== (string)($cr['content'] ?? '')) || (intval($lr->ttl) !== intval($cr['ttl'] ?? 600));
                        if ($need) {
                            $action = ($mode === 'fix') ? 'update_local' : 'diff_update_local';
                            if ($mode === 'fix') {
                                Capsule::table('mod_cloudflare_dns_records')->where('id', $lr->id)->update([
                                    'content' => (string)($cr['content'] ?? ''),
                                    'ttl' => intval($cr['ttl'] ?? 600),
                                    'updated_at' => $now
                                ]);
                                $stats['records_updated_local']++;
                            }
                            cfmod_sync_result($jobId, $s->id, 'reconcile', $action, ['name'=>$cr['name']??'','type'=>$cr['type']??'']);
                            cfmod_track_sync_stat($stats, 'reconcile', $action);
                        }
                    } else {
                        $action = 'diff_cloud_missing';
                        cfmod_sync_result($jobId, $s->id, 'reconcile', $action, ['name'=>$lr->name,'type'=>$lr->type]);
                        cfmod_track_sync_stat($stats, 'reconcile', $action);
                    }
                }
            } catch (\Throwable $e) {
                $stats['warnings'][] = 'sub:' . $s->id;
                cfmod_sync_result($jobId, $s->id, 'reconcile', 'error', ['message'=>substr($e->getMessage(),0,200)]);
                cfmod_report_exception('reconcile_all', $e);
            }
        }
    }

    $lastProcessedId = $subs->last()->id ?? $cursor;
    if ($hasMore && $lastProcessedId) {
        $newPayload = $payload;
        $newPayload['cursor_id'] = $lastProcessedId;
        $newPayload['batch_size'] = $batchSize;
        $newPayload['mode'] = $mode;
        try {
            $continuationId = Capsule::table('mod_cloudflare_jobs')->insertGetId([
                'type' => 'reconcile_all',
                'payload_json' => json_encode($newPayload, JSON_UNESCAPED_UNICODE),
                'priority' => intval($job->priority ?? 10),
                'status' => 'pending',
                'attempts' => 0,
                'next_run_at' => null,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ]);
            $stats['has_more'] = true;
            $stats['next_cursor'] = $lastProcessedId;
            $stats['continuation_job_id'] = $continuationId;
        } catch (\Throwable $e) {
            $stats['has_more'] = true;
            $stats['warnings'][] = 'enqueue_failed:' . $lastProcessedId;
            cfmod_report_exception('reconcile_enqueue', $e);
        }
    } else {
        $stats['has_more'] = false;
    }

    $stats['message'] = 'reconcile ' . ($mode === 'fix' ? 'fix' : 'dry');
    return $stats;
}


/**
 * Enforce DNS on all free subdomains of a banned user:
 * - Keep only A records and set to specified IPv4
 * - Delete all other record types (AAAA, CNAME, TXT, MX, NS, etc.)
 * payload: { userid: number, ipv4: string }
 */
function cfmod_job_enforce_ban_dns($job, array $payload = []): array {
    $jobId = intval($job->id);
    $userid = intval($payload['userid'] ?? 0);
    $ip4 = trim((string)($payload['ipv4'] ?? ''));
    if ($userid <= 0 || $ip4 === '') {
        return [
            'warnings' => ['invalid_payload'],
            'message' => 'invalid payload',
            'processed_subdomains' => 0,
        ];
    }
    $settings = cfmod_get_settings();
    $now = date('Y-m-d H:i:s');
    $subs = Capsule::table('mod_cloudflare_subdomain')->where('userid', $userid)->orderBy('id','asc')->get();

    $stats = [
        'processed_subdomains' => 0,
        'records_updated_on_cf' => 0,
        'records_deleted_on_cf' => 0,
        'warnings' => [],
    ];

    $providerClients = [];
    foreach ($subs as $s) {
        try {
            $stats['processed_subdomains']++;
            $providerId = cfmod_worker_resolve_provider_account_id_for_subdomain($s, $settings);
            $providerContext = cfmod_worker_acquire_provider_client_cached($providerId, $settings, $providerClients, $stats, 'enforce_ban_dns');
            if (!$providerContext) {
                $stats['warnings'][] = 'provider_unavailable:' . $s->id;
                continue;
            }
            $cf = $providerContext['client'];

            $zone = $s->cloudflare_zone_id ?: $s->rootdomain;
            $name = strtolower($s->subdomain);
            $remote = $cf->getDnsRecords($zone, $name, ['per_page' => 1000]);
            if (!($remote['success'] ?? false)) { throw new \RuntimeException('list failed'); }
            $records = $remote['result'] ?? [];
            foreach ($records as $r) {
                $rid = $r['id'] ?? null;
                $type = strtoupper($r['type'] ?? '');
                $rname = $r['name'] ?? $name;
                if (!$rid || $rname === '') { continue; }
                if ($type === 'A') {
                    $cf->updateDnsRecord($zone, $rid, [ 'type' => 'A', 'name' => $rname, 'content' => $ip4, 'ttl' => intval($r['ttl'] ?? 600) ]);
                    $stats['records_updated_on_cf']++;
                } else {
                    try {
                        $cf->deleteSubdomain($zone, $rid);
                        $stats['records_deleted_on_cf']++;
                    } catch (\Throwable $inner) {
                        $stats['warnings'][] = 'delete_failed:' . $rid;
                        cfmod_report_exception('enforce_ban_dns_delete', $inner);
                    }
                }
            }
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'sub:' . $s->id;
            cfmod_report_exception('enforce_ban_dns', $e);
        }
    }

    $stats['message'] = 'enforced dns for user ' . $userid;
    return $stats;
}

function cfmod_job_client_dns_operation($job, array $payload = []): array
{
    $userId = intval($payload['user_id'] ?? 0);
    if ($userId <= 0) {
        throw new \RuntimeException('Async DNS job missing user id (job #' . ($job->id ?? '?') . ')');
    }
    $postData = $payload['post'] ?? null;
    if (!is_array($postData) || empty($postData['action'])) {
        throw new \RuntimeException('Async DNS job payload is invalid (job #' . ($job->id ?? '?') . ')');
    }

    $originalPost = $_POST ?? [];
    $originalRequest = $_REQUEST ?? [];
    $originalMethod = $_SERVER['REQUEST_METHOD'] ?? null;

    try {
        $_POST = $postData;
        $_REQUEST = $_POST;
        $_SERVER['REQUEST_METHOD'] = 'POST';

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        try {
            $sessionId = 'asyncdns_' . ($job->id ?? 0) . '_' . bin2hex(random_bytes(4));
        } catch (\Throwable $e) {
            $sessionId = 'asyncdns_' . ($job->id ?? 0) . '_' . uniqid();
        }
        session_id($sessionId);
        session_start();
        $_SESSION['uid'] = $userId;

        $viewModel = CfClientViewModelBuilder::build($userId);
        $globals = $viewModel['globals'] ?? [];
        if (empty($globals)) {
            throw new \RuntimeException('Unable to build client context for async DNS job #' . ($job->id ?? '?'));
        }

        $result = CfClientActionService::process($globals);
    } finally {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        $_POST = $originalPost;
        $_REQUEST = $originalRequest;
        if ($originalMethod !== null) {
            $_SERVER['REQUEST_METHOD'] = $originalMethod;
        } else {
            unset($_SERVER['REQUEST_METHOD']);
        }
    }

    $msg = trim(strip_tags($result['msg'] ?? ''));
    $msgType = strtolower((string)($result['msg_type'] ?? ''));
    if ($msgType === 'danger') {
        throw new \RuntimeException($msg !== '' ? $msg : 'DNS operation failed');
    }

    return [
        'message' => $msg !== '' ? $msg : 'queued',
        'status' => $msgType !== '' ? $msgType : 'success',
        'action' => $postData['action'],
    ];
}

/**
 * 清理风险事件数据任务
 */
function cfmod_job_cleanup_risk_events($job, array $payload = []): array {
    $now = date('Y-m-d H:i:s');
    $totalCleaned = 0;
    $highRiskCleaned = 0;
    $duplicateCleaned = 0;
    $stats = [
        'deleted' => 0,
        'warnings' => [],
        'processed_subdomains' => 0,
        'high_risk_deleted' => 0,
        'duplicate_deleted' => 0,
    ];

    try {
        $highRiskCleaned = Capsule::table('mod_cloudflare_risk_events')
            ->where('level', 'high')
            ->where('created_at', '<', date('Y-m-d H:i:s', strtotime('-72 hours')))
            ->delete();
        $totalCleaned += $highRiskCleaned;

        $duplicatesRaw = Capsule::table('mod_cloudflare_risk_events')
            ->select('subdomain_id', Capsule::raw('DATE(created_at) as date'), Capsule::raw('COUNT(*) as count'))
            ->where('source', 'summary')
            ->groupBy('subdomain_id', Capsule::raw('DATE(created_at)'))
            ->having('count', '>', 1)
            ->get();
        if ($duplicatesRaw instanceof \Illuminate\Support\Collection) {
            $duplicates = $duplicatesRaw->all();
            $duplicatesCount = $duplicatesRaw->count();
        } else {
            $duplicates = is_array($duplicatesRaw) ? $duplicatesRaw : [];
            $duplicatesCount = count($duplicates);
        }

        foreach ($duplicates as $dup) {
            $subdomainId = is_object($dup) ? ($dup->subdomain_id ?? null) : ($dup['subdomain_id'] ?? null);
            $dupDate = is_object($dup) ? ($dup->date ?? null) : ($dup['date'] ?? null);
            if ($subdomainId === null || $dupDate === null) {
                continue;
            }

            $toDeleteRaw = Capsule::table('mod_cloudflare_risk_events')
                ->where('subdomain_id', $subdomainId)
                ->where('source', 'summary')
                ->whereRaw('DATE(created_at) = ?', [$dupDate])
                ->orderBy('id', 'desc')
                ->skip(1)
                ->get();
            $toDelete = $toDeleteRaw instanceof \Illuminate\Support\Collection ? $toDeleteRaw->all() : (is_array($toDeleteRaw) ? $toDeleteRaw : []);

            foreach ($toDelete as $record) {
                $recordId = is_object($record) ? ($record->id ?? null) : ($record['id'] ?? null);
                if ($recordId === null) {
                    continue;
                }
                Capsule::table('mod_cloudflare_risk_events')->where('id', $recordId)->delete();
                $duplicateCleaned++;
            }
        }
        $totalCleaned += $duplicateCleaned;

        if (function_exists('cloudflare_subdomain_log')) {
            cloudflare_subdomain_log('risk_events_cleanup', [
                'cleaned_count' => $totalCleaned,
                'high_risk' => $highRiskCleaned,
                'duplicates' => $duplicateCleaned,
                'note' => 'Only high-risk events are stored and cleaned after 72 hours'
            ]);
        }

        try {
            Capsule::statement("OPTIMIZE TABLE `mod_cloudflare_risk_events`");
        } catch (\Throwable $optimizeException) {
            $warnMsg = trim((string) $optimizeException->getMessage());
            if ($warnMsg === '') {
                $stats['warnings'][] = 'optimize_failed';
            } else {
                $stats['warnings'][] = 'optimize_failed:' . substr($warnMsg, 0, 120);
            }
            cfmod_report_exception('cleanup_risk_events_optimize', $optimizeException);
        }

        $stats['deleted'] = $totalCleaned;
        $stats['processed_subdomains'] = $duplicatesCount;
        $stats['high_risk_deleted'] = $highRiskCleaned;
        $stats['duplicate_deleted'] = $duplicateCleaned;
        $message = 'cleaned ' . $totalCleaned . ' risk events';
        if (!empty($stats['warnings'])) {
            $message .= ' (with warnings)';
        }
        $stats['message'] = $message;
    } catch (\Throwable $e) {
        $errMsg = trim((string) $e->getMessage());
        if ($errMsg === '') {
            $errMsg = 'cleanup failed';
        }
        $stats['warnings'][] = 'cleanup_failed:' . substr($errMsg, 0, 120);
        $stats['message'] = 'cleanup encountered errors: ' . substr($errMsg, 0, 120);
        cfmod_report_exception('cleanup_risk_events', $e);
    }

    return $stats;
}

function cfmod_job_cleanup_expired_subdomains($job, array $payload = []): array {
    $stats = [
        'processed_subdomains' => 0,
        'deleted' => 0,
        'failed' => 0,
        'warnings' => [],
    ];

    try {
        $settings = cfmod_get_settings();
        $graceRaw = $settings['domain_grace_period_days'] ?? ($settings['domain_auto_delete_grace_days'] ?? 45);
        $graceDays = is_numeric($graceRaw) ? (int) $graceRaw : 45;
        if ($graceDays < 0) {
            $graceDays = 0;
        }

        $redemptionDays = intval($settings['domain_redemption_days'] ?? 0);
        if ($redemptionDays < 0) {
            $redemptionDays = 0;
        }
        $redemptionCleanupDays = intval($settings['domain_redemption_cleanup_days'] ?? 0);
        if ($redemptionCleanupDays < 0) {
            $redemptionCleanupDays = 0;
        }
        $totalRetentionDays = $graceDays + $redemptionDays + $redemptionCleanupDays;

        $batchSize = intval($payload['batch_size'] ?? ($settings['domain_cleanup_batch_size'] ?? 50));
        if ($batchSize <= 0) {
            $batchSize = 50;
        }
        $batchSize = max(1, min(500, $batchSize));

        $deepDeletePayload = !empty($payload['deep_delete']);
        $deepDeleteSetting = in_array(($settings['domain_cleanup_deep_delete'] ?? 'yes'), ['1','on','yes','true'], true);
        $deepDelete = $deepDeletePayload || $deepDeleteSetting;

        $thresholdTs = time() - ($totalRetentionDays * 86400);
        $threshold = date('Y-m-d H:i:s', $thresholdTs);

        $expiredQuery = Capsule::table('mod_cloudflare_subdomain')
            ->where('never_expires', 0)
            ->whereNotNull('expires_at')
            ->whereNull('auto_deleted_at')
            ->whereNotIn('status', ['deleted', 'Deleted'])
            ->where('expires_at', '<', $threshold)
            ->orderBy('id', 'asc')
            ->limit($batchSize);

        $records = $expiredQuery->get();
        if ($records instanceof \Illuminate\Support\Collection) {
            $records = $records->all();
        }

        $stats['processed_subdomains'] = count($records);
        if ($stats['processed_subdomains'] === 0) {
            $stats['message'] = 'nothing_to_cleanup';
            return $stats;
        }

        $providerClients = [];
        $nowStr = date('Y-m-d H:i:s');

        $failures = [];
        $deletedIds = [];
        $deletedCount = 0;

        foreach ($records as $record) {
            $recordId = intval($record->id ?? 0);
            if ($recordId <= 0) {
                $stats['warnings'][] = 'invalid_record_id';
                continue;
            }

            $userid = intval($record->userid ?? 0);
            $subdomainName = $record->subdomain ?? '';
            $zoneId = $record->cloudflare_zone_id ?: ($record->rootdomain ?? '');

            $deleteSuccess = false;
            $apiError = null;

            $providerId = cfmod_worker_resolve_provider_account_id_for_subdomain($record, $settings);
            $providerContext = cfmod_worker_acquire_provider_client_cached($providerId, $settings, $providerClients, $stats, 'cleanup_expired');
            if (!$providerContext) {
                $apiError = 'provider_unavailable';
            } else {
                $cf = $providerContext['client'];
                try {
                    if ($zoneId) {
                        $result = $deepDelete
                            ? $cf->deleteDomainRecordsDeep($zoneId, $subdomainName)
                            : $cf->deleteDomainRecords($zoneId, $subdomainName);
                        $deleteSuccess = (bool)($result['success'] ?? false);
                        if (!$deleteSuccess && $deepDelete) {
                            $fallback = $cf->deleteDomainRecords($zoneId, $subdomainName);
                            $deleteSuccess = (bool)($fallback['success'] ?? false);
                            if (!$deleteSuccess) {
                                $apiError = $fallback['errors'] ?? ($fallback['Message'] ?? 'unknown_error');
                            }
                        } elseif (!$deleteSuccess) {
                            $apiError = $result['errors'] ?? ($result['Message'] ?? 'unknown_error');
                        }
                    } else {
                        $deleteSuccess = true;
                    }
                } catch (\Throwable $apiException) {
                    $apiError = $apiException->getMessage();
                    cfmod_report_exception('cleanup_expired_subdomains_api', $apiException);
                }
            }

            if ($deleteSuccess) {
                $deletedIds[] = $recordId;

                try {
                    $quota = Capsule::table('mod_cloudflare_subdomain_quotas')
                        ->where('userid', $userid)
                        ->first();
                    if ($quota) {
                        $used = max(0, intval($quota->used_count ?? 0));
                        $newUsed = $used > 0 ? $used - 1 : 0;
                        Capsule::table('mod_cloudflare_subdomain_quotas')
                            ->where('userid', $userid)
                            ->update([
                                'used_count' => $newUsed,
                                'updated_at' => $nowStr
                            ]);
                    }
                } catch (\Throwable $quotaException) {
                    cfmod_report_exception('cleanup_expired_subdomains_quota', $quotaException);
                }

                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('auto_cleanup_expired_subdomain', [
                        'subdomain' => $subdomainName,
                        'userid' => $userid,
                        'deleted_at' => $nowStr,
                        'deep_delete' => $deepDelete ? 1 : 0
                    ], $userid, $recordId);
                }

                $deletedCount++;
            } else {
                $failures[] = [
                    'id' => $recordId,
                    'subdomain' => $subdomainName,
                    'error' => is_string($apiError) ? $apiError : json_encode($apiError, JSON_UNESCAPED_UNICODE),
                    'error_type' => $apiError === 'provider_unavailable' ? 'provider' : 'dns',
                ];
            }
        }

        if (!empty($deletedIds)) {
            $cleanupWarnings = cfmod_delete_local_subdomain_artifacts($deletedIds);
            if (!empty($cleanupWarnings)) {
                foreach ($cleanupWarnings as $cleanupWarning) {
                    $stats['warnings'][] = $cleanupWarning;
                }
            }
        }

        $stats['deleted'] = $deletedCount;
        $stats['failed'] = count($failures);
        if (!empty($failures)) {
            $stats['failures'] = array_slice($failures, 0, 20);
            $stats['warnings'][] = count($failures) > 20 ? 'partial_failures_truncated' : 'partial_failures';
        }

        if ($stats['processed_subdomains'] === $batchSize) {
            $stats['has_more'] = true;
            try {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_expired_subdomains',
                    'payload_json' => json_encode([
                        'batch_size' => $batchSize,
                        'deep_delete' => $deepDelete ? 1 : 0,
                        'auto' => !empty($payload['auto'])
                    ], JSON_UNESCAPED_UNICODE),
                    'priority' => 15,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => $nowStr,
                    'updated_at' => $nowStr
                ]);
            } catch (\Throwable $queueMore) {
                cfmod_report_exception('cleanup_expired_subdomains_requeue', $queueMore);
            }
        }

        $stats['message'] = 'deleted ' . $deletedCount . ' expired subdomains';
    } catch (\Throwable $e) {
        $stats['warnings'][] = 'cleanup_failed';
        $stats['message'] = 'cleanup failed: ' . substr($e->getMessage(), 0, 120);
        cfmod_report_exception('cleanup_expired_subdomains', $e);
    }

    return $stats;
}

function cfmod_delete_local_subdomain_artifacts(array $subdomainIds): array {
    $uniqueIds = array_values(array_filter(array_unique(array_map('intval', $subdomainIds)), function ($value) {
        return $value > 0;
    }));
    if (empty($uniqueIds)) {
        return [];
    }

    $warnings = [];
    $tasks = [
        ['table' => 'mod_cloudflare_dns_records', 'column' => 'subdomain_id', 'warning' => 'cleanup_dns_records_failed', 'context' => 'cleanup_expired_dns_records'],
        ['table' => 'mod_cloudflare_domain_risk', 'column' => 'subdomain_id', 'warning' => 'cleanup_domain_risk_failed', 'context' => 'cleanup_expired_domain_risk'],
        ['table' => 'mod_cloudflare_risk_events', 'column' => 'subdomain_id', 'warning' => 'cleanup_risk_events_failed', 'context' => 'cleanup_expired_risk_events'],
        ['table' => 'mod_cloudflare_sync_results', 'column' => 'subdomain_id', 'warning' => 'cleanup_sync_results_failed', 'context' => 'cleanup_expired_sync_results'],
        ['table' => 'mod_cloudflare_domain_gifts', 'column' => 'subdomain_id', 'warning' => 'cleanup_domain_gifts_failed', 'context' => 'cleanup_expired_domain_gifts'],
        ['table' => 'mod_cloudflare_subdomain', 'column' => 'id', 'warning' => 'cleanup_subdomains_failed', 'context' => 'cleanup_expired_subdomain_delete'],
    ];

    foreach ($tasks as $task) {
        try {
            Capsule::table($task['table'])
                ->whereIn($task['column'], $uniqueIds)
                ->delete();
        } catch (\Throwable $e) {
            $warnings[] = $task['warning'];
            cfmod_report_exception($task['context'], $e);
        }
    }

    return array_values(array_unique($warnings));
}

function cfmod_job_cleanup_api_logs($job, array $payload = []): array {
    $stats = [
        'deleted' => 0,
        'warnings' => [],
    ];
    try {
        $settings = cfmod_get_settings();
        $days = intval($payload['retention_days'] ?? ($settings['api_logs_retention_days'] ?? 30));
        if ($days <= 0) {
            $stats['message'] = 'api log cleanup disabled';
            return $stats;
        }
        $days = max(1, min(365, $days));
        $threshold = date('Y-m-d H:i:s', time() - $days * 86400);
        $deleted = Capsule::table('mod_cloudflare_api_logs')->where('created_at','<',$threshold)->delete();
        try { Capsule::statement('OPTIMIZE TABLE `mod_cloudflare_api_logs`'); } catch (\Throwable $e) {
            $stats['warnings'][] = 'optimize_failed';
            cfmod_report_exception('cleanup_api_logs_optimize', $e);
        }

        $rateDeleted = 0;
        try {
            if (Capsule::schema()->hasTable('mod_cloudflare_api_rate_limit')) {
                $cutoffRate = date('Y-m-d H:i:s', time() - 2 * 86400);
                $rateDeleted = Capsule::table('mod_cloudflare_api_rate_limit')
                    ->where('window_end', '<', $cutoffRate)
                    ->delete();
                if ($rateDeleted > 0) {
                    try { Capsule::statement('OPTIMIZE TABLE `mod_cloudflare_api_rate_limit`'); } catch (\Throwable $e) {
                        $stats['warnings'][] = 'optimize_rate_limit_failed';
                        cfmod_report_exception('cleanup_api_rate_limit_optimize', $e);
                    }
                }
            }
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'rate_limit_cleanup_failed';
            cfmod_report_exception('cleanup_api_rate_limit', $e);
        }

        $stats['deleted'] = $deleted;
        if ($rateDeleted > 0) {
            $stats['deleted_rate_windows'] = $rateDeleted;
        }
        $message = 'cleaned '.$deleted.' api logs older than '.$days.' days';
        if ($rateDeleted > 0) {
            $message .= '; removed '.$rateDeleted.' rate windows';
        }
        $stats['message'] = $message;
        $stats['processed_subdomains'] = 0;
    } catch (\Throwable $e) {
        $stats['warnings'][] = 'cleanup_failed';
        $stats['message'] = 'api log cleanup failed';
        cfmod_report_exception('cleanup_api_logs', $e);
    }
    return $stats;
}

function cfmod_job_cleanup_general_logs($job, array $payload = []): array {
    $stats = [
        'deleted' => 0,
        'warnings' => [],
    ];
    try {
        $settings = cfmod_get_settings();
        $retention = intval($payload['retention_days'] ?? ($settings['general_logs_retention_days'] ?? 0));
        if ($retention <= 0) {
            $stats['message'] = 'general log cleanup disabled';
            return $stats;
        }
        $batchLimit = intval($payload['batch_limit'] ?? 2000);
        if ($batchLimit <= 0) { $batchLimit = 2000; }
        $batchLimit = max(100, min(5000, $batchLimit));
        $cutoff = date('Y-m-d H:i:s', time() - $retention * 86400);

        $rowsRaw = Capsule::table('mod_cloudflare_logs')
            ->where('created_at', '<', $cutoff)
            ->orderBy('id', 'asc')
            ->limit($batchLimit + 1)
            ->get();
        if ($rowsRaw instanceof \Illuminate\Support\Collection) {
            $rowsRaw = $rowsRaw->all();
        }
        $rowCount = is_array($rowsRaw) ? count($rowsRaw) : 0;
        if ($rowCount === 0) {
            $stats['message'] = 'no general logs to cleanup';
            return $stats;
        }
        $hasMore = $rowCount > $batchLimit;
        $batchRows = $hasMore ? array_slice($rowsRaw, 0, $batchLimit) : $rowsRaw;
        $ids = [];
        foreach ($batchRows as $row) {
            $id = is_object($row) ? ($row->id ?? null) : ($row['id'] ?? null);
            if ($id !== null) {
                $ids[] = (int) $id;
            }
        }
        if (empty($ids)) {
            $stats['message'] = 'no general logs to cleanup';
            return $stats;
        }
        $deleted = Capsule::table('mod_cloudflare_logs')->whereIn('id', $ids)->delete();
        $stats['deleted'] = $deleted;
        $stats['message'] = 'deleted '.$deleted.' general logs older than '.$retention.' days';
        if ($hasMore) {
            $stats['has_more'] = true;
            try {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_general_logs',
                    'payload_json' => json_encode([
                        'retention_days' => $retention,
                        'batch_limit' => $batchLimit,
                        'auto' => !empty($payload['auto'])
                    ], JSON_UNESCAPED_UNICODE),
                    'priority' => intval($job->priority ?? 5),
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
            } catch (\Throwable $e) {
                $stats['warnings'][] = 'enqueue_failed';
                cfmod_report_exception('cleanup_general_logs_enqueue', $e);
            }
        }
        if ($deleted > 0 && function_exists('cloudflare_subdomain_log')) {
            cloudflare_subdomain_log('cleanup_general_logs', [
                'deleted' => $deleted,
                'cutoff' => $cutoff,
                'has_more' => $hasMore ? 1 : 0
            ]);
        }
    } catch (\Throwable $e) {
        $stats['warnings'][] = 'cleanup_failed';
        $stats['message'] = 'general log cleanup failed';
        cfmod_report_exception('cleanup_general_logs', $e);
    }
    return $stats;
}

function cfmod_job_cleanup_sync_logs($job, array $payload = []): array {
    $stats = [
        'deleted' => 0,
        'warnings' => [],
    ];
    try {
        $settings = cfmod_get_settings();
        $retention = intval($payload['retention_days'] ?? ($settings['sync_logs_retention_days'] ?? 0));
        if ($retention <= 0) {
            $stats['message'] = 'sync log cleanup disabled';
            return $stats;
        }
        $batchLimit = intval($payload['batch_limit'] ?? 2000);
        if ($batchLimit <= 0) { $batchLimit = 2000; }
        $batchLimit = max(100, min(5000, $batchLimit));
        $cutoff = date('Y-m-d H:i:s', time() - $retention * 86400);

        $rowsRaw = Capsule::table('mod_cloudflare_sync_results')
            ->where('created_at', '<', $cutoff)
            ->orderBy('id', 'asc')
            ->limit($batchLimit + 1)
            ->get();
        if ($rowsRaw instanceof \Illuminate\Support\Collection) {
            $rowsRaw = $rowsRaw->all();
        }
        $rowCount = is_array($rowsRaw) ? count($rowsRaw) : 0;
        if ($rowCount === 0) {
            $stats['message'] = 'no sync logs to cleanup';
            return $stats;
        }
        $hasMore = $rowCount > $batchLimit;
        $batchRows = $hasMore ? array_slice($rowsRaw, 0, $batchLimit) : $rowsRaw;
        $ids = [];
        foreach ($batchRows as $row) {
            $id = is_object($row) ? ($row->id ?? null) : ($row['id'] ?? null);
            if ($id !== null) {
                $ids[] = (int) $id;
            }
        }
        if (empty($ids)) {
            $stats['message'] = 'no sync logs to cleanup';
            return $stats;
        }
        $deleted = Capsule::table('mod_cloudflare_sync_results')->whereIn('id', $ids)->delete();
        $stats['deleted'] = $deleted;
        $stats['message'] = 'deleted '.$deleted.' sync logs older than '.$retention.' days';
        if ($hasMore) {
            $stats['has_more'] = true;
            try {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_sync_logs',
                    'payload_json' => json_encode([
                        'retention_days' => $retention,
                        'batch_limit' => $batchLimit,
                        'auto' => !empty($payload['auto'])
                    ], JSON_UNESCAPED_UNICODE),
                    'priority' => intval($job->priority ?? 6),
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
            } catch (\Throwable $e) {
                $stats['warnings'][] = 'enqueue_failed';
                cfmod_report_exception('cleanup_sync_logs_enqueue', $e);
            }
        }
        if ($deleted > 0 && function_exists('cloudflare_subdomain_log')) {
            cloudflare_subdomain_log('cleanup_sync_logs', [
                'deleted' => $deleted,
                'cutoff' => $cutoff,
                'has_more' => $hasMore ? 1 : 0
            ]);
        }
    } catch (\Throwable $e) {
        $stats['warnings'][] = 'cleanup_failed';
        $stats['message'] = 'sync log cleanup failed';
        cfmod_report_exception('cleanup_sync_logs', $e);
    }
    return $stats;
}

function cfmod_job_cleanup_user_subdomains($job, array $payload = []): array {
    $userid = intval($payload['userid'] ?? 0);
    if ($userid <= 0) {
        throw new \RuntimeException('cleanup_user_subdomains requires userid');
    }
    $deleteRecords = !empty($payload['delete_records']);
    $deleteDomains = !empty($payload['delete_domains']);
    $stats = [
        'userid' => $userid,
        'processed_subdomains' => 0,
        'deleted_subdomains' => 0,
        'dns_records_deleted' => 0,
        'warnings' => [],
    ];
    if (!$deleteRecords && !$deleteDomains) {
        $stats['message'] = 'nothing to cleanup';
        return $stats;
    }

    $batchSize = intval($payload['batch_size'] ?? 50);
    if ($batchSize <= 0) {
        $batchSize = 50;
    }
    $batchSize = max(10, min(200, $batchSize));
    $cursor = intval($payload['cursor_id'] ?? 0);

    $subsCollection = Capsule::table('mod_cloudflare_subdomain')
        ->where('userid', $userid)
        ->where('id', '>', $cursor)
        ->orderBy('id', 'asc')
        ->limit($batchSize + 1)
        ->get();
    if (!($subsCollection instanceof \Illuminate\Support\Collection)) {
        $subsCollection = new \Illuminate\Support\Collection(is_array($subsCollection) ? $subsCollection : (array) $subsCollection);
    }
    if ($subsCollection->count() === 0) {
        $stats['message'] = 'no subdomains to cleanup';
        return $stats;
    }

    $hasMore = $subsCollection->count() > $batchSize;
    $subs = $hasMore ? $subsCollection->slice(0, $batchSize)->values() : $subsCollection->values();

    foreach ($subs as $sub) {
        $stats['processed_subdomains']++;
        try {
            if ($deleteRecords) {
                $deleted = cfmod_admin_deep_delete_subdomain(null, $sub);
                $stats['dns_records_deleted'] += $deleted;
            }
            if ($deleteDomains) {
                Capsule::transaction(function () use ($sub, $deleteRecords) {
                    if (!$deleteRecords) {
                        Capsule::table('mod_cloudflare_dns_records')->where('subdomain_id', $sub->id)->delete();
                    }
                    Capsule::table('mod_cloudflare_subdomain')->where('id', $sub->id)->delete();
                    if (!empty($sub->userid)) {
                        Capsule::table('mod_cloudflare_subdomain_quotas')
                            ->where('userid', $sub->userid)
                            ->where('used_count', '>', 0)
                            ->decrement('used_count');
                    }
                });
                $stats['deleted_subdomains']++;
                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('cleanup_user_subdomain', [
                        'subdomain' => $sub->subdomain,
                        'userid' => $userid,
                    ], $userid, $sub->id);
                }
            }
        } catch (\Throwable $e) {
            $stats['warnings'][] = 'subdomain:' . $sub->id;
            cfmod_report_exception('cleanup_user_subdomains', $e);
        }
    }

    if ($hasMore) {
        $last = $subs->last();
        $nextCursor = $last ? ($last->id ?? null) : null;
        if ($nextCursor) {
            $newPayload = $payload;
            $newPayload['cursor_id'] = $nextCursor;
            try {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_user_subdomains',
                    'payload_json' => json_encode($newPayload, JSON_UNESCAPED_UNICODE),
                    'priority' => intval($job->priority ?? 8),
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                $stats['has_more'] = true;
                $stats['next_cursor'] = $nextCursor;
            } catch (\Throwable $e) {
                $stats['warnings'][] = 'enqueue_failed';
                cfmod_report_exception('cleanup_user_subdomains_enqueue', $e);
            }
        }
    } else {
        $stats['message'] = 'cleanup complete';
    }

    return $stats;
}

function cfmod_job_cleanup_domain_gifts($job, array $payload = []): array {
    $stats = [
        'expired' => 0,
        'warnings' => [],
    ];
    $limit = intval($payload['batch_size'] ?? 200);
    $limit = max(20, min(500, $limit));
    try {
        $nowStr = date('Y-m-d H:i:s');
        $pending = Capsule::table('mod_cloudflare_domain_gifts')
            ->where('status', 'pending')
            ->where('expires_at', '<', $nowStr)
            ->orderBy('id', 'asc')
            ->limit($limit)
            ->get();
        if (!($pending instanceof Collection)) {
            if (is_array($pending)) {
                $pending = new Collection($pending);
            } elseif ($pending instanceof \Traversable) {
                $pending = new Collection(iterator_to_array($pending));
            } elseif ($pending === null) {
                $pending = new Collection();
            } else {
                $pending = new Collection([$pending]);
            }
        }
        if ($pending->isEmpty()) {
            $stats['message'] = 'no expired gifts';
            return $stats;
        }
        foreach ($pending as $gift) {
            Capsule::transaction(function () use ($gift, $nowStr, &$stats) {
                $fresh = Capsule::table('mod_cloudflare_domain_gifts')
                    ->where('id', $gift->id)
                    ->lockForUpdate()
                    ->first();
                if (!$fresh || $fresh->status !== 'pending') {
                    return;
                }
                if (strtotime($fresh->expires_at ?? '') > time()) {
                    return;
                }
                Capsule::table('mod_cloudflare_domain_gifts')
                    ->where('id', $fresh->id)
                    ->update([
                        'status' => 'expired',
                        'cancelled_at' => $nowStr,
                        'updated_at' => $nowStr,
                    ]);
                Capsule::table('mod_cloudflare_subdomain')
                    ->where('id', $fresh->subdomain_id)
                    ->where('gift_lock_id', $fresh->id)
                    ->update([
                        'gift_lock_id' => null,
                        'updated_at' => $nowStr,
                    ]);
                $stats['expired']++;
            });
        }
        $stats['message'] = 'expired ' . $stats['expired'] . ' gifts';
        if ($pending->count() === $limit) {
            $stats['has_more'] = true;
        }
    } catch (\Throwable $e) {
        $stats['warnings'][] = 'gift_cleanup_failed';
        $stats['message'] = 'gift cleanup failed';
        cfmod_report_exception('cleanup_domain_gifts', $e);
    }
    return $stats;
}

function cfmod_job_cleanup_orphan_dns($job, array $payload = []): array {
    $stats = CfAdminActionService::executeOrphanScan($payload);
    if (is_array($stats)) {
        $stats['job_id'] = $job->id ?? null;
        $hasMore = !empty($stats['has_more']);
        if ($hasMore) {
            try {
                $nextPayload = $payload;
                $nextPayload['cursor_mode'] = 'resume';
                $nextJobId = Capsule::table('mod_cloudflare_jobs')->insertGetId([
                    'type' => 'cleanup_orphan_dns',
                    'payload_json' => json_encode($nextPayload, JSON_UNESCAPED_UNICODE),
                    'priority' => intval($job->priority ?? 12),
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => null,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
                $stats['next_job_id'] = $nextJobId;
            } catch (\Throwable $e) {
                if (!isset($stats['warnings']) || !is_array($stats['warnings'])) {
                    $stats['warnings'] = [];
                }
                $stats['warnings'][] = 'enqueue_failed';
                cfmod_report_exception('cleanup_orphan_dns_enqueue', $e);
            }
        }
    }
    return $stats;
}

if (php_sapi_name() === 'cli' && basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    $max = isset($argv[1]) ? intval($argv[1]) : 3;
    run_cf_queue_once(max(1, $max));
}

