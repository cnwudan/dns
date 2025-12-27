<?php
// 手动结算邀请排行榜：生成指定周期（或上一期）的快照与奖励
// 用法示例：
//   php cli_settle_invite.php                  # 依据配置自适应：若设置了 invite_cycle_start 则补齐历史未结算期，否则结算上一期（等同周一逻辑）
//   php cli_settle_invite.php --period-end=2025-08-20  # 指定期末日期，周期长度取自配置 invite_leaderboard_period_days
//   php cli_settle_invite.php --period-start=2025-08-01 --period-end=2025-08-07
//   php cli_settle_invite.php --dry-run        # 仅计算不写库

declare(strict_types=1);
require_once __DIR__ . '/lib/autoload.php';
CfModuleSettings::bootstrap();

// 1) 尝试自动定位 WHMCS 根目录以加载 init.php
$cwd = getcwd();
$dirs = [ $cwd, dirname($cwd), dirname(dirname($cwd)), dirname(dirname(dirname($cwd))) ];
$bootstrapped = false;
foreach ($dirs as $dir) {
    if (is_file($dir . '/init.php')) {
        require_once $dir . '/init.php';
        $bootstrapped = true;
        break;
    }
}
if (!$bootstrapped) {
    fwrite(STDERR, "无法定位 WHMCS init.php，请在 WHMCS 安装目录或其上级运行。\n");
    exit(1);
}

use WHMCS\Database\Capsule;

$moduleSlug = defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
$moduleSlugLegacy = defined('CF_MODULE_NAME_LEGACY') ? CF_MODULE_NAME_LEGACY : 'cloudflare_subdomain';

cf_ensure_module_settings_migrated();

function read_settings(): array {
    global $moduleSlug, $moduleSlugLegacy;
    $settings = [];
    $rows = Capsule::table('tbladdonmodules')->where('module', $moduleSlug)->get();
    if (count($rows) === 0 && $moduleSlugLegacy !== $moduleSlug) {
        $rows = Capsule::table('tbladdonmodules')->where('module', $moduleSlugLegacy)->get();
    }
    foreach ($rows as $r) { $settings[$r->setting] = $r->value; }
    return $settings;
}

function parse_args(): array {
    $opts = [
        'period-start:',
        'period-end:',
        'dry-run',
        'help'
    ];
    $g = getopt('', $opts);
    return [
        'period_start' => isset($g['period-start']) ? trim((string)$g['period-start']) : null,
        'period_end'   => isset($g['period-end']) ? trim((string)$g['period-end']) : null,
        'dry_run'      => isset($g['dry-run']),
        'help'         => isset($g['help'])
    ];
}

function usage(): void {
    echo "用法:\n";
    echo "  php cli_settle_invite.php [--period-start=YYYY-MM-DD] [--period-end=YYYY-MM-DD] [--dry-run]\n";
    echo "说明:\n";
    echo "  - 未指定周期时：\n";
    echo "      如果设置了 invite_cycle_start，则会补齐所有已结束且未快照的周期；\n";
    echo "      否则按每周模式结算上一期（等同周一 cron 逻辑）。\n";
    echo "  - 指定了 period-end 而未指定 period-start 时，period-start=period-end-(periodDays-1)。\n";
}

function ensure_tables(): void {
    // 和后台模板中一致：确保快照与奖励表存在
    if (!Capsule::schema()->hasTable('mod_cloudflare_invite_leaderboard')) {
        Capsule::schema()->create('mod_cloudflare_invite_leaderboard', function ($table) {
            $table->increments('id');
            $table->date('period_start');
            $table->date('period_end');
            $table->text('top_json');
            $table->timestamps();
            $table->index(['period_start','period_end']);
        });
    }
    if (!Capsule::schema()->hasTable('mod_cloudflare_invite_rewards')) {
        Capsule::schema()->create('mod_cloudflare_invite_rewards', function ($table) {
            $table->increments('id');
            $table->date('period_start');
            $table->date('period_end');
            $table->integer('inviter_userid')->unsigned();
            $table->string('code', 64)->nullable();
            $table->integer('rank')->default(0);
            $table->integer('count')->default(0);
            $table->string('status', 20)->default('eligible');
            $table->dateTime('requested_at')->nullable();
            $table->dateTime('claimed_at')->nullable();
            $table->text('notes')->nullable();
            $table->timestamps();
            $table->index(['period_start','period_end']);
            $table->index(['inviter_userid','period_start','period_end']);
        });
    }
}

function settle_period(string $periodStart, string $periodEnd, int $topN, bool $dryRun): void {
    echo "结算周期: {$periodStart} ~ {$periodEnd}" . ($dryRun ? " [DRY-RUN]" : "") . "\n";
    $exists = Capsule::table('mod_cloudflare_invite_leaderboard')
        ->where('period_start', $periodStart)
        ->where('period_end', $periodEnd)
        ->count();
    if ($exists) {
        echo "- 已存在快照，跳过\n";
        return;
    }

    $winners = Capsule::table('mod_cloudflare_invitation_claims as ic')
        ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as cnt'))
        ->whereBetween('ic.created_at', [$periodStart.' 00:00:00', $periodEnd.' 23:59:59'])
        ->groupBy('ic.inviter_userid')
        ->orderBy('cnt', 'desc')
        ->limit($topN)
        ->get();

    $top = [];
    foreach ($winners as $idx => $w) {
        $codeRow = Capsule::table('mod_cloudflare_invitation_codes')->select('code')->where('userid', $w->inviter_userid)->first();
        $top[] = [
            'rank' => $idx + 1,
            'inviter_userid' => (int) $w->inviter_userid,
            'code' => $codeRow ? ($codeRow->code ?? '') : '',
            'count' => (int) $w->cnt
        ];
    }

    echo "- TopN 计算完成，条目数：" . count($top) . "\n";
    if ($dryRun) { return; }

    Capsule::table('mod_cloudflare_invite_leaderboard')->insert([
        'period_start' => $periodStart,
        'period_end' => $periodEnd,
        'top_json' => json_encode($top, JSON_UNESCAPED_UNICODE),
        'created_at' => date('Y-m-d H:i:s'),
        'updated_at' => date('Y-m-d H:i:s')
    ]);
    foreach ($top as $row) {
        $existsReward = Capsule::table('mod_cloudflare_invite_rewards')
            ->where('period_start', $periodStart)
            ->where('period_end', $periodEnd)
            ->where('inviter_userid', $row['inviter_userid'])
            ->count();
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
    echo "- 已写入快照与奖励表\n";
}

function main(): int {
    $args = parse_args();
    if ($args['help']) { usage(); return 0; }

    $settings = read_settings();
    $enabled = (($settings['enable_invite_leaderboard'] ?? 'on') === 'on') || (($settings['enable_invite_leaderboard'] ?? '1') == '1');
    if (!$enabled) {
        fwrite(STDERR, "警告：enable_invite_leaderboard 未开启，仍可手动结算（继续）。\n");
    }
    $topN = max(1, (int) ($settings['invite_leaderboard_top'] ?? 5));
    $periodDays = max(1, (int) ($settings['invite_leaderboard_period_days'] ?? 7));
    $cycleStart = trim((string) ($settings['invite_cycle_start'] ?? ''));
    $dryRun = (bool) $args['dry_run'];

    ensure_tables();

    $psArg = $args['period_start'];
    $peArg = $args['period_end'];
    if ($psArg && !$peArg) {
        fwrite(STDERR, "必须同时提供 --period-start 与 --period-end，或只提供 --period-end。\n");
        return 2;
    }
    if ($peArg && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $peArg)) {
        fwrite(STDERR, "period-end 格式错误，应为 YYYY-MM-DD。\n");
        return 2;
    }
    if ($psArg && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $psArg)) {
        fwrite(STDERR, "period-start 格式错误，应为 YYYY-MM-DD。\n");
        return 2;
    }

    if ($peArg) {
        $periodEnd = $peArg;
        $periodStart = $psArg ?: date('Y-m-d', strtotime($periodEnd . ' -' . ($periodDays - 1) . ' days'));
        settle_period($periodStart, $periodEnd, $topN, $dryRun);
        return 0;
    }

    // 未指定周期：
    $todayYmd = date('Y-m-d');
    if ($cycleStart !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $cycleStart)) {
        $startTs = strtotime($cycleStart);
        $todayTs = strtotime($todayYmd);
        if ($todayTs <= $startTs) {
            fwrite(STDERR, "当前日期早于周期开始日期，无可结算周期。\n");
            return 0;
        }
        $maxK = (int) floor( ($todayTs - $startTs) / 86400 / $periodDays );
        for ($k = 0; $k <= $maxK; $k++) {
            $periodStart = date('Y-m-d', strtotime('+' . ($k * $periodDays) . ' days', $startTs));
            $periodEnd   = date('Y-m-d', strtotime($periodStart . ' +' . ($periodDays - 1) . ' days'));
            if ($todayYmd <= $periodEnd) { continue; } // 仅处理已结束的周期
            settle_period($periodStart, $periodEnd, $topN, $dryRun);
        }
        return 0;
    }

    // 默认每周模式：结算上一期（昨天为期末）
    $periodEnd = date('Y-m-d', strtotime('yesterday'));
    $periodStart = date('Y-m-d', strtotime($periodEnd . ' -' . ($periodDays - 1) . ' days'));
    settle_period($periodStart, $periodEnd, $topN, $dryRun);
    return 0;
}

exit(main());

