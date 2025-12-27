<?php
/**
 * 数据库性能检查脚本
 * 
 * 用途：检查当前插件的数据库性能状态
 * 使用：php 性能检查脚本.php
 */

// 检查是否在CLI模式
if (php_sapi_name() !== 'cli') {
    die('此脚本只能在命令行模式下运行');
}

// 加载WHMCS
require_once dirname(__DIR__, 3) . '/init.php';

use WHMCS\Database\Capsule;

echo "\n";
echo "========================================\n";
echo "🔍 数据库性能检查工具\n";
echo "========================================\n";
echo "开始时间：" . date('Y-m-d H:i:s') . "\n\n";

// 检查数据库连接
try {
    Capsule::connection()->getPdo();
    echo "✅ 数据库连接正常\n\n";
} catch (Exception $e) {
    echo "❌ 数据库连接失败：" . $e->getMessage() . "\n";
    exit(1);
}

// ========================================
// 1. 检查表大小和记录数
// ========================================
echo "========================================\n";
echo "📊 表数据统计\n";
echo "========================================\n";

$tables = [
    'mod_cloudflare_subdomain' => '子域名',
    'mod_cloudflare_dns_records' => 'DNS记录',
    'mod_cloudflare_subdomain_quotas' => '用户配额',
    'mod_cloudflare_invitation_codes' => '邀请码',
    'mod_cloudflare_invitation_claims' => '邀请记录',
    'mod_cloudflare_api_keys' => 'API密钥',
    'mod_cloudflare_api_logs' => 'API日志',
    'mod_cloudflare_domain_risk' => '域名风险',
    'mod_cloudflare_risk_events' => '风险事件',
    'mod_cloudflare_rootdomains' => '根域名',
    'mod_cloudflare_forbidden_domains' => '禁止域名',
];

$totalRows = 0;
$totalSize = 0;

foreach ($tables as $tableName => $desc) {
    try {
        $exists = Capsule::schema()->hasTable($tableName);
        if (!$exists) {
            echo "⚠️  {$desc}表 ({$tableName}) - 不存在\n";
            continue;
        }
        
        $count = Capsule::table($tableName)->count();
        $totalRows += $count;
        
        // 获取表大小
        $sizeQuery = Capsule::select("
            SELECT 
                ROUND((data_length + index_length) / 1024 / 1024, 2) AS size_mb
            FROM information_schema.tables 
            WHERE table_schema = DATABASE() 
            AND table_name = ?
        ", [$tableName]);
        
        $sizeMb = $sizeQuery[0]->size_mb ?? 0;
        $totalSize += $sizeMb;
        
        $statusIcon = $count > 10000 ? '⚠️' : '✅';
        echo "{$statusIcon} {$desc}表 ({$tableName})\n";
        echo "   记录数：" . number_format($count) . " 条\n";
        echo "   大小：{$sizeMb} MB\n";
        
        if ($tableName === 'mod_cloudflare_risk_events' && $count > 50000) {
            echo "   🔴 警告：风险事件表过大，建议清理！\n";
        }
        if ($tableName === 'mod_cloudflare_api_logs' && $count > 100000) {
            echo "   🔴 警告：API日志表过大，建议清理！\n";
        }
        
    } catch (Exception $e) {
        echo "❌ {$desc}表检查失败：" . $e->getMessage() . "\n";
    }
}

echo "\n总记录数：" . number_format($totalRows) . " 条\n";
echo "总大小：{$totalSize} MB\n";

// ========================================
// 2. 检查索引
// ========================================
echo "\n========================================\n";
echo "🔑 索引检查\n";
echo "========================================\n";

$requiredIndexes = [
    'mod_cloudflare_subdomain' => ['idx_status', 'idx_userid_status', 'idx_subdomain_unique'],
    'mod_cloudflare_dns_records' => ['idx_subdomain_id', 'idx_subdomain_type'],
    'mod_cloudflare_invitation_codes' => ['idx_code_unique', 'idx_userid_unique'],
    'mod_cloudflare_invitation_claims' => ['idx_inviter', 'idx_invitee_code', 'idx_created_at'],
    'mod_cloudflare_subdomain_quotas' => ['idx_userid_unique'],
    'mod_cloudflare_api_keys' => ['idx_api_key_unique', 'idx_userid', 'idx_status'],
];

$missingIndexes = [];

foreach ($requiredIndexes as $tableName => $indexes) {
    try {
        $exists = Capsule::schema()->hasTable($tableName);
        if (!$exists) continue;
        
        echo "\n表：{$tableName}\n";
        
        foreach ($indexes as $indexName) {
            $indexExists = Capsule::select("
                SELECT COUNT(*) as cnt
                FROM information_schema.statistics 
                WHERE table_schema = DATABASE() 
                AND table_name = ? 
                AND index_name = ?
            ", [$tableName, $indexName]);
            
            if ($indexExists[0]->cnt > 0) {
                echo "  ✅ {$indexName}\n";
            } else {
                echo "  ❌ {$indexName} - 缺失！\n";
                $missingIndexes[] = "{$tableName}.{$indexName}";
            }
        }
    } catch (Exception $e) {
        echo "  ❌ 检查失败：" . $e->getMessage() . "\n";
    }
}

if (count($missingIndexes) > 0) {
    echo "\n🔴 发现 " . count($missingIndexes) . " 个缺失的索引！\n";
    echo "建议立即执行：立即优化-添加索引.sql\n";
} else {
    echo "\n✅ 所有索引都已创建\n";
}

// ========================================
// 3. 检查慢查询
// ========================================
echo "\n========================================\n";
echo "⏱️  性能测试\n";
echo "========================================\n";

// 测试1：查询所有子域名（无索引优化前）
$start = microtime(true);
try {
    $count = Capsule::table('mod_cloudflare_subdomain')
        ->where('status', 'active')
        ->count();
    $time = round((microtime(true) - $start) * 1000, 2);
    $status = $time < 100 ? '✅' : ($time < 500 ? '⚠️' : '🔴');
    echo "{$status} 查询活跃域名数量：{$time}ms (记录数：{$count})\n";
} catch (Exception $e) {
    echo "❌ 测试失败：" . $e->getMessage() . "\n";
}

// 测试2：查询用户配额
$start = microtime(true);
try {
    $exists = Capsule::schema()->hasTable('mod_cloudflare_subdomain_quotas');
    if ($exists) {
        $count = Capsule::table('mod_cloudflare_subdomain_quotas')->count();
        $time = round((microtime(true) - $start) * 1000, 2);
        $status = $time < 50 ? '✅' : ($time < 200 ? '⚠️' : '🔴');
        echo "{$status} 查询用户配额：{$time}ms (记录数：{$count})\n";
    }
} catch (Exception $e) {
    echo "❌ 测试失败：" . $e->getMessage() . "\n";
}

// 测试3：查询邀请排行榜
$start = microtime(true);
try {
    $exists = Capsule::schema()->hasTable('mod_cloudflare_invitation_claims');
    if ($exists) {
        $result = Capsule::table('mod_cloudflare_invitation_claims')
            ->select('inviter_userid', Capsule::raw('COUNT(*) as cnt'))
            ->groupBy('inviter_userid')
            ->orderBy('cnt', 'desc')
            ->limit(10)
            ->get();
        $time = round((microtime(true) - $start) * 1000, 2);
        $status = $time < 200 ? '✅' : ($time < 1000 ? '⚠️' : '🔴');
        echo "{$status} 查询排行榜TOP10：{$time}ms\n";
    }
} catch (Exception $e) {
    echo "❌ 测试失败：" . $e->getMessage() . "\n";
}

// 测试4：检查域名是否存在
$start = microtime(true);
try {
    $exists = Capsule::table('mod_cloudflare_subdomain')
        ->where('subdomain', 'test.example.com')
        ->exists();
    $time = round((microtime(true) - $start) * 1000, 2);
    $status = $time < 10 ? '✅' : ($time < 50 ? '⚠️' : '🔴');
    echo "{$status} 检查域名是否存在：{$time}ms\n";
} catch (Exception $e) {
    echo "❌ 测试失败：" . $e->getMessage() . "\n";
}

// ========================================
// 4. 系统建议
// ========================================
echo "\n========================================\n";
echo "💡 优化建议\n";
echo "========================================\n";

$suggestions = [];

// 检查总记录数
if ($totalRows > 50000) {
    $suggestions[] = "🔴 总记录数超过50000，建议清理历史数据";
}

// 检查风险事件
try {
    $exists = Capsule::schema()->hasTable('mod_cloudflare_risk_events');
    if ($exists) {
        $riskCount = Capsule::table('mod_cloudflare_risk_events')->count();
        if ($riskCount > 50000) {
            $suggestions[] = "🔴 风险事件表过大（{$riskCount}条），建议执行清理：database_optimization.sql";
        }
    }
} catch (Exception $e) {}

// 检查API日志
try {
    $exists = Capsule::schema()->hasTable('mod_cloudflare_api_logs');
    if ($exists) {
        $logCount = Capsule::table('mod_cloudflare_api_logs')->count();
        if ($logCount > 100000) {
            $suggestions[] = "🔴 API日志表过大（{$logCount}条），建议定期清理30天前的日志";
        }
    }
} catch (Exception $e) {}

// 检查缺失索引
if (count($missingIndexes) > 0) {
    $suggestions[] = "🔴 发现" . count($missingIndexes) . "个缺失索引，立即执行：立即优化-添加索引.sql";
}

// 检查是否有缓存
$suggestions[] = "⚠️ 建议启用Redis缓存以减少数据库压力";
$suggestions[] = "⚠️ 建议为管理后台列表添加分页功能";

if (count($suggestions) === 0) {
    echo "✅ 当前系统性能良好，无需优化\n";
} else {
    foreach ($suggestions as $i => $suggestion) {
        echo ($i + 1) . ". {$suggestion}\n";
    }
}

// ========================================
// 5. 性能评分
// ========================================
echo "\n========================================\n";
echo "⭐ 性能评分\n";
echo "========================================\n";

$score = 100;

// 扣分项
if (count($missingIndexes) > 0) {
    $score -= count($missingIndexes) * 5;
}
if ($totalRows > 50000) {
    $score -= 10;
}
if (isset($riskCount) && $riskCount > 50000) {
    $score -= 15;
}
if (isset($logCount) && $logCount > 100000) {
    $score -= 10;
}

$score = max(0, $score);

if ($score >= 90) {
    echo "🟢 优秀：{$score}分 - 系统性能良好\n";
} elseif ($score >= 70) {
    echo "🟡 良好：{$score}分 - 有一些优化空间\n";
} elseif ($score >= 50) {
    echo "🟠 一般：{$score}分 - 建议尽快优化\n";
} else {
    echo "🔴 较差：{$score}分 - 需要立即优化！\n";
}

echo "\n========================================\n";
echo "✅ 检查完成！\n";
echo "结束时间：" . date('Y-m-d H:i:s') . "\n";
echo "========================================\n\n";

// ========================================
// 6. 快速修复命令
// ========================================
echo "🚀 快速修复命令：\n\n";
echo "# 1. 添加索引（5-10分钟）\n";
echo "mysql -u用户名 -p数据库名 < 立即优化-添加索引.sql\n\n";
echo "# 2. 清理风险事件（可选）\n";
echo "mysql -u用户名 -p -e \"CALL CleanupRiskEvents()\" 数据库名\n\n";
echo "# 3. 重启PHP-FPM\n";
echo "service php-fpm reload\n\n";


