<?php
/**
 * WHMCS7 域名分发插件数据库优化脚本 V2
 * 新策略：只保存高风险事件，中低风险直接过滤
 */

if (!defined('WHMCS')) {
    // 尝试引导WHMCS环境
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

class RiskEventsOptimizerV2 {
    
    /**
     * 执行数据库优化
     */
    public static function optimize() {
        echo "开始优化 mod_cloudflare_risk_events 表（新策略：只保存高风险）...\n";
        
        try {
            // 1. 添加索引
            self::addIndexes();
            
            // 2. 清理所有中低风险数据
            $cleaned = self::cleanupNonHighRiskData();
            
            // 3. 优化表结构
            self::optimizeTable();
            
            // 4. 创建简化的清理任务
            self::createSimplifiedCleanupJob();
            
            echo "优化完成！清理了 {$cleaned} 条中低风险记录\n";
            echo "新策略：只保存高风险事件72小时\n";
            
        } catch (Exception $e) {
            echo "优化失败: " . $e->getMessage() . "\n";
            return false;
        }
        
        return true;
    }
    
    /**
     * 添加索引
     */
    private static function addIndexes() {
        echo "添加索引...\n";
        
        $indexes = [
            'idx_subdomain_created' => '(`subdomain_id`, `created_at`)',
            'idx_level_created' => '(`level`, `created_at`)',
            'idx_source_created' => '(`source`, `created_at`)'
        ];
        
        foreach ($indexes as $name => $columns) {
            try {
                Capsule::statement("ALTER TABLE `mod_cloudflare_risk_events` ADD INDEX `{$name}` {$columns}");
                echo "✓ 索引 {$name} 添加成功\n";
            } catch (Exception $e) {
                if (strpos($e->getMessage(), 'Duplicate key name') !== false) {
                    echo "⚠ 索引 {$name} 已存在\n";
                } else {
                    echo "❌ 索引 {$name} 添加失败: " . $e->getMessage() . "\n";
                }
            }
        }
    }
    
    /**
     * 清理所有中低风险数据
     */
    private static function cleanupNonHighRiskData() {
        echo "清理中低风险数据...\n";
        
        $totalCleaned = 0;
        
        // 清理所有低风险事件
        $lowRiskCleaned = Capsule::table('mod_cloudflare_risk_events')
            ->where('level', 'low')
            ->delete();
        $totalCleaned += $lowRiskCleaned;
        echo "✓ 清理了 {$lowRiskCleaned} 条低风险事件\n";
        
        // 清理所有中等风险事件
        $mediumRiskCleaned = Capsule::table('mod_cloudflare_risk_events')
            ->where('level', 'medium')
            ->delete();
        $totalCleaned += $mediumRiskCleaned;
        echo "✓ 清理了 {$mediumRiskCleaned} 条中等风险事件\n";
        
        // 清理超过72小时的高风险事件
        $highRiskCleaned = Capsule::table('mod_cloudflare_risk_events')
            ->where('level', 'high')
            ->where('created_at', '<', date('Y-m-d H:i:s', strtotime('-72 hours')))
            ->delete();
        $totalCleaned += $highRiskCleaned;
        echo "✓ 清理了 {$highRiskCleaned} 条高风险事件（超过72小时）\n";
        
        return $totalCleaned;
    }
    
    /**
     * 优化表结构
     */
    private static function optimizeTable() {
        echo "优化表结构...\n";
        
        try {
            Capsule::statement("OPTIMIZE TABLE `mod_cloudflare_risk_events`");
            echo "✓ 表优化完成\n";
        } catch (Exception $e) {
            echo "⚠ 表优化失败: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * 创建简化的清理任务
     */
    private static function createSimplifiedCleanupJob() {
        echo "创建简化清理任务...\n";
        
        try {
            // 检查是否已存在清理任务
            $existingJob = Capsule::table('mod_cloudflare_jobs')
                ->where('type', 'cleanup_risk_events')
                ->where('status', 'pending')
                ->first();
            
            if (!$existingJob) {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_risk_events',
                    'payload_json' => json_encode(['strategy' => 'high_risk_only', 'retention_hours' => 72]),
                    'priority' => 5,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => date('Y-m-d H:i:s', strtotime('+1 day')),
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                echo "✓ 简化清理任务创建成功\n";
            } else {
                echo "⚠ 清理任务已存在\n";
            }
        } catch (Exception $e) {
            echo "❌ 创建清理任务失败: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * 获取表统计信息
     */
    public static function getStats() {
        try {
            $total = Capsule::table('mod_cloudflare_risk_events')->count();
            $byLevel = Capsule::table('mod_cloudflare_risk_events')
                ->select('level', Capsule::raw('COUNT(*) as count'))
                ->groupBy('level')
                ->get();
            $bySource = Capsule::table('mod_cloudflare_risk_events')
                ->select('source', Capsule::raw('COUNT(*) as count'))
                ->groupBy('source')
                ->get();
            $oldest = Capsule::table('mod_cloudflare_risk_events')
                ->orderBy('created_at', 'asc')
                ->value('created_at');
            $newest = Capsule::table('mod_cloudflare_risk_events')
                ->orderBy('created_at', 'desc')
                ->value('created_at');
            
            return [
                'total' => $total,
                'by_level' => $byLevel,
                'by_source' => $bySource,
                'oldest' => $oldest,
                'newest' => $newest
            ];
        } catch (Exception $e) {
            return null;
        }
    }
}

// 如果直接运行此脚本
if (php_sapi_name() === 'cli' && basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "========================================\n";
    echo "WHMCS7 域名分发插件数据库优化工具 V2\n";
    echo "新策略：只保存高风险事件72小时\n";
    echo "========================================\n\n";
    
    // 显示当前统计信息
    echo "当前表统计信息:\n";
    $stats = RiskEventsOptimizerV2::getStats();
    if ($stats) {
        echo "总记录数: {$stats['total']}\n";
        echo "按风险级别分布:\n";
        foreach ($stats['by_level'] as $level) {
            echo "  {$level->level}: {$level->count}\n";
        }
        echo "按来源分布:\n";
        foreach ($stats['by_source'] as $source) {
            echo "  {$source->source}: {$source->count}\n";
        }
        echo "最早记录: {$stats['oldest']}\n";
        echo "最新记录: {$stats['newest']}\n";
    } else {
        echo "无法获取统计信息\n";
    }
    
    echo "\n";
    
    // 执行优化
    if (RiskEventsOptimizerV2::optimize()) {
        echo "\n优化后的统计信息:\n";
        $newStats = RiskEventsOptimizerV2::getStats();
        if ($newStats) {
            echo "总记录数: {$newStats['total']}\n";
            echo "按风险级别分布:\n";
            foreach ($newStats['by_level'] as $level) {
                echo "  {$level->level}: {$level->count}\n";
            }
        }
        
        echo "\n🎯 新策略说明:\n";
        echo "- 只保存高风险事件（level='high' 或 score >= threshold）\n";
        echo "- 高风险事件保留72小时后自动清理\n";
        echo "- 中低风险事件直接过滤，不保存到数据库\n";
        echo "- 大幅减少数据库存储和查询压力\n";
    }
    
    echo "\n========================================\n";
    echo "优化完成！\n";
    echo "========================================\n";
}
