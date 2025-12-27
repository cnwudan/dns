<?php
/**
 * WHMCS7 域名分发插件数据库优化脚本
 * 解决 mod_cloudflare_risk_events 表性能问题
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

class RiskEventsOptimizer {
    
    /**
     * 执行数据库优化
     */
    public static function optimize() {
        echo "开始优化 mod_cloudflare_risk_events 表...\n";
        
        try {
            // 1. 添加索引
            self::addIndexes();
            
            // 2. 清理旧数据
            $cleaned = self::cleanupOldData();
            
            // 3. 优化表结构
            self::optimizeTable();
            
            // 4. 创建清理任务
            self::createCleanupJob();
            
            echo "优化完成！清理了 {$cleaned} 条记录\n";
            
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
     * 清理旧数据
     */
    private static function cleanupOldData() {
        echo "清理旧数据...\n";
        
        $totalCleaned = 0;
        
        // 清理所有低风险事件（直接删除）
        $lowRiskCleaned = Capsule::table('mod_cloudflare_risk_events')
            ->where('level', 'low')
            ->delete();
        $totalCleaned += $lowRiskCleaned;
        echo "✓ 清理了 {$lowRiskCleaned} 条低风险事件（全部删除）\n";
        
        // 清理所有中等风险事件（直接删除）
        $mediumRiskCleaned = Capsule::table('mod_cloudflare_risk_events')
            ->where('level', 'medium')
            ->delete();
        $totalCleaned += $mediumRiskCleaned;
        echo "✓ 清理了 {$mediumRiskCleaned} 条中等风险事件（全部删除）\n";
        
        // 清理超过72小时的高风险事件
        $highRiskCleaned = Capsule::table('mod_cloudflare_risk_events')
            ->where('level', 'high')
            ->where('created_at', '<', date('Y-m-d H:i:s', strtotime('-72 hours')))
            ->delete();
        $totalCleaned += $highRiskCleaned;
        echo "✓ 清理了 {$highRiskCleaned} 条高风险事件（超过72小时）\n";
        
        // 清理重复的扫描摘要事件
        $duplicateCleaned = self::cleanupDuplicateSummaries();
        $totalCleaned += $duplicateCleaned;
        echo "✓ 清理了 {$duplicateCleaned} 条重复摘要事件\n";
        
        return $totalCleaned;
    }
    
    /**
     * 清理重复的扫描摘要事件
     */
    private static function cleanupDuplicateSummaries() {
        // 查找重复的摘要事件
        $duplicates = Capsule::table('mod_cloudflare_risk_events')
            ->select('subdomain_id', Capsule::raw('DATE(created_at) as date'), Capsule::raw('COUNT(*) as count'))
            ->where('source', 'summary')
            ->groupBy('subdomain_id', Capsule::raw('DATE(created_at)'))
            ->having('count', '>', 1)
            ->get();
        
        $cleaned = 0;
        foreach ($duplicates as $dup) {
            // 保留最新的，删除其他的
            $toDelete = Capsule::table('mod_cloudflare_risk_events')
                ->where('subdomain_id', $dup->subdomain_id)
                ->where('source', 'summary')
                ->whereRaw('DATE(created_at) = ?', [$dup->date])
                ->orderBy('id', 'desc')
                ->skip(1) // 跳过最新的
                ->get();
            
            foreach ($toDelete as $record) {
                Capsule::table('mod_cloudflare_risk_events')->where('id', $record->id)->delete();
                $cleaned++;
            }
        }
        
        return $cleaned;
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
     * 创建自动清理任务
     */
    private static function createCleanupJob() {
        echo "创建自动清理任务...\n";
        
        try {
            // 检查是否已存在清理任务
            $existingJob = Capsule::table('mod_cloudflare_jobs')
                ->where('type', 'cleanup_risk_events')
                ->where('status', 'pending')
                ->first();
            
            if (!$existingJob) {
                Capsule::table('mod_cloudflare_jobs')->insert([
                    'type' => 'cleanup_risk_events',
                    'payload_json' => json_encode(['auto' => true]),
                    'priority' => 5,
                    'status' => 'pending',
                    'attempts' => 0,
                    'next_run_at' => date('Y-m-d H:i:s', strtotime('+1 day')),
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                echo "✓ 自动清理任务创建成功\n";
            } else {
                echo "⚠ 自动清理任务已存在\n";
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
    echo "WHMCS7 域名分发插件数据库优化工具\n";
    echo "========================================\n\n";
    
    // 显示当前统计信息
    echo "当前表统计信息:\n";
    $stats = RiskEventsOptimizer::getStats();
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
    if (RiskEventsOptimizer::optimize()) {
        echo "\n优化后的统计信息:\n";
        $newStats = RiskEventsOptimizer::getStats();
        if ($newStats) {
            echo "总记录数: {$newStats['total']}\n";
            echo "按风险级别分布:\n";
            foreach ($newStats['by_level'] as $level) {
                echo "  {$level->level}: {$level->count}\n";
            }
        }
    }
    
    echo "\n========================================\n";
    echo "优化完成！\n";
    echo "========================================\n";
}
