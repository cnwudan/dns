<?php
/**
 * WHMCS7 域名分发插件性能监控工具
 * 用于监控数据库性能和系统状态
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

class PerformanceMonitor {
    
    /**
     * 获取数据库性能统计
     */
    public static function getDatabaseStats() {
        try {
            // 表大小统计
            $tableStats = Capsule::select("
                SELECT 
                    table_name,
                    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Size (MB)',
                    table_rows,
                    ROUND((data_length / 1024 / 1024), 2) AS 'Data (MB)',
                    ROUND((index_length / 1024 / 1024), 2) AS 'Index (MB)'
                FROM information_schema.tables 
                WHERE table_schema = DATABASE() 
                AND table_name LIKE 'mod_cloudflare_%'
                ORDER BY (data_length + index_length) DESC
            ");
            
            // 风险事件表统计
            $riskStats = Capsule::select("
                SELECT 
                    level,
                    COUNT(*) as count,
                    MIN(created_at) as oldest,
                    MAX(created_at) as newest
                FROM mod_cloudflare_risk_events 
                GROUP BY level
            ");
            
            // 队列任务统计
            $jobStats = Capsule::select("
                SELECT 
                    type,
                    status,
                    COUNT(*) as count,
                    AVG(attempts) as avg_attempts
                FROM mod_cloudflare_jobs 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY type, status
            ");
            
            return [
                'tables' => $tableStats,
                'risk_events' => $riskStats,
                'jobs' => $jobStats
            ];
        } catch (Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
    
    /**
     * 检查慢查询
     */
    public static function checkSlowQueries() {
        try {
            // 检查是否有全表扫描的查询
            $slowQueries = Capsule::select("
                SELECT 
                    sql_text,
                    exec_count,
                    avg_timer_wait/1000000000 as avg_time_seconds,
                    sum_timer_wait/1000000000 as total_time_seconds
                FROM performance_schema.events_statements_summary_by_digest 
                WHERE sql_text LIKE '%mod_cloudflare_risk_events%'
                AND avg_timer_wait > 1000000000  -- 超过1秒
                ORDER BY avg_timer_wait DESC
                LIMIT 10
            ");
            
            return $slowQueries;
        } catch (Exception $e) {
            return ['error' => 'Performance schema not available: ' . $e->getMessage()];
        }
    }
    
    /**
     * 获取索引使用情况
     */
    public static function getIndexUsage() {
        try {
            $indexUsage = Capsule::select("
                SELECT 
                    table_name,
                    index_name,
                    seq_in_index,
                    column_name,
                    cardinality
                FROM information_schema.statistics 
                WHERE table_schema = DATABASE() 
                AND table_name = 'mod_cloudflare_risk_events'
                ORDER BY table_name, index_name, seq_in_index
            ");
            
            return $indexUsage;
        } catch (Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
    
    /**
     * 生成性能报告
     */
    public static function generateReport() {
        echo "========================================\n";
        echo "WHMCS7 域名分发插件性能监控报告\n";
        echo "生成时间: " . date('Y-m-d H:i:s') . "\n";
        echo "========================================\n\n";
        
        // 数据库统计
        echo "📊 数据库统计:\n";
        $dbStats = self::getDatabaseStats();
        if (isset($dbStats['error'])) {
            echo "❌ 错误: " . $dbStats['error'] . "\n\n";
        } else {
            echo "表大小统计:\n";
            foreach ($dbStats['tables'] as $table) {
                echo "  {$table->table_name}: {$table->{'Size (MB)'}} MB ({$table->table_rows} 行)\n";
            }
            
            echo "\n风险事件统计:\n";
            foreach ($dbStats['risk_events'] as $risk) {
                echo "  {$risk->level}: {$risk->count} 条记录\n";
            }
            
            echo "\n队列任务统计 (最近7天):\n";
            foreach ($dbStats['jobs'] as $job) {
                echo "  {$job->type} ({$job->status}): {$job->count} 个任务\n";
            }
        }
        
        // 慢查询检查
        echo "\n🐌 慢查询检查:\n";
        $slowQueries = self::checkSlowQueries();
        if (isset($slowQueries['error'])) {
            echo "⚠ " . $slowQueries['error'] . "\n";
        } elseif (empty($slowQueries)) {
            echo "✅ 未发现慢查询\n";
        } else {
            foreach ($slowQueries as $query) {
                echo "  平均执行时间: " . round($query->avg_time_seconds, 2) . "秒\n";
                echo "  SQL: " . substr($query->sql_text, 0, 100) . "...\n\n";
            }
        }
        
        // 索引使用情况
        echo "\n📈 索引使用情况:\n";
        $indexUsage = self::getIndexUsage();
        if (isset($indexUsage['error'])) {
            echo "❌ 错误: " . $indexUsage['error'] . "\n";
        } else {
            foreach ($indexUsage as $index) {
                echo "  {$index->index_name}: {$index->column_name} (基数: {$index->cardinality})\n";
            }
        }
        
        // 性能建议
        echo "\n💡 性能建议:\n";
        $riskEventCount = 0;
        if (isset($dbStats['risk_events'])) {
            foreach ($dbStats['risk_events'] as $risk) {
                $riskEventCount += $risk->count;
            }
        }
        
        if ($riskEventCount > 10000) {
            echo "⚠ 风险事件表记录过多 ({$riskEventCount} 条)，建议运行清理脚本\n";
        } else {
            echo "✅ 风险事件表记录数量正常\n";
        }
        
        if (isset($dbStats['tables'])) {
            foreach ($dbStats['tables'] as $table) {
                if ($table->{'Size (MB)'} > 100) {
                    echo "⚠ 表 {$table->table_name} 过大 ({$table->{'Size (MB)'}} MB)，建议优化\n";
                }
            }
        }
        
        echo "\n========================================\n";
        echo "报告生成完成\n";
        echo "========================================\n";
    }
    
    /**
     * 清理建议
     */
    public static function getCleanupSuggestions() {
        $suggestions = [];
        
        try {
            // 检查风险事件表
            $riskCount = Capsule::table('mod_cloudflare_risk_events')->count();
            if ($riskCount > 50000) {
                $suggestions[] = "风险事件表记录过多 ({$riskCount} 条)，建议立即清理";
            }
            
            // 检查旧任务
            $oldJobs = Capsule::table('mod_cloudflare_jobs')
                ->where('created_at', '<', date('Y-m-d H:i:s', strtotime('-30 days')))
                ->count();
            if ($oldJobs > 1000) {
                $suggestions[] = "旧任务记录过多 ({$oldJobs} 条)，建议清理";
            }
            
            // 检查失败任务
            $failedJobs = Capsule::table('mod_cloudflare_jobs')
                ->where('status', 'failed')
                ->where('attempts', '>=', 5)
                ->count();
            if ($failedJobs > 100) {
                $suggestions[] = "失败任务过多 ({$failedJobs} 个)，建议检查配置";
            }
            
        } catch (Exception $e) {
            $suggestions[] = "检查过程中出现错误: " . $e->getMessage();
        }
        
        return $suggestions;
    }
}

// 如果直接运行此脚本
if (php_sapi_name() === 'cli' && basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    PerformanceMonitor::generateReport();
    
    echo "\n🔧 清理建议:\n";
    $suggestions = PerformanceMonitor::getCleanupSuggestions();
    if (empty($suggestions)) {
        echo "✅ 系统状态良好，无需清理\n";
    } else {
        foreach ($suggestions as $suggestion) {
            echo "⚠ " . $suggestion . "\n";
        }
    }
}
