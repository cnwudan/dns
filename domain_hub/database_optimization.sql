-- WHMCS7 域名分发插件数据库优化方案
-- 解决 mod_cloudflare_risk_events 表性能问题

-- 1. 添加复合索引优化查询性能
ALTER TABLE `mod_cloudflare_risk_events` 
ADD INDEX `idx_subdomain_created` (`subdomain_id`, `created_at`),
ADD INDEX `idx_level_created` (`level`, `created_at`),
ADD INDEX `idx_source_created` (`source`, `created_at`);

-- 2. 创建数据清理存储过程
DELIMITER $$

CREATE PROCEDURE CleanupRiskEvents()
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE cleanup_count INT DEFAULT 0;
    
    -- 删除所有低风险事件（直接删除）
    DELETE FROM `mod_cloudflare_risk_events` 
    WHERE `level` = 'low';
    
    SET cleanup_count = ROW_COUNT();
    
    -- 删除所有中等风险事件（直接删除）
    DELETE FROM `mod_cloudflare_risk_events` 
    WHERE `level` = 'medium';
    
    SET cleanup_count = cleanup_count + ROW_COUNT();
    
    -- 删除超过72小时的高风险事件
    DELETE FROM `mod_cloudflare_risk_events` 
    WHERE `level` = 'high' 
    AND `created_at` < DATE_SUB(NOW(), INTERVAL 72 HOUR);
    
    SET cleanup_count = cleanup_count + ROW_COUNT();
    
    -- 删除重复的扫描摘要事件（保留最新的）
    DELETE re1 FROM `mod_cloudflare_risk_events` re1
    INNER JOIN `mod_cloudflare_risk_events` re2 
    WHERE re1.id < re2.id 
    AND re1.subdomain_id = re2.subdomain_id 
    AND re1.source = 'summary' 
    AND re2.source = 'summary'
    AND DATE(re1.created_at) = DATE(re2.created_at);
    
    SET cleanup_count = cleanup_count + ROW_COUNT();
    
    -- 记录清理结果
    INSERT INTO `mod_cloudflare_logs` 
    (`action`, `details`, `created_at`, `updated_at`) 
    VALUES 
    ('risk_events_cleanup', CONCAT('Cleaned up ', cleanup_count, ' risk events'), NOW(), NOW());
    
    SELECT CONCAT('Cleaned up ', cleanup_count, ' risk events') as result;
END$$

DELIMITER ;

-- 3. 创建表分区（可选，适用于MySQL 5.7+）
-- 按月份分区，提高查询和维护效率
ALTER TABLE `mod_cloudflare_risk_events` 
PARTITION BY RANGE (YEAR(created_at) * 100 + MONTH(created_at)) (
    PARTITION p202401 VALUES LESS THAN (202402),
    PARTITION p202402 VALUES LESS THAN (202403),
    PARTITION p202403 VALUES LESS THAN (202404),
    PARTITION p202404 VALUES LESS THAN (202405),
    PARTITION p202405 VALUES LESS THAN (202406),
    PARTITION p202406 VALUES LESS THAN (202407),
    PARTITION p202407 VALUES LESS THAN (202408),
    PARTITION p202408 VALUES LESS THAN (202409),
    PARTITION p202409 VALUES LESS THAN (202410),
    PARTITION p202410 VALUES LESS THAN (202411),
    PARTITION p202411 VALUES LESS THAN (202412),
    PARTITION p202412 VALUES LESS THAN (202501),
    PARTITION p_future VALUES LESS THAN MAXVALUE
);

-- 4. 优化查询语句
-- 替换全表扫描查询为索引查询
-- 原查询：SELECT * FROM mod_cloudflare_risk_events
-- 优化后：
SELECT * FROM `mod_cloudflare_risk_events` 
WHERE `created_at` >= DATE_SUB(NOW(), INTERVAL 7 DAY)
ORDER BY `created_at` DESC 
LIMIT 1000;

-- 5. 创建数据统计视图
CREATE VIEW `v_risk_events_summary` AS
SELECT 
    `subdomain_id`,
    `level`,
    COUNT(*) as `event_count`,
    MAX(`created_at`) as `last_event`,
    AVG(`score`) as `avg_score`
FROM `mod_cloudflare_risk_events` 
WHERE `created_at` >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY `subdomain_id`, `level`;

-- 6. 添加表注释
ALTER TABLE `mod_cloudflare_risk_events` 
COMMENT = '风险事件表 - 已优化索引和分区';

-- 7. 创建自动清理事件（需要开启事件调度器）
-- SET GLOBAL event_scheduler = ON;

CREATE EVENT IF NOT EXISTS `auto_cleanup_risk_events`
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO
  CALL CleanupRiskEvents();
