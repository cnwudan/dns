-- ========================================
-- 🚀 数据库性能立即优化 - 添加索引
-- ========================================
-- 
-- 执行时间：约5-10分钟（取决于数据量）
-- 影响：大幅提升查询性能，支持更大用户规模
-- 风险：低（只添加索引，不修改数据）
--
-- ========================================

-- 开始执行
SET @start_time = NOW();
SELECT '开始添加索引...' as status;

-- ========================================
-- 1. mod_cloudflare_subdomain 表（核心表）
-- ========================================
SELECT '正在优化 mod_cloudflare_subdomain 表...' as status;

-- 检查并添加 status 索引
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_subdomain' 
    AND index_name = 'idx_status');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_subdomain` ADD INDEX `idx_status` (`status`)',
    'SELECT "索引 idx_status 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 检查并添加 userid+status 复合索引
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_subdomain' 
    AND index_name = 'idx_userid_status');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_subdomain` ADD INDEX `idx_userid_status` (`userid`, `status`)',
    'SELECT "索引 idx_userid_status 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 检查并添加 subdomain 唯一索引
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_subdomain' 
    AND index_name = 'idx_subdomain_unique');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_subdomain` ADD UNIQUE INDEX `idx_subdomain_unique` (`subdomain`)',
    'SELECT "索引 idx_subdomain_unique 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 检查并添加 created_at 索引
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_subdomain' 
    AND index_name = 'idx_created_at');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_subdomain` ADD INDEX `idx_created_at` (`created_at`)',
    'SELECT "索引 idx_created_at 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT '✅ mod_cloudflare_subdomain 表优化完成' as status;


-- ========================================
-- 2. mod_cloudflare_dns_records 表（DNS记录）
-- ========================================
SELECT '正在优化 mod_cloudflare_dns_records 表...' as status;

-- 检查并添加 subdomain_id 索引（非常重要！）
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_dns_records' 
    AND index_name = 'idx_subdomain_id');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_dns_records` ADD INDEX `idx_subdomain_id` (`subdomain_id`)',
    'SELECT "索引 idx_subdomain_id 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 检查并添加 subdomain_id+type 复合索引
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_dns_records' 
    AND index_name = 'idx_subdomain_type');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_dns_records` ADD INDEX `idx_subdomain_type` (`subdomain_id`, `type`)',
    'SELECT "索引 idx_subdomain_type 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT '✅ mod_cloudflare_dns_records 表优化完成' as status;


-- ========================================
-- 3. mod_cloudflare_invitation_codes 表（邀请码）
-- ========================================
SELECT '正在优化 mod_cloudflare_invitation_codes 表...' as status;

-- 检查并添加 code 唯一索引
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_invitation_codes' 
    AND index_name = 'idx_code_unique');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_invitation_codes` ADD UNIQUE INDEX `idx_code_unique` (`code`)',
    'SELECT "索引 idx_code_unique 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 检查并添加 userid 唯一索引
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_invitation_codes' 
    AND index_name = 'idx_userid_unique');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_invitation_codes` ADD UNIQUE INDEX `idx_userid_unique` (`userid`)',
    'SELECT "索引 idx_userid_unique 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT '✅ mod_cloudflare_invitation_codes 表优化完成' as status;


-- ========================================
-- 4. mod_cloudflare_invitation_claims 表（邀请记录）
-- ========================================
SELECT '正在优化 mod_cloudflare_invitation_claims 表...' as status;

-- 检查并添加 inviter_userid 索引
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_invitation_claims' 
    AND index_name = 'idx_inviter');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_invitation_claims` ADD INDEX `idx_inviter` (`inviter_userid`)',
    'SELECT "索引 idx_inviter 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 检查并添加 invitee_userid+code 复合索引
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_invitation_claims' 
    AND index_name = 'idx_invitee_code');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_invitation_claims` ADD INDEX `idx_invitee_code` (`invitee_userid`, `code`)',
    'SELECT "索引 idx_invitee_code 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 检查并添加 created_at 索引（排行榜需要）
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_invitation_claims' 
    AND index_name = 'idx_created_at');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_invitation_claims` ADD INDEX `idx_created_at` (`created_at`)',
    'SELECT "索引 idx_created_at 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT '✅ mod_cloudflare_invitation_claims 表优化完成' as status;


-- ========================================
-- 5. mod_cloudflare_subdomain_quotas 表（配额）
-- ========================================
SELECT '正在优化 mod_cloudflare_subdomain_quotas 表...' as status;

-- 检查并添加 userid 唯一索引
SET @index_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_subdomain_quotas' 
    AND index_name = 'idx_userid_unique');

SET @sql = IF(@index_exists = 0,
    'ALTER TABLE `mod_cloudflare_subdomain_quotas` ADD UNIQUE INDEX `idx_userid_unique` (`userid`)',
    'SELECT "索引 idx_userid_unique 已存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT '✅ mod_cloudflare_subdomain_quotas 表优化完成' as status;


-- ========================================
-- 6. mod_cloudflare_api_keys 表（API密钥）
-- ========================================
SELECT '正在优化 mod_cloudflare_api_keys 表...' as status;

-- 检查表是否存在
SET @table_exists = (SELECT COUNT(*) FROM information_schema.tables 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_api_keys');

-- 只有表存在时才添加索引
SET @sql = IF(@table_exists > 0, 'SELECT "表存在，继续添加索引" as result', 'SELECT "表不存在，跳过" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 添加 api_key 唯一索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_api_keys' 
    AND index_name = 'idx_api_key_unique'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_api_keys` ADD UNIQUE INDEX `idx_api_key_unique` (`api_key`)',
    'SELECT "索引 idx_api_key_unique 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 添加 userid 索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_api_keys' 
    AND index_name = 'idx_userid'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_api_keys` ADD INDEX `idx_userid` (`userid`)',
    'SELECT "索引 idx_userid 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 添加 status 索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_api_keys' 
    AND index_name = 'idx_status'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_api_keys` ADD INDEX `idx_status` (`status`)',
    'SELECT "索引 idx_status 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT '✅ mod_cloudflare_api_keys 表优化完成' as status;


-- ========================================
-- 7. mod_cloudflare_api_logs 表（API日志）
-- ========================================
SELECT '正在优化 mod_cloudflare_api_logs 表...' as status;

-- 检查表是否存在
SET @table_exists = (SELECT COUNT(*) FROM information_schema.tables 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_api_logs');

-- 添加 api_key_id 索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_api_logs' 
    AND index_name = 'idx_api_key_id'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_api_logs` ADD INDEX `idx_api_key_id` (`api_key_id`)',
    'SELECT "索引 idx_api_key_id 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 添加 created_at 索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_api_logs' 
    AND index_name = 'idx_created_at'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_api_logs` ADD INDEX `idx_created_at` (`created_at`)',
    'SELECT "索引 idx_created_at 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 添加 api_key_id+created_at 复合索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_api_logs' 
    AND index_name = 'idx_api_key_created'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_api_logs` ADD INDEX `idx_api_key_created` (`api_key_id`, `created_at`)',
    'SELECT "索引 idx_api_key_created 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT '✅ mod_cloudflare_api_logs 表优化完成' as status;


-- ========================================
-- 8. mod_cloudflare_domain_risk 表（域名风险）
-- ========================================
SELECT '正在优化 mod_cloudflare_domain_risk 表...' as status;

-- 检查表是否存在
SET @table_exists = (SELECT COUNT(*) FROM information_schema.tables 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_domain_risk');

-- 添加 subdomain_id 唯一索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_domain_risk' 
    AND index_name = 'idx_subdomain_id_unique'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_domain_risk` ADD UNIQUE INDEX `idx_subdomain_id_unique` (`subdomain_id`)',
    'SELECT "索引 idx_subdomain_id_unique 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 添加 risk_level 索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_domain_risk' 
    AND index_name = 'idx_risk_level'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_domain_risk` ADD INDEX `idx_risk_level` (`risk_level`)',
    'SELECT "索引 idx_risk_level 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 添加 last_checked_at 索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_domain_risk' 
    AND index_name = 'idx_last_checked'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_domain_risk` ADD INDEX `idx_last_checked` (`last_checked_at`)',
    'SELECT "索引 idx_last_checked 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT '✅ mod_cloudflare_domain_risk 表优化完成' as status;


-- ========================================
-- 9. mod_cloudflare_rootdomains 表（根域名）
-- ========================================
SELECT '正在优化 mod_cloudflare_rootdomains 表...' as status;

-- 检查表是否存在
SET @table_exists = (SELECT COUNT(*) FROM information_schema.tables 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_rootdomains');

-- 添加 domain 唯一索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_rootdomains' 
    AND index_name = 'idx_domain_unique'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_rootdomains` ADD UNIQUE INDEX `idx_domain_unique` (`domain`)',
    'SELECT "索引 idx_domain_unique 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 添加 status 索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_rootdomains' 
    AND index_name = 'idx_status'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_rootdomains` ADD INDEX `idx_status` (`status`)',
    'SELECT "索引 idx_status 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT '✅ mod_cloudflare_rootdomains 表优化完成' as status;


-- ========================================
-- 10. mod_cloudflare_forbidden_domains 表（禁止域名）
-- ========================================
SELECT '正在优化 mod_cloudflare_forbidden_domains 表...' as status;

-- 检查表是否存在
SET @table_exists = (SELECT COUNT(*) FROM information_schema.tables 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_forbidden_domains');

-- 添加 domain 唯一索引
SET @index_exists = IF(@table_exists > 0, (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_schema = DATABASE() 
    AND table_name = 'mod_cloudflare_forbidden_domains' 
    AND index_name = 'idx_domain_unique'), 1);

SET @sql = IF(@table_exists > 0 AND @index_exists = 0,
    'ALTER TABLE `mod_cloudflare_forbidden_domains` ADD UNIQUE INDEX `idx_domain_unique` (`domain`)',
    'SELECT "索引 idx_domain_unique 已存在或表不存在" as result');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT '✅ mod_cloudflare_forbidden_domains 表优化完成' as status;


-- ========================================
-- 完成
-- ========================================
SELECT CONCAT('✅ 所有索引添加完成！耗时：', TIMESTAMPDIFF(SECOND, @start_time, NOW()), ' 秒') as result;

-- 显示优化结果
SELECT '========================================' as '';
SELECT '📊 优化结果统计' as '';
SELECT '========================================' as '';

-- 统计各表索引数量
SELECT 
    table_name as '表名',
    COUNT(DISTINCT index_name) as '索引数量'
FROM information_schema.statistics 
WHERE table_schema = DATABASE() 
AND table_name LIKE 'mod_cloudflare_%'
GROUP BY table_name
ORDER BY table_name;

SELECT '========================================' as '';
SELECT '✅ 数据库优化完成！' as '';
SELECT '建议：重启PHP-FPM以刷新查询缓存' as '';
SELECT 'service php-fpm reload' as '命令';
SELECT '========================================' as '';


