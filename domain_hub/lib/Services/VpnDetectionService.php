<?php
/**
 * VPN/代理检测服务
 * 
 * 使用 ip-api.com 免费API检测用户IP是否为VPN/代理
 * 支持检测结果缓存，减少API调用
 */

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfVpnDetectionService
{
    private const CACHE_TABLE = 'mod_cloudflare_vpn_cache';
    private const API_ENDPOINT = 'http://ip-api.com/json/';
    private const API_FIELDS = 'status,proxy,hosting,mobile,message';
    
    /**
     * 检查IP是否应被阻止注册
     *
     * @param string $ip 用户IP地址
     * @param array $settings 模块配置
     * @return array ['blocked' => bool, 'reason' => string, 'details' => array]
     */
    public static function shouldBlockRegistration(string $ip, array $settings): array
    {
        // 1. 检查是否启用VPN检测
        if (!self::isEnabled($settings)) {
            return ['blocked' => false, 'reason' => 'disabled'];
        }
        
        // 2. 验证IP格式
        $ip = trim($ip);
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['blocked' => false, 'reason' => 'invalid_ip'];
        }
        
        // 3. 跳过本地/私有IP
        if (self::isPrivateIp($ip)) {
            return ['blocked' => false, 'reason' => 'private_ip'];
        }
        
        // 4. 检查IP白名单
        if (self::isWhitelisted($ip, $settings)) {
            return ['blocked' => false, 'reason' => 'whitelisted'];
        }
        
        // 5. 检查缓存
        $cached = self::getCachedResult($ip, $settings);
        if ($cached !== null) {
            return $cached;
        }
        
        // 6. 调用API检测
        $result = self::detectWithIpApi($ip, $settings);
        
        // 7. 缓存结果
        self::cacheResult($ip, $result, $settings);
        
        return $result;
    }
    
    /**
     * 检查VPN检测是否启用（注册功能）
     */
    public static function isEnabled(array $settings): bool
    {
        $value = $settings['enable_vpn_detection'] ?? '';
        return self::settingToBool($value);
    }
    
    /**
     * 检查DNS操作VPN检测是否启用
     */
    public static function isDnsCheckEnabled(array $settings): bool
    {
        // 首先必须启用VPN检测总开关
        if (!self::isEnabled($settings)) {
            return false;
        }
        // 然后检查DNS操作专用开关
        $value = $settings['vpn_detection_dns_enabled'] ?? '';
        return self::settingToBool($value);
    }
    
    /**
     * 检查DNS操作是否应被阻止（用于DNS创建/更新/删除）
     *
     * @param string $ip 用户IP地址
     * @param array $settings 模块配置
     * @return array ['blocked' => bool, 'reason' => string, 'details' => array]
     */
    public static function shouldBlockDnsOperation(string $ip, array $settings): array
    {
        // 检查DNS操作VPN检测是否启用
        if (!self::isDnsCheckEnabled($settings)) {
            return ['blocked' => false, 'reason' => 'dns_check_disabled'];
        }
        
        // 复用注册检测逻辑
        return self::shouldBlockRegistration($ip, $settings);
    }
    
    /**
     * 检查IP是否在白名单中
     */
    private static function isWhitelisted(string $ip, array $settings): bool
    {
        $whitelist = trim((string)($settings['vpn_detection_ip_whitelist'] ?? ''));
        if ($whitelist === '') {
            return false;
        }
        
        $lines = array_filter(array_map('trim', preg_split('/[\r\n]+/', $whitelist)));
        foreach ($lines as $entry) {
            if ($entry === '') {
                continue;
            }
            
            // 支持CIDR格式
            if (strpos($entry, '/') !== false) {
                if (self::ipInCidr($ip, $entry)) {
                    return true;
                }
            } else {
                // 精确匹配
                if ($entry === $ip) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * 检查IP是否在CIDR范围内
     */
    private static function ipInCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr);
        if (count($parts) !== 2) {
            return false;
        }
        
        $subnet = $parts[0];
        $mask = (int)$parts[1];
        
        // IPv4
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && 
            filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $maskBits = -1 << (32 - $mask);
            return ($ipLong & $maskBits) === ($subnetLong & $maskBits);
        }
        
        // IPv6 (简化处理，仅精确匹配)
        return $ip === $subnet;
    }
    
    /**
     * 检查是否为私有/本地IP
     */
    private static function isPrivateIp(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }
    
    /**
     * 从缓存获取检测结果
     */
    private static function getCachedResult(string $ip, array $settings): ?array
    {
        if (!self::isCacheTableReady()) {
            return null;
        }
        
        $cacheHours = max(1, (int)($settings['vpn_detection_cache_hours'] ?? 24));
        $ipHash = self::hashIp($ip);
        
        try {
            $row = Capsule::table(self::CACHE_TABLE)
                ->where('ip_hash', $ipHash)
                ->where('expires_at', '>', date('Y-m-d H:i:s'))
                ->first();
            
            if ($row) {
                return [
                    'blocked' => (bool)$row->is_blocked,
                    'reason' => $row->reason ?: 'cached',
                    'is_vpn' => (bool)$row->is_vpn,
                    'is_proxy' => (bool)$row->is_proxy,
                    'is_hosting' => (bool)$row->is_hosting,
                    'cached' => true,
                ];
            }
        } catch (\Throwable $e) {
            // 缓存查询失败，继续实时检测
        }
        
        return null;
    }
    
    /**
     * 缓存检测结果
     */
    private static function cacheResult(string $ip, array $result, array $settings): void
    {
        if (!self::isCacheTableReady()) {
            return;
        }
        
        $cacheHours = max(1, (int)($settings['vpn_detection_cache_hours'] ?? 24));
        $ipHash = self::hashIp($ip);
        $now = date('Y-m-d H:i:s');
        $expiresAt = date('Y-m-d H:i:s', time() + $cacheHours * 3600);
        
        try {
            // 使用 REPLACE INTO 或 ON DUPLICATE KEY UPDATE
            Capsule::statement(
                'INSERT INTO `' . self::CACHE_TABLE . '` 
                (`ip_hash`, `is_blocked`, `reason`, `is_vpn`, `is_proxy`, `is_hosting`, `checked_at`, `expires_at`, `created_at`) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                `is_blocked` = VALUES(`is_blocked`), 
                `reason` = VALUES(`reason`),
                `is_vpn` = VALUES(`is_vpn`),
                `is_proxy` = VALUES(`is_proxy`),
                `is_hosting` = VALUES(`is_hosting`),
                `checked_at` = VALUES(`checked_at`), 
                `expires_at` = VALUES(`expires_at`)',
                [
                    $ipHash,
                    $result['blocked'] ? 1 : 0,
                    $result['reason'] ?? '',
                    ($result['is_vpn'] ?? false) ? 1 : 0,
                    ($result['is_proxy'] ?? false) ? 1 : 0,
                    ($result['is_hosting'] ?? false) ? 1 : 0,
                    $now,
                    $expiresAt,
                    $now,
                ]
            );
            
            // 定期清理过期缓存
            self::maybeCleanupCache();
        } catch (\Throwable $e) {
            // 缓存写入失败，忽略
        }
    }
    
    /**
     * 使用 ip-api.com 检测IP
     */
    private static function detectWithIpApi(string $ip, array $settings): array
    {
        $url = self::API_ENDPOINT . urlencode($ip) . '?fields=' . self::API_FIELDS;
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT => 'WHMCS-DomainHub/1.0',
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        // API调用失败，默认放行
        if ($error || $httpCode !== 200 || !$response) {
            return [
                'blocked' => false,
                'reason' => 'api_error',
                'error' => $error ?: 'HTTP ' . $httpCode,
            ];
        }
        
        $data = json_decode($response, true);
        if (!is_array($data) || ($data['status'] ?? '') !== 'success') {
            return [
                'blocked' => false,
                'reason' => 'api_failed',
                'error' => $data['message'] ?? 'Unknown error',
            ];
        }
        
        // 解析检测结果
        $isProxy = (bool)($data['proxy'] ?? false);
        $isHosting = (bool)($data['hosting'] ?? false);
        $isMobile = (bool)($data['mobile'] ?? false);
        
        // 判断是否阻止
        $blocked = false;
        $reason = '';
        
        $blockVpnProxy = self::settingToBool($settings['vpn_detection_block_vpn'] ?? 'yes');
        $blockHosting = self::settingToBool($settings['vpn_detection_block_hosting'] ?? 'no');
        
        if ($isProxy && $blockVpnProxy) {
            $blocked = true;
            $reason = 'vpn_proxy';
        } elseif ($isHosting && $blockHosting) {
            $blocked = true;
            $reason = 'datacenter';
        }
        
        return [
            'blocked' => $blocked,
            'reason' => $reason ?: 'clean',
            'is_vpn' => $isProxy,
            'is_proxy' => $isProxy,
            'is_hosting' => $isHosting,
            'is_mobile' => $isMobile,
            'raw' => $data,
        ];
    }
    
    /**
     * 哈希IP地址（隐私保护）
     */
    private static function hashIp(string $ip): string
    {
        return hash('sha256', $ip . '_vpn_cache_salt_v1');
    }
    
    /**
     * 检查缓存表是否就绪
     */
    private static function isCacheTableReady(): bool
    {
        static $ready = null;
        if ($ready !== null) {
            return $ready;
        }
        
        try {
            $ready = Capsule::schema()->hasTable(self::CACHE_TABLE);
        } catch (\Throwable $e) {
            $ready = false;
        }
        
        return $ready;
    }
    
    /**
     * 定期清理过期缓存
     */
    private static function maybeCleanupCache(): void
    {
        static $lastCleanup = 0;
        $now = time();
        
        // 每5分钟最多清理一次
        if ($now - $lastCleanup < 300) {
            return;
        }
        $lastCleanup = $now;
        
        try {
            Capsule::table(self::CACHE_TABLE)
                ->where('expires_at', '<', date('Y-m-d H:i:s', $now - 3600))
                ->limit(100)
                ->delete();
        } catch (\Throwable $e) {
            // 忽略清理错误
        }
    }
    
    /**
     * 创建缓存表（由ModuleInstaller调用）
     */
    public static function ensureCacheTable(): void
    {
        if (Capsule::schema()->hasTable(self::CACHE_TABLE)) {
            return;
        }
        
        try {
            Capsule::schema()->create(self::CACHE_TABLE, function ($table) {
                $table->increments('id');
                $table->string('ip_hash', 64)->unique();
                $table->tinyInteger('is_blocked')->default(0);
                $table->string('reason', 32)->nullable();
                $table->tinyInteger('is_vpn')->default(0);
                $table->tinyInteger('is_proxy')->default(0);
                $table->tinyInteger('is_hosting')->default(0);
                $table->dateTime('checked_at');
                $table->dateTime('expires_at');
                $table->dateTime('created_at');
                $table->index('expires_at');
            });
        } catch (\Throwable $e) {
            // 表创建失败，记录日志
            error_log('[domain_hub][VpnDetection] Failed to create cache table: ' . $e->getMessage());
        }
    }
    
    /**
     * 将配置值转换为布尔值
     */
    private static function settingToBool($value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        $normalized = strtolower(trim((string)$value));
        return in_array($normalized, ['1', 'on', 'yes', 'true', 'enabled'], true);
    }
    
    /**
     * 获取用于前端显示的错误消息
     */
    public static function getBlockMessage(array $result, array $lang = []): string
    {
        $reason = $result['reason'] ?? 'vpn_proxy';
        
        $messages = [
            'vpn_proxy' => $lang['vpn_blocked'] ?? '检测到您正在使用VPN或代理，请关闭后再尝试注册域名。',
            'datacenter' => $lang['datacenter_blocked'] ?? '检测到您的IP来自数据中心，请使用家庭网络注册。',
        ];
        
        return $messages[$reason] ?? ($lang['vpn_blocked'] ?? '检测到您正在使用VPN或代理，请关闭后再尝试注册域名。');
    }
}
