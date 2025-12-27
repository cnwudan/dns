<?php
/**
 * CloudflareAPI compatibility wrapper implemented on top of Alibaba Cloud Alidns (2015-01-09).
 *
 * For minimal intrusion to the existing codebase, we keep the class name and
 * method signatures used by the module, but internally translate operations
 * to AliDNS RPC API calls.
 *
 * Credentials mapping:
 * - $email parameter -> AccessKeyId
 * - $api_key parameter -> AccessKeySecret
 */
class CloudflareAPI {
    private const MAX_RETRIES = 3;
    private const RETRY_BASE_DELAY_MS = 200;

    private $access_key_id;
    private $access_key_secret;
    private $endpoint = 'https://alidns.aliyuncs.com/';
    private $version = '2015-01-09';

    public function __construct($email, $api_key){
        $this->access_key_id = trim((string)$email);
        $this->access_key_secret = trim((string)$api_key);
    }

    private function percentEncode($str) {
        $res = urlencode($str);
        $res = str_replace(['+','*','%7E'], ['%20','%2A','~'], $res);
        return $res;
    }

    private function rpcRequest(string $action, array $params = []) : array {
        $attempt = 0;
        $response = [];
        do {
            $attempt++;
            $response = $this->performRpcRequest($action, $params);
            if (!$this->shouldRetry($response) || $attempt >= self::MAX_RETRIES) {
                break;
            }
            usleep($this->retryDelayMicros($attempt));
        } while (true);

        return $response;
    }

    private function performRpcRequest(string $action, array $params = []) : array {
        $sysParams = [
            'Format' => 'JSON',
            'Version' => $this->version,
            'AccessKeyId' => $this->access_key_id,
            'SignatureMethod' => 'HMAC-SHA1',
            'Timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            'SignatureVersion' => '1.0',
            'SignatureNonce' => uniqid('', true),
            'Action' => $action
        ];
        $all = array_merge($sysParams, $params);

        ksort($all);
        $canonicalized = [];
        foreach ($all as $k => $v) {
            $canonicalized[] = $this->percentEncode($k) . '=' . $this->percentEncode((string)$v);
        }
        $canonicalizedQuery = implode('&', $canonicalized);
        $stringToSign = 'GET&%2F&' . $this->percentEncode($canonicalizedQuery);
        $signature = base64_encode(hash_hmac('sha1', $stringToSign, $this->access_key_secret . '&', true));
        $signedQuery = $canonicalizedQuery . '&Signature=' . $this->percentEncode($signature);

        $url = $this->endpoint . '?' . $signedQuery;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            return ['success' => false, 'errors' => ['curl_error' => $error], 'http_code' => $http_code];
        }
        $decoded = json_decode($result, true);
        if (!is_array($decoded)) {
            return ['success' => false, 'errors' => ['json_decode_error' => 'Invalid JSON response'], 'http_code' => $http_code];
        }
        $ok = !isset($decoded['Code']) && $http_code >= 200 && $http_code < 300;
        $decoded['success'] = $ok;
        $decoded['http_code'] = $http_code;
        return $decoded;
    }

    private function shouldRetry(array $response): bool {
        if ($response['success'] ?? false) {
            return false;
        }
        $httpCode = $response['http_code'] ?? 0;
        if ($httpCode === 0 || ($httpCode >= 500 && $httpCode < 600)) {
            return true;
        }
        $errors = $response['errors'] ?? [];
        if (!is_array($errors)) {
            return false;
        }
        if (isset($errors['curl_error']) || isset($errors['json_decode_error'])) {
            return true;
        }
        foreach ($errors as $key => $value) {
            if (is_string($key) && stripos($key, 'curl_error') !== false) {
                return true;
            }
            if (is_string($value)) {
                $lower = strtolower($value);
                if (strpos($lower, 'timeout') !== false || strpos($lower, 'temporarily unavailable') !== false) {
                    return true;
                }
            }
        }
        return false;
    }

    private function retryDelayMicros(int $attempt): int {
        $delayMs = self::RETRY_BASE_DELAY_MS * max(1, $attempt);
        return min(1500, $delayMs) * 1000;
    }

    private function splitNameToRR(string $fullName, string $domainName): string {
        $fullName = strtolower(rtrim($fullName, '.'));
        $domainName = strtolower(rtrim($domainName, '.'));
        if ($fullName === $domainName) {
            return '@';
        }
        if (substr($fullName, - (strlen($domainName) + 1)) === ('.' . $domainName)) {
            return substr($fullName, 0, - (strlen($domainName) + 1));
        }
        // Fallback: if cannot derive, use full as RR (AliDNS will reject, but better than wrong root)
        return $fullName;
    }

    private function mapAliToCfRecord(array $rec, string $domainName): array {
        $rr = $rec['RR'] ?? '';
        $name = ($rr === '@' || $rr === '') ? $domainName : ($rr . '.' . $domainName);
        return [
            'id' => $rec['RecordId'] ?? null,
            'type' => $rec['Type'] ?? '',
            'name' => $name,
            'content' => $rec['Value'] ?? '',
            'ttl' => intval($rec['TTL'] ?? 600),
            'proxied' => false
        ];
    }

    private function endsWith(string $haystack, string $needle): bool {
        if ($needle === '') { return true; }
        $len = strlen($needle);
        if (strlen($haystack) < $len) { return false; }
        return substr($haystack, -$len) === $needle;
    }

    private function normalizeTtl($ttl): int {
        $t = intval($ttl);
        if ($t <= 0) { return 600; }
        return max(600, $t);
    }

    private function mapAliErrorToSuggestion($res) : string {
        $code = $res['Code'] ?? ($res['errors']['Code'] ?? null);
        $msg = $res['Message'] ?? ($res['errors']['Message'] ?? null);
        if (!$code && !$msg) return '';
        $text = $msg ?: '未知错误';
        $suggest = '';
        $lower = strtolower($text);
        if (strpos($lower, 'conflict') !== false) {
            $suggest = '记录冲突：请检查同名不同类型是否已存在（如 NS 与 A/CNAME 冲突）或开启强制替换后重试。';
        } elseif (strpos($lower, 'format') !== false || strpos($lower, 'invalid') !== false) {
            $suggest = '格式错误：请核对记录内容格式（IP/域名/TTL/优先级/端口）。';
        } elseif (strpos($lower, 'denied') !== false || strpos($lower, 'permission') !== false || strpos($lower, 'auth') !== false) {
            $suggest = '权限错误：请检查 AccessKey 权限与域名授权，或重新配置凭据。';
        } elseif (strpos($lower, 'quota') !== false || strpos($lower, 'limit') !== false || strpos($lower, 'too many') !== false) {
            $suggest = '超限：请减少同名记录数量或稍后重试；必要时提升配额。';
        }
        return trim(($code ? ("[".$code."] ") : '') . $text . ($suggest ? ('；建议：' . $suggest) : ''));
    }

    // Find domain in AliDNS; return domain name as "zone id" for compatibility
    public function getZoneId($domain){
        $res = $this->rpcRequest('DescribeDomainInfo', [ 'DomainName' => $domain ]);
        if ($res['success'] ?? false) {
            return $res['DomainName'] ?? $domain;
        }
        return false;
    }

    // 创建子域名（支持二级和三级域名）
    public function createSubdomain($zone_id, $subdomain, $ip='192.0.2.1', $proxied=true, $type='A'){
        return $this->createDnsRecord($zone_id, $subdomain, $type, $ip, 120, false);
    }

    // 创建三级域名
    public function createThirdLevelDomain($zone_id, $third_level_name, $parent_subdomain, $ip='192.0.2.1', $proxied=true){
        $full_domain = $third_level_name . '.' . $parent_subdomain;
        return $this->createSubdomain($zone_id, $full_domain, $ip, $proxied);
    }

    // 检查域名是否已存在
    public function checkDomainExists($zone_id, $domain_name){
        $res = $this->rpcRequest('DescribeSubDomainRecords', [ 'SubDomain' => $domain_name, 'PageSize' => 1, 'PageNumber' => 1 ]);
        if (($res['success'] ?? false) && isset($res['TotalCount'])) {
            return intval($res['TotalCount']) > 0;
        }
        return false;
    }

    // 获取指定域名的所有DNS记录（按 name 过滤）
    public function getDomainRecords($zone_id, $domain_name){
        $res = $this->getDnsRecords($zone_id, $domain_name);
        if($res['success']){
            return $res['result'];
        }
        return [];
    }

    public function updateSubdomain($zone_id, $record_id, $subdomain, $ip, $proxied=true){
        return $this->updateDnsRecord($zone_id, $record_id, [
            'type' => 'A',
            'name' => $subdomain,
            'content' => $ip,
            'ttl' => 120
        ]);
    }

    public function deleteSubdomain($zone_id, $record_id){
        $res = $this->rpcRequest('DeleteDomainRecord', [ 'RecordId' => $record_id ]);
        if (!($res['success'] ?? false)) { return ['success'=>false, 'errors'=>[$this->mapAliErrorToSuggestion($res) ?: ($res['Message'] ?? 'delete failed')]]; }
        return [ 'success' => true, 'result' => $res ];
    }

    // 删除指定域名的所有记录（谨慎使用）
    public function deleteDomainRecords($zone_id, $domain_name){
        $records = $this->getDomainRecords($zone_id, $domain_name);
        $deleted_count = 0;
        foreach($records as $record){
            $res = $this->rpcRequest('DeleteDomainRecord', [ 'RecordId' => $record['id'] ]);
            if($res['success'] ?? false){ $deleted_count++; }
        }
        return ['success' => true, 'deleted_count' => $deleted_count];
    }

    // 深度删除：删除等于 subdomain_root 以及其所有子级（*.subdomain_root）的记录
    public function deleteDomainRecordsDeep($zone_id, $subdomain_root){
        $list = $this->getDnsRecords($zone_id, null, ['per_page' => 1000]);
        if (!($list['success'] ?? false)) { return ['success' => false, 'errors' => $list['errors'] ?? ['list failed']]; }
        $target = strtolower(rtrim($subdomain_root, '.'));
        $deleted = 0; $errors = [];
        foreach (($list['result'] ?? []) as $r) {
            $name = strtolower(rtrim((string)($r['name'] ?? ''), '.'));
            if ($name === $target || $this->endsWith($name, '.' . $target)) {
                $rid = $r['id'] ?? null;
                if ($rid) {
                    $res = $this->rpcRequest('DeleteDomainRecord', [ 'RecordId' => $rid ]);
                    if ($res['success'] ?? false) { $deleted++; }
                }
            }
        }
        return ['success' => true, 'deleted_count' => $deleted, 'note' => 'deep'];
    }

    public function getDnsRecords($zone_id, $name=null, $params = []){
        $result = [];
        if ($name) {
            // Exact subdomain query
            $req = [ 'SubDomain' => $name, 'PageSize' => min(500, intval($params['per_page'] ?? 1000) ?: 500), 'PageNumber' => 1 ];
            if (!empty($params['type'])) { $req['Type'] = strtoupper($params['type']); }
            do {
                $res = $this->rpcRequest('DescribeSubDomainRecords', $req);
                if (!($res['success'] ?? false)) { return ['success' => false, 'errors' => [$this->mapAliErrorToSuggestion($res) ?: ($res['Message'] ?? 'query failed')]]; }
                $list = $res['DomainRecords']['Record'] ?? [];
                foreach ($list as $rec) { $result[] = $this->mapAliToCfRecord($rec, $zone_id); }
                $total = intval($res['TotalCount'] ?? count($list));
                $pageSize = intval($req['PageSize']);
                $fetched = $req['PageNumber'] * $pageSize;
                $req['PageNumber']++;
            } while ($fetched < $total);
        } else {
            // Full domain listing
            $pageSize = min(500, intval($params['per_page'] ?? 1000) ?: 500);
            $page = 1;
            do {
                $res = $this->rpcRequest('DescribeDomainRecords', [ 'DomainName' => $zone_id, 'PageSize' => $pageSize, 'PageNumber' => $page ]);
                if (!($res['success'] ?? false)) { return ['success' => false, 'errors' => [$this->mapAliErrorToSuggestion($res) ?: ($res['Message'] ?? 'query failed')]]; }
                $list = $res['DomainRecords']['Record'] ?? [];
                foreach ($list as $rec) { $result[] = $this->mapAliToCfRecord($rec, $zone_id); }
                $total = intval($res['TotalCount'] ?? count($list));
                $fetched = $page * $pageSize;
                $page++;
            } while ($fetched < $total);
        }
        return ['success' => true, 'result' => $result];
    }

    // No proxy concept in AliDNS; make it a no-op success to keep UI flow
    public function toggleProxy($zone_id, $record_id, $proxied){
        return ['success' => true, 'result' => ['proxied' => false, 'note' => 'AliDNS does not support proxy']];
    }

    public function updateDnsRecord($zone_id, $record_id, $data){
        $type = strtoupper($data['type'] ?? $data['Type'] ?? 'A');
        $name = $data['name'] ?? '';
        $value = $data['content'] ?? $data['Value'] ?? '';
        $ttl = $this->normalizeTtl($data['ttl'] ?? $data['TTL'] ?? 600);
        $rr = $this->splitNameToRR(($name ?: $zone_id), $zone_id);
        $req = [
            'RecordId' => $record_id,
            'RR' => $rr,
            'Type' => $type,
            'Value' => $value,
            'TTL' => $ttl
        ];
        if ($type === 'MX' && isset($data['priority'])) { $req['Priority'] = intval($data['priority']); }
        if (!empty($data['line'])) { $req['Line'] = $data['line']; }
        $res = $this->rpcRequest('UpdateDomainRecord', $req);
        if (!($res['success'] ?? false)) { return ['success' => false, 'errors' => [ $this->mapAliErrorToSuggestion($res) ?: ($res['Message'] ?? 'update failed') ]]; }
        return ['success' => true, 'result' => ['id' => $record_id]];
    }

    public function createDnsRecord($zone_id, $name, $type, $content, $ttl=120, $proxied=true){
        $rr = $this->splitNameToRR($name, $zone_id);
        $req = [
            'DomainName' => $zone_id,
            'RR' => $rr,
            'Type' => strtoupper($type),
            'Value' => $content,
            'TTL' => $this->normalizeTtl($ttl)
        ];
        $res = $this->rpcRequest('AddDomainRecord', $req);
        if (!($res['success'] ?? false)) { return ['success' => false, 'errors' => [ $this->mapAliErrorToSuggestion($res) ?: ($res['Message'] ?? 'create failed') ]]; }
        $rid = $res['RecordId'] ?? null;
        return [ 'success' => true, 'result' => [ 'id' => $rid, 'name' => $name, 'type' => strtoupper($type), 'content' => $content, 'ttl' => intval($ttl), 'proxied' => false ] ];
    }

    // 创建CNAME记录
    public function createCNAMERecord($zone_id, $name, $target, $ttl=120, $proxied=false){
        return $this->createDnsRecord($zone_id, $name, 'CNAME', $target, $ttl, false);
    }

    // 创建MX记录
    public function createMXRecord($zone_id, $name, $mail_server, $priority=10, $ttl=120){
        $rr = $this->splitNameToRR($name, $zone_id);
        $res = $this->rpcRequest('AddDomainRecord', [
            'DomainName' => $zone_id,
            'RR' => $rr,
            'Type' => 'MX',
            'Value' => $mail_server,
            'TTL' => $this->normalizeTtl($ttl),
            'Priority' => intval($priority)
        ]);
        if (!($res['success'] ?? false)) { return ['success' => false, 'errors' => [ $this->mapAliErrorToSuggestion($res) ?: ($res['Message'] ?? 'create MX failed') ]]; }
        return [ 'success' => true, 'result' => [ 'id' => $res['RecordId'] ?? null, 'name' => $name, 'type' => 'MX', 'content' => $mail_server, 'ttl' => intval($ttl), 'proxied' => false, 'priority' => intval($priority) ] ];
    }

    // 创建SRV记录（AliDNS使用 Value="priority weight port target" 格式）
    public function createSRVRecord($zone_id, $name, $target, $port, $priority=0, $weight=0, $ttl=120){
        $value = trim(intval($priority) . ' ' . intval($weight) . ' ' . intval($port) . ' ' . $target);
        return $this->createDnsRecord($zone_id, $name, 'SRV', $value, $this->normalizeTtl($ttl), false);
    }

    // 创建CAA记录（AliDNS使用 Value="flag tag \"value\"" 格式）
    public function createCAARecord($zone_id, $name, $flags, $tag, $value, $ttl=120){
        $val = intval($flags) . ' ' . trim($tag) . ' "' . str_replace('"','\"', $value) . '"';
        return $this->createDnsRecord($zone_id, $name, 'CAA', $val, $this->normalizeTtl($ttl), false);
    }

    // 创建TXT记录
    public function createTXTRecord($zone_id, $name, $content, $ttl=120){
        return $this->createDnsRecord($zone_id, $name, 'TXT', $content, $this->normalizeTtl($ttl), false);
    }

    public function getDnsRecord($zone_id, $record_id){
        $res = $this->rpcRequest('DescribeDomainRecordInfo', [ 'RecordId' => $record_id ]);
        if (!($res['success'] ?? false)) { return ['success' => false, 'errors' => [ $this->mapAliErrorToSuggestion($res) ?: ($res['Message'] ?? 'query failed') ]]; }
        $mapped = $this->mapAliToCfRecord([
            'RecordId' => $res['RecordId'] ?? $record_id,
            'RR' => $res['RR'] ?? '',
            'Type' => $res['Type'] ?? '',
            'Value' => $res['Value'] ?? '',
            'TTL' => $res['TTL'] ?? 600
        ], $res['DomainName'] ?? $zone_id);
        return ['success' => true, 'result' => $mapped];
    }

    // Stubs for CF-specific methods (not applicable in AliDNS)
    public function getZoneSettings($zone_id){ return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']]; }
    public function updateZoneSetting($zone_id, $setting_name, $value){ return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']]; }
    public function enableCDN($zone_id){ return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']]; }
    public function getZoneAnalytics($zone_id, $since='-7d', $until='now'){ return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']]; }
    public function getFirewallRules($zone_id){ return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']]; }
    public function createFirewallRule($zone_id, $expression, $action='block', $description=''){ return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']]; }
    public function getPageRules($zone_id){ return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']]; }
    public function createPageRule($zone_id, $url_pattern, $actions, $priority=1, $status='active'){ return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']]; }
    public function getRateLimits($zone_id){ return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']]; }
    public function createRateLimit($zone_id, $expression, $threshold, $period, $action='block'){ return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']]; }

    // 批量操作DNS记录（按兼容格式）
    public function batchUpdateDnsRecords($zone_id, $updates){
        $results = [];
        foreach($updates as $update){
            if(isset($update['id'])){
                $results[] = $this->updateDnsRecord($zone_id, $update['id'], $update);
            } else {
                $results[] = $this->createDnsRecord(
                    $zone_id,
                    $update['name'],
                    $update['type'],
                    $update['content'],
                    $update['ttl'] ?? 120,
                    false
                );
            }
        }
        return $results;
    }

    // 原生payload：支持 Line/Priority 直传
    public function createDnsRecordRaw($zone_id, $payload){
        if (!isset($payload['type'],$payload['name'])) { return ['success' => false, 'errors' => ['unsupported' => 'missing fields']]; }
        $type = strtoupper($payload['type']);
        $name = (string)($payload['name']);
        $value = (string)($payload['content'] ?? ($payload['Value'] ?? ''));
        $ttl = $this->normalizeTtl($payload['ttl'] ?? $payload['TTL'] ?? 600);
        $rr = $this->splitNameToRR($name, $zone_id);
        $req = [
            'DomainName' => $zone_id,
            'RR' => $rr,
            'Type' => $type,
            'Value' => $value,
            'TTL' => $ttl
        ];
        if ($type === 'MX' && isset($payload['priority'])) { $req['Priority'] = intval($payload['priority']); }
        if (!empty($payload['line'])) { $req['Line'] = $payload['line']; }
        $res = $this->rpcRequest('AddDomainRecord', $req);
        if (!($res['success'] ?? false)) { return ['success' => false, 'errors' => [ $this->mapAliErrorToSuggestion($res) ?: ($res['Message'] ?? 'create failed') ]]; }
        return [ 'success' => true, 'result' => [ 'id' => $res['RecordId'] ?? null ] ];
    }

    public function updateDnsRecordRaw($zone_id, $record_id, $payload){
        return $this->updateDnsRecord($zone_id, $record_id, $payload);
    }

    public function validateCredentials(){
        $res = $this->rpcRequest('DescribeDomains', [ 'PageNumber' => 1, 'PageSize' => 1 ]);
        return ($res['success'] ?? false) === true;
    }

    public function getAccountInfo(){
        $ok = $this->validateCredentials();
        return [ 'success' => $ok ];
    }

    public function getZones(){
        $res = $this->rpcRequest('DescribeDomains', [ 'PageNumber' => 1, 'PageSize' => 50 ]);
        if (!($res['success'] ?? false)) { return ['success' => false, 'errors' => [ $res['Message'] ?? 'query failed' ]]; }
        $zones = [];
        foreach (($res['Domains']['Domain'] ?? []) as $d) {
            $zones[] = [ 'name' => $d['DomainName'] ?? '', 'id' => $d['DomainName'] ?? '' ];
        }
        return ['success' => true, 'result' => $zones];
    }

    public function searchZone($search_term){
        // Basic implementation using DescribeDomains and filtering
        $res = $this->getZones();
        if (!($res['success'] ?? false)) return $res;
        $term = strtolower($search_term);
        $filtered = array_values(array_filter($res['result'] ?? [], function($z) use ($term){ return strpos(strtolower($z['name'] ?? ''), $term) !== false; }));
        return ['success' => true, 'result' => $filtered];
    }

    public function getZoneDetails($zone_id){
        $res = $this->rpcRequest('DescribeDomainInfo', [ 'DomainName' => $zone_id ]);
        return [ 'success' => ($res['success'] ?? false), 'result' => $res ];
    }

    public function purgeCache($zone_id, $files=null){
        return ['success' => false, 'errors' => ['unsupported' => 'AliDNS']];
    }
}