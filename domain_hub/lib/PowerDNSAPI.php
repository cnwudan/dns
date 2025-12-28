<?php
/**
 * PowerDNS API Client
 *
 * Supports self-hosted PowerDNS Authoritative Server with HTTP API enabled.
 * Credentials mapping:
 * - $api_url parameter (access_key_id) -> PowerDNS API URL (e.g., http://localhost:8081/api/v1)
 * - $api_key parameter (access_key_secret) -> X-API-Key header value
 */
class PowerDNSAPI
{
    private const MAX_RETRIES = 3;
    private const RETRY_BASE_DELAY_MS = 200;
    private const DEFAULT_TTL = 3600;

    private $api_url;
    private $api_key;
    private $server_id;
    private $timeout;
    private array $zoneDetailCache = [];
    private array $zoneRecordCache = [];
    private array $zoneRecordCacheDisabled = [];

    /**
     * @param string $api_url PowerDNS API base URL (e.g., http://localhost:8081/api/v1)
     * @param string $api_key X-API-Key for authentication
     * @param string $server_id Server ID (default: localhost)
     * @param int $timeout Request timeout in seconds
     */
    public function __construct(string $api_url, string $api_key, string $server_id = 'localhost', int $timeout = 30)
    {
        $this->api_url = rtrim(trim($api_url), '/');
        $this->api_key = trim($api_key);
        $this->server_id = $server_id ?: 'localhost';
        $this->timeout = max(5, $timeout);
    }

    /**
     * Make HTTP request to PowerDNS API with retry logic
     */
    private function request(string $method, string $endpoint, ?array $data = null): array
    {
        $attempt = 0;
        $response = [];
        do {
            $attempt++;
            $response = $this->performRequest($method, $endpoint, $data);
            if (!$this->shouldRetry($response) || $attempt >= self::MAX_RETRIES) {
                break;
            }
            usleep($this->retryDelayMicros($attempt));
        } while (true);

        return $response;
    }

    private function performRequest(string $method, string $endpoint, ?array $data = null): array
    {
        $url = $this->api_url . $endpoint;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));

        $headers = [
            'X-API-Key: ' . $this->api_key,
            'Content-Type: application/json',
            'Accept: application/json',
        ];
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        if ($data !== null && in_array(strtoupper($method), ['POST', 'PUT', 'PATCH'])) {
            $jsonData = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonData);
        }

        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            return [
                'success' => false,
                'errors' => ['curl_error' => $error],
                'http_code' => $httpCode,
            ];
        }

        // Empty response is OK for DELETE/PATCH operations
        if ($result === '' || $result === false) {
            if ($httpCode >= 200 && $httpCode < 300) {
                return ['success' => true, 'result' => [], 'http_code' => $httpCode];
            }
            return [
                'success' => false,
                'errors' => ['empty_response' => 'Empty response from server'],
                'http_code' => $httpCode,
            ];
        }

        $decoded = json_decode($result, true);
        if (!is_array($decoded) && $httpCode >= 200 && $httpCode < 300) {
            return ['success' => true, 'result' => [], 'http_code' => $httpCode];
        }

        if (!is_array($decoded)) {
            return [
                'success' => false,
                'errors' => ['json_decode_error' => 'Invalid JSON: ' . substr($result, 0, 200)],
                'http_code' => $httpCode,
            ];
        }

        // PowerDNS returns error in 'error' field
        if (isset($decoded['error'])) {
            return [
                'success' => false,
                'errors' => ['pdns_error' => $decoded['error']],
                'http_code' => $httpCode,
            ];
        }

        $ok = $httpCode >= 200 && $httpCode < 300;
        return [
            'success' => $ok,
            'result' => $decoded,
            'http_code' => $httpCode,
        ];
    }

    private function shouldRetry(array $response): bool
    {
        if ($response['success'] ?? false) {
            return false;
        }
        $httpCode = $response['http_code'] ?? 0;
        if ($httpCode === 0 || ($httpCode >= 500 && $httpCode < 600)) {
            return true;
        }
        $errors = $response['errors'] ?? [];
        if (isset($errors['curl_error'])) {
            return true;
        }
        return false;
    }

    private function retryDelayMicros(int $attempt): int
    {
        $delayMs = self::RETRY_BASE_DELAY_MS * max(1, $attempt);
        return min(1500, $delayMs) * 1000;
    }

    /**
     * Normalize zone name (ensure trailing dot for PowerDNS)
     */
    private function normalizeZoneName(string $name): string
    {
        $name = strtolower(trim($name));
        if ($name !== '' && substr($name, -1) !== '.') {
            $name .= '.';
        }
        return $name;
    }

    /**
     * Normalize record name (ensure trailing dot)
     */
    private function normalizeRecordName(string $name): string
    {
        $name = strtolower(trim($name));
        if ($name !== '' && substr($name, -1) !== '.') {
            $name .= '.';
        }
        return $name;
    }

    /**
     * Remove trailing dot for external compatibility
     */
    private function stripTrailingDot(string $name): string
    {
        return rtrim($name, '.');
    }

    /**
     * Convert PowerDNS record to Cloudflare-compatible format
     */
    private function mapPdnsToCfRecord(array $rrset, string $zoneName): array
    {
        $records = [];
        $type = $rrset['type'] ?? '';
        $name = $this->stripTrailingDot($rrset['name'] ?? '');
        $ttlRaw = $rrset['ttl'] ?? null;
        $ttl = $ttlRaw !== null ? intval($ttlRaw) : null;
        if ($ttl !== null && $ttl <= 0) {
            $ttl = self::DEFAULT_TTL;
        }

        foreach (($rrset['records'] ?? []) as $record) {
            $content = $record['content'] ?? '';
            // For certain record types, strip trailing dots from content
            if (in_array($type, ['CNAME', 'MX', 'NS', 'SRV', 'PTR'])) {
                $content = $this->stripTrailingDot($content);
            }
            $records[] = [
                'id' => $this->generateRecordId($name, $type, $content),
                'type' => $type,
                'name' => $name,
                'content' => $content,
                'ttl' => $ttl,
                'proxied' => false,
                'disabled' => !empty($record['disabled']),
            ];
        }
        return $records;
    }

    private function clearZoneCache(string $zoneName): void
    {
        $normalized = $this->normalizeZoneName($zoneName);
        $key = strtolower($normalized);
        unset($this->zoneDetailCache[$key], $this->zoneRecordCache[$key], $this->zoneRecordCacheDisabled[$key]);
    }

    private function markZoneCacheDisabled(string $zoneName): void
    {
        $key = strtolower($this->normalizeZoneName($zoneName));
        $this->zoneRecordCacheDisabled[$key] = true;
    }

    private function isZoneCacheDisabled(string $zoneName): bool
    {
        $key = strtolower($this->normalizeZoneName($zoneName));
        return !empty($this->zoneRecordCacheDisabled[$key]);
    }

    private function memoryLimitBytes(): int
    {
        $limit = ini_get('memory_limit');
        if ($limit === false || $limit === '' || $limit === '-1') {
            return 0;
        }
        $value = trim($limit);
        $unit = strtolower(substr($value, -1));
        $number = (int) $value;
        switch ($unit) {
            case 'g':
                return $number * 1024 * 1024 * 1024;
            case 'm':
                return $number * 1024 * 1024;
            case 'k':
                return $number * 1024;
            default:
                return (int) $value;
        }
    }

    private function canCacheEstimatedRecords(int $estimatedRecords): bool
    {
        if ($estimatedRecords <= 0) {
            return true;
        }
        $limit = $this->memoryLimitBytes();
        if ($limit === 0) {
            return true;
        }
        $usage = function_exists('memory_get_usage') ? memory_get_usage(true) : 0;
        $headroom = $limit - $usage;
        if ($headroom <= 0) {
            return false;
        }
        $estimatedBytes = max(1, $estimatedRecords) * 400;
        return ($estimatedBytes * 2) < $headroom;
    }

    private function normalizeTargetName(?string $filterName, string $zoneName): ?string
    {
        if ($filterName === null) {
            return null;
        }
        $targetName = $this->normalizeRecordName($filterName);
        if ($targetName === '@.' || $targetName === '@') {
            return $zoneName;
        }
        $zoneTrimmed = $this->stripTrailingDot($zoneName);
        $targetTrimmed = $this->stripTrailingDot($targetName);
        if ($targetTrimmed !== $zoneTrimmed && substr($targetTrimmed, -strlen($zoneTrimmed)) !== $zoneTrimmed) {
            return $this->normalizeRecordName($targetTrimmed . '.' . $zoneTrimmed);
        }
        return $targetName;
    }

    private function collectRecordsFromCacheIndex(array $index, ?string $targetName, ?string $typeFilter): array
    {
        $result = [];
        $typeFilter = $typeFilter ? strtoupper($typeFilter) : null;
        if ($targetName !== null) {
            $nameKey = strtolower($this->stripTrailingDot($targetName));
            $typeGroups = $index[$nameKey] ?? [];
            if ($typeFilter !== null) {
                $typeGroups = isset($typeGroups[$typeFilter]) ? [$typeGroups[$typeFilter]] : [];
            }
            foreach ($typeGroups as $records) {
                foreach ($records as $record) {
                    if ($typeFilter !== null && strtoupper($record['type'] ?? '') !== $typeFilter) {
                        continue;
                    }
                    $result[] = $record;
                }
            }
            return $result;
        }

        foreach ($index as $typeGroups) {
            if ($typeFilter !== null) {
                if (!empty($typeGroups[$typeFilter])) {
                    foreach ($typeGroups[$typeFilter] as $record) {
                        if (strtoupper($record['type'] ?? '') === $typeFilter) {
                            $result[] = $record;
                        }
                    }
                }
                continue;
            }
            foreach ($typeGroups as $records) {
                foreach ($records as $record) {
                    $result[] = $record;
                }
            }
        }
        return $result;
    }

    private function ensureZoneRecordCache(string $zoneName): bool
    {
        if ($this->isZoneCacheDisabled($zoneName)) {
            return false;
        }

        $normalized = $this->normalizeZoneName($zoneName);
        $key = strtolower($normalized);
        if (isset($this->zoneRecordCache[$key])) {
            return true;
        }

        $detail = $this->loadZoneDetail($normalized);
        if (!($detail['success'] ?? false)) {
            return false;
        }

        $rrsets = $detail['result']['rrsets'] ?? [];
        $estimatedRecords = 0;
        foreach ($rrsets as $rrset) {
            $estimatedRecords += max(1, count($rrset['records'] ?? []));
        }
        if (!$this->canCacheEstimatedRecords($estimatedRecords)) {
            $this->markZoneCacheDisabled($zoneName);
            return false;
        }

        $index = [];
        foreach ($rrsets as $rrset) {
            $mapped = $this->mapPdnsToCfRecord($rrset, $normalized);
            if (empty($mapped)) {
                continue;
            }
            $nameKey = strtolower($this->stripTrailingDot($rrset['name'] ?? ''));
            $typeKey = strtoupper($rrset['type'] ?? '');
            if ($nameKey === '' || $typeKey === '') {
                continue;
            }
            $index[$nameKey][$typeKey] = $mapped;
        }

        $this->zoneRecordCache[$key] = [
            'index' => $index,
        ];
        return true;
    }

    private function filterRrsetsToRecords(array $rrsets, string $zoneName, array $params = [], ?string $filterName = null): array
    {
        $normalized = $this->normalizeZoneName($zoneName);
        $targetName = $this->normalizeTargetName($filterName, $normalized);
        $typeFilter = !empty($params['type']) ? strtoupper($params['type']) : null;
        $result = [];
        foreach ($rrsets as $rrset) {
            $rrsetName = $rrset['name'] ?? '';
            if ($targetName !== null && $rrsetName !== $targetName) {
                continue;
            }
            if ($typeFilter !== null && strtoupper($rrset['type'] ?? '') !== $typeFilter) {
                continue;
            }
            $result = array_merge($result, $this->mapPdnsToCfRecord($rrset, $normalized));
        }
        return $result;
    }

    private function updateZoneCacheRrset(string $zoneName, string $recordName, string $type, array $records, ?int $ttl = null): void
    {
        $zoneKey = strtolower($this->normalizeZoneName($zoneName));
        if (empty($this->zoneRecordCache[$zoneKey])) {
            return;
        }
        if (empty($records)) {
            $this->removeZoneCacheRrset($zoneName, $recordName, $type);
            return;
        }

        $normalizedZone = $this->normalizeZoneName($zoneName);
        $rrset = [
            'name' => $this->normalizeRecordName($recordName),
            'type' => strtoupper($type),
            'ttl' => $ttl ?? self::DEFAULT_TTL,
            'records' => [],
        ];
        foreach ($records as $record) {
            $rrset['records'][] = [
                'content' => $record['content'] ?? '',
                'disabled' => !empty($record['disabled']),
            ];
        }
        $mapped = $this->mapPdnsToCfRecord($rrset, $normalizedZone);
        $nameKey = strtolower($this->stripTrailingDot($rrset['name']));
        $this->zoneRecordCache[$zoneKey]['index'][$nameKey][$rrset['type']] = $mapped;
    }

    private function removeZoneCacheRrset(string $zoneName, string $recordName, string $type): void
    {
        $zoneKey = strtolower($this->normalizeZoneName($zoneName));
        if (empty($this->zoneRecordCache[$zoneKey])) {
            return;
        }
        $nameKey = strtolower($this->stripTrailingDot($this->normalizeRecordName($recordName)));
        $typeKey = strtoupper($type);
        unset($this->zoneRecordCache[$zoneKey]['index'][$nameKey][$typeKey]);
        if (empty($this->zoneRecordCache[$zoneKey]['index'][$nameKey])) {
            unset($this->zoneRecordCache[$zoneKey]['index'][$nameKey]);
        }
    }

    /**
     * Generate a unique record ID (PowerDNS doesn't have individual record IDs)
     */
    private function generateRecordId(string $name, string $type, string $content): string
    {
        return 'pdns_' . substr(md5($name . '|' . $type . '|' . $content), 0, 16);
    }

    /**
     * Parse record ID to get name, type, content
     */
    private function parseRecordContext(string $recordId, string $zoneName): ?array
    {
        // For PowerDNS, record_id is the name|type|content hash or stored context
        // We need to lookup the record first
        return null;
    }

    private function normalizeContentForId(string $type, string $content): string
    {
        $type = strtoupper($type);
        if (in_array($type, ['CNAME', 'MX', 'NS', 'SRV', 'PTR'], true)) {
            return $this->stripTrailingDot($content);
        }
        return $content;
    }

    private function formatRecordContentForPatch(string $type, string $content, array $data = []): string
    {
        $type = strtoupper($type);
        if ($type === 'MX') {
            $priority = isset($data['priority']) ? (int) $data['priority'] : 10;
            return $priority . ' ' . $this->ensureTrailingDot($content);
        }
        if ($type === 'TXT') {
            return $this->normalizeTxtInput($content, true);
        }
        if (in_array($type, ['CNAME', 'NS', 'PTR'], true)) {
            return $this->ensureTrailingDot($content);
        }
        if ($type === 'CAA' || $type === 'SRV') {
            return $content;
        }
        return $content;
    }

    private function buildRecordIdFromRaw(string $name, string $type, string $content): string
    {
        return $this->generateRecordId(
            $this->stripTrailingDot($name),
            strtoupper($type),
            $this->normalizeContentForId($type, $content)
        );
    }

    private function normalizeTxtInput(string $content, bool $wrapQuotes = true): string
    {
        $decoded = html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $trimmed = trim($decoded);
        if ($trimmed === '') {
            return $wrapQuotes ? '""' : '';
        }
        if ($trimmed[0] === '"' && substr($trimmed, -1) === '"' && strlen($trimmed) >= 2) {
            $trimmed = substr($trimmed, 1, -1);
        }
        if (!$wrapQuotes) {
            return $trimmed;
        }
        $escaped = str_replace('"', '\"', $trimmed);
        return '"' . $escaped . '"';
    }


    private function normalizeTtl($ttl): int
    {
        $t = intval($ttl);
        if ($t <= 0) {
            return self::DEFAULT_TTL;
        }
        return max(60, $t);
    }

    private function ensureTrailingDot(string $value): string
    {
        $value = trim($value);
        if ($value !== '' && substr($value, -1) !== '.') {
            return $value . '.';
        }
        return $value;
    }

    private function loadZoneDetail(string $zoneName, bool $forceRefresh = false): array
    {
        $normalized = $this->normalizeZoneName($zoneName);
        $cacheKey = strtolower($normalized);
        if (!$forceRefresh && isset($this->zoneDetailCache[$cacheKey])) {
            return $this->zoneDetailCache[$cacheKey];
        }

        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($normalized);
        $res = $this->request('GET', $endpoint);
        if ($res['success'] ?? false) {
            $this->zoneDetailCache[$cacheKey] = $res;
        }
        return $res;
    }

    // ==================== Public API Methods ====================

    /**
     * Get zone ID (for PowerDNS, zone ID is the zone name with trailing dot)
     */
    public function getZoneId(string $domain)
    {
        $zoneName = $this->normalizeZoneName($domain);
        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);
        $res = $this->request('GET', $endpoint);

        if ($res['success'] ?? false) {
            return $this->stripTrailingDot($res['result']['name'] ?? $domain);
        }
        return false;
    }

    /**
     * Validate API credentials
     */
    public function validateCredentials(): bool
    {
        $endpoint = '/servers/' . urlencode($this->server_id);
        $res = $this->request('GET', $endpoint);
        return ($res['success'] ?? false) === true;
    }

    /**
     * Get all zones
     */
    public function getZones(): array
    {
        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones';
        $res = $this->request('GET', $endpoint);

        if (!($res['success'] ?? false)) {
            return ['success' => false, 'errors' => $res['errors'] ?? ['query failed']];
        }

        $zones = [];
        foreach (($res['result'] ?? []) as $z) {
            $name = $this->stripTrailingDot($z['name'] ?? '');
            $zones[] = [
                'name' => $name,
                'id' => $name,
            ];
        }
        return ['success' => true, 'result' => $zones];
    }

    /**
     * Check if domain/record exists
     */
    public function checkDomainExists(string $zoneId, string $domainName): bool
    {
        $records = $this->getDnsRecords($zoneId, $domainName);
        if (!($records['success'] ?? false)) {
            return false;
        }
        return count($records['result'] ?? []) > 0;
    }

    /**
     * Get DNS records for a zone
     */
    public function getDnsRecords(string $zoneId, ?string $name = null, array $params = []): array
    {
        $zoneName = $this->normalizeZoneName($zoneId);
        $trimmedName = trim((string) $name);

        if ($trimmedName !== '') {
            $precise = $this->fetchZoneRecordsPrecise($zoneName, $trimmedName, $params);
            if (($precise['success'] ?? false) && empty($precise['fallback'])) {
                return $precise;
            }
            if (($precise['success'] ?? false) && empty($precise['result'])) {
                // allow fallback to search-data when precise lookup returns no entries
            } elseif (!($precise['success'] ?? false) && empty($precise['fallback'])) {
                return $precise;
            }

            $searchResult = $this->fetchRecordsByName($zoneName, $trimmedName, $params);
            if ($searchResult['success'] ?? false) {
                return $searchResult;
            }
            if (empty($searchResult['success']) && empty($searchResult['fallback'])) {
                return $searchResult;
            }

            // fall back to full zone fetch when the previous strategies cannot satisfy the query
            return $this->fetchZoneRecords($zoneName, $params, $trimmedName);
        }

        return $this->fetchZoneRecords($zoneName, $params);
    }

    /**
     * Get records for a specific domain
     */
    public function getDomainRecords(string $zoneId, string $domainName): array
    {
        $res = $this->getDnsRecords($zoneId, $domainName);
        if ($res['success']) {
            return $res['result'];
        }
        return [];
    }

    private function fetchZoneRecords(string $zoneName, array $params = [], ?string $filterName = null): array
{
if (!$this->ensureZoneRecordCache($zoneName)) {
if ($filterName !== null) {
$targeted = $this->fetchZoneRecordsPrecise($zoneName, $filterName, $params);
if (($targeted['success'] ?? false) && empty($targeted['fallback'])) {
return $targeted;
}
$search = $this->fetchRecordsByName($this->normalizeZoneName($zoneName), $filterName, $params);
if ($search['success'] ?? false) {
return $search;
}
}
return $this->fetchZoneRecordsWithoutCache($zoneName, $params, $filterName);
}
$normalized = $this->normalizeZoneName($zoneName);
$cacheKey = strtolower($normalized);
$cacheIndex = $this->zoneRecordCache[$cacheKey]['index'] ?? [];
$targetName = $this->normalizeTargetName($filterName, $normalized);
$typeFilter = !empty($params['type']) ? strtoupper($params['type']) : null;
$result = $this->collectRecordsFromCacheIndex($cacheIndex, $targetName, $typeFilter);
return ['success' => true, 'result' => $result];
}
private function fetchZoneRecordsWithoutCache(string $zoneName, array $params = [], ?string $filterName = null): array
    {
        $normalized = $this->normalizeZoneName($zoneName);
        $detail = $this->loadZoneDetail($normalized);
        if (!($detail['success'] ?? false)) {
            return ['success' => false, 'errors' => $detail['errors'] ?? ['zone_fetch_failed']];
        }

        $rrsets = $detail['result']['rrsets'] ?? [];
        $records = $this->filterRrsetsToRecords($rrsets, $normalized, $params, $filterName);

        return ['success' => true, 'result' => $records];
    }

    private function fetchExistingRrsetRecords(string $zoneName, string $recordName, string $type): array
{
$normalizedZone = $this->normalizeZoneName($zoneName);
$targetName = $this->normalizeTargetName($recordName, $normalizedZone) ?? $this->normalizeRecordName($recordName);
$typeFilter = strtoupper($type);
$query = ['rrset_name' => $targetName, 'rrset_type' => $typeFilter];
$endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($normalizedZone) . '?' . http_build_query($query);
$res = $this->request('GET', $endpoint);
if (($res['success'] ?? false)) {
foreach (($res['result']['rrsets'] ?? []) as $rrset) {
if (($rrset['name'] ?? '') === $targetName && strtoupper($rrset['type'] ?? '') === $typeFilter) {
return ['success' => true, 'records' => $rrset['records'] ?? [], 'ttl' => $rrset['ttl'] ?? null];
}
}
}
$searchQuery = [
'q' => $this->stripTrailingDot($targetName),
'object' => 'record',
'max' => 500,
];
$searchEndpoint = '/servers/' . urlencode($this->server_id) . '/search-data?' . http_build_query($searchQuery);
$search = $this->request('GET', $searchEndpoint);
if (($search['success'] ?? false)) {
$records = [];
$ttl = null;
foreach (($search['result'] ?? []) as $item) {
$itemZone = $this->normalizeZoneName($item['zone'] ?? ($item['zone_id'] ?? ''));
if ($itemZone !== $normalizedZone) { continue; }
$itemName = $this->normalizeRecordName($item['name'] ?? '');
if ($itemName !== $targetName) { continue; }
$itemType = strtoupper($item['type'] ?? '');
if ($itemType !== $typeFilter) { continue; }
$records[] = [
'content' => $item['content'] ?? '',
'disabled' => !empty($item['disabled']),
];
if ($ttl === null && isset($item['ttl'])) { $ttl = $item['ttl']; }
}
if (!empty($records)) {
return ['success' => true, 'records' => $records, 'ttl' => $ttl];
}
}
return ['success' => false, 'errors' => ['rrset_lookup_failed']];
}

private function fetchZoneRecordsPrecise(string $zoneName, string $name, array $params = []): array
    {
        $normalizedZone = $this->normalizeZoneName($zoneName);
        $targetName = $this->normalizeTargetName($name, $normalizedZone) ?? $this->normalizeRecordName($name);
        $query = ['rrset_name' => $targetName];
        if (!empty($params['type'])) {
            $query['rrset_type'] = strtoupper($params['type']);
        }
        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($normalizedZone) . '?' . http_build_query($query);
        $res = $this->request('GET', $endpoint);
        if (!($res['success'] ?? false)) {
            return ['success' => false, 'fallback' => true, 'errors' => $res['errors'] ?? ['precise query failed']];
        }
        $rrsets = $res['result']['rrsets'] ?? [];
        if (empty($rrsets)) {
            return ['success' => true, 'result' => [], 'fallback' => true];
        }
        $records = $this->filterRrsetsToRecords($rrsets, $normalizedZone, $params, $targetName);
        return ['success' => true, 'result' => $records];
    }

private function fetchRecordsByName(string $zoneName, string $name, array $params): array
    {
        $searchName = $this->normalizeRecordName($name);
        if ($searchName === '@.' || $searchName === '@') {
            $searchName = $zoneName;
        }
        $zoneTrimmed = $this->stripTrailingDot($zoneName);
        $searchTrimmed = $this->stripTrailingDot($searchName);
        if ($searchTrimmed !== $zoneTrimmed && substr($searchTrimmed, -strlen($zoneTrimmed)) !== $zoneTrimmed) {
            $searchName = $this->normalizeRecordName($searchTrimmed . '.' . $zoneTrimmed);
        }

        $maxResults = isset($params['per_page']) ? (int) $params['per_page'] : (int) ($params['max_results'] ?? 250);
        $query = http_build_query([
            'q' => $this->stripTrailingDot($searchName),
            'object' => 'rrset',
            'max' => max(1, min(1000, $maxResults > 0 ? $maxResults : 250)),
        ]);

        $endpoint = '/servers/' . urlencode($this->server_id) . '/search-data?' . $query;
        $res = $this->request('GET', $endpoint);
        if (!($res['success'] ?? false)) {
            return ['success' => false, 'fallback' => true, 'errors' => $res['errors'] ?? ['search failed']];
        }

        $items = $res['result'] ?? [];
        if (empty($items)) {
            return ['success' => true, 'result' => []];
        }

        $typeFilter = !empty($params['type']) ? strtoupper($params['type']) : null;
        $rrsets = [];
        foreach ($items as $item) {
            $itemZone = $this->normalizeZoneName($item['zone_id'] ?? ($item['zone'] ?? ''));
            if ($itemZone !== $zoneName) {
                continue;
            }
            $itemName = $this->normalizeRecordName($item['name'] ?? $searchName);
            $type = strtoupper($item['type'] ?? '');
            if ($type === '' || ($typeFilter && $type !== $typeFilter)) {
                continue;
            }
            if (!isset($rrsets[$itemName][$type])) {
                $rrsets[$itemName][$type] = [
                    'name' => $itemName,
                    'type' => $type,
                    'ttl' => $item['ttl'] ?? null,
                    'records' => [],
                ];
            }
            $rrsets[$itemName][$type]['records'][] = [
                'content' => $item['content'] ?? '',
                'disabled' => !empty($item['disabled']),
            ];
        }

        $result = [];
        foreach ($rrsets as $typeGroup) {
            foreach ($typeGroup as $rrset) {
                $result = array_merge($result, $this->mapPdnsToCfRecord($rrset, $zoneName));
            }
        }

        return ['success' => true, 'result' => $result];
    }

    /**
     * Create a DNS record
     */
    public function createDnsRecord(string $zoneId, string $name, string $type,
string $content, $ttl = 3600, bool $proxied = false): array
{
$zoneName = $this->normalizeZoneName($zoneId);
$recordName = $this->normalizeRecordName($name);
$type = strtoupper($type);
$ttl = $this->normalizeTtl($ttl);
// Normalize content for certain record types
if (in_array($type, ['CNAME', 'MX', 'NS', 'PTR'])) {
$content = $this->ensureTrailingDot($content);
}
if ($type === 'TXT') {
$content = $this->normalizeTxtInput($content, true);
}
// First, get existing records for this name+type
$lookup = $this->fetchExistingRrsetRecords($zoneName, $recordName, $type);
$existingRecords = [];
$ttlForPatch = $ttl;
if ($lookup['success'] ?? false) {
$existingRecords = array_map(function ($rec) {
return [
'content' => $rec['content'] ?? '',
'disabled' => !empty($rec['disabled']),
];
}, $lookup['records'] ?? []);
$ttlForPatch = $this->normalizeTtl($lookup['ttl'] ?? $ttl);
}
// Add new record to existing
$existingRecords[] = ['content' => $content, 'disabled' => false];
$endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);
// PATCH the zone with updated RRset
$payload = [
'rrsets' => [
[
'name' => $recordName,
'type' => $type,
'ttl' => $ttlForPatch,
'changetype' => 'REPLACE',
'records' => $existingRecords,
]
]
];
$res = $this->request('PATCH', $endpoint, $payload);
if (!($res['success'] ?? false)) {
return ['success' => false, 'errors' => $res['errors'] ?? ['create failed']];
}
$this->updateZoneCacheRrset($zoneName, $recordName, $type, $existingRecords, $ttlForPatch);
$recordId = $this->generateRecordId($this->stripTrailingDot($recordName)
, $type, $this->stripTrailingDot($content));
return [
'success' => true,
'result' => [
'id' => $recordId,
'name' => $this->stripTrailingDot($recordName),
'type' => $type,
'content' => $this->stripTrailingDot($content),
'ttl' => $ttlForPatch,
'proxied' => false,
]
];
}
public function updateDnsRecord(string $zoneId, string $recordId, array $data): array
{
$zoneName = $this->normalizeZoneName($zoneId);
$type = strtoupper($data['type'] ?? 'A');
$name = $data['name'] ?? '';
$content = $data['content'] ?? '';
$ttl = $this->normalizeTtl($data['ttl'] ?? self::DEFAULT_TTL);
if ($name === '' || $content === '') {
return ['success' => false, 'errors' => ['missing required fields']];
}
$recordName = $this->normalizeRecordName($name);
$formattedContent = $this->formatRecordContentForPatch($type, $content, $data);
$lookup = $this->fetchExistingRrsetRecords($zoneName, $recordName, $type);
$recordsPayload = [];
$ttlForPatch = $ttl;
if ($lookup['success'] ?? false) {
$recordsPayload = array_map(function ($rec) {
return [
'content' => $rec['content'] ?? '',
'disabled' => !empty($rec['disabled']),
];
}, $lookup['records'] ?? []);
$ttlForPatch = $this->normalizeTtl($lookup['ttl'] ?? $ttl);
} else {
$zoneDetail = $this->loadZoneDetail($zoneName);
if (!($zoneDetail['success'] ?? false)) {
return ['success' => false, 'errors' => $zoneDetail['errors'] ?? ['query failed']];
}
foreach (($zoneDetail['result']['rrsets'] ?? []) as $rrset) {
if (($rrset['name'] ?? '') === $recordName && strtoupper($rrset['type'] ?? '') === $type) {
$ttlForPatch = $this->normalizeTtl($rrset['ttl'] ?? $ttl);
foreach (($rrset['records'] ?? []) as $record) {
$recordsPayload[] = [
'content' => $record['content'],
'disabled' => !empty($record['disabled']),
];
}
break;
}
}
}
if (empty($recordsPayload)) {
$recordsPayload[] = ['content' => $formattedContent, 'disabled' => false];
$recordMatched = true;
} else {
$recordMatched = false;
foreach ($recordsPayload as &$record) {
$existingId = $this->buildRecordIdFromRaw($recordName, $type, $record['content'] ?? '');
if ($existingId === $recordId) {
$record['content'] = $formattedContent;
$recordMatched = true;
}
}
unset($record);
if (!$recordMatched) {
$recordsPayload[] = ['content' => $formattedContent, 'disabled' => false];
}
}
$endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);
$payload = [
'rrsets' => [
[
'name' => $recordName,
'type' => $type,
'ttl' => $ttlForPatch,
'changetype' => 'REPLACE',
'records' => $recordsPayload,
]
]
];
$res = $this->request('PATCH', $endpoint, $payload);
if (!($res['success'] ?? false)) {
return ['success' => false, 'errors' => $res['errors'] ?? ['update failed']];
}
$this->updateZoneCacheRrset($zoneName, $recordName, $type, $recordsPayload, $ttlForPatch);
$newRecordId = $this->buildRecordIdFromRaw($recordName, $type, $formattedContent);
return ['success' => true, 'result' => ['id' => $newRecordId]];
}
public function deleteSubdomain(string $zoneId, string $recordId): array
    {
        $zoneName = $this->normalizeZoneName($zoneId);
        $recordId = (string) $recordId;

        if ($recordId === '') {
            return ['success' => false, 'errors' => ['record id required']];
        }

        $zoneDetail = $this->loadZoneDetail($zoneName);
        if (!($zoneDetail['success'] ?? false)) {
            return ['success' => false, 'errors' => $zoneDetail['errors'] ?? ['query failed']];
        }

        $targetName = '';
        $targetType = '';
        $targetRecords = [];
        $ttl = self::DEFAULT_TTL;

        foreach (($zoneDetail['result']['rrsets'] ?? []) as $rrset) {
            $name = $rrset['name'] ?? '';
            $type = strtoupper($rrset['type'] ?? '');
            foreach (($rrset['records'] ?? []) as $record) {
                $existingId = $this->buildRecordIdFromRaw($name, $type, $record['content'] ?? '');
                if ($existingId === $recordId) {
                    $targetName = $name;
                    $targetType = $type;
                    $targetRecords = $rrset['records'] ?? [];
                    $ttl = $this->normalizeTtl($rrset['ttl'] ?? $ttl);
                    break 2;
                }
            }
        }

        if ($targetName === '') {
            return ['success' => false, 'errors' => ['record not found']];
        }

        $remainingRecords = [];
        foreach ($targetRecords as $record) {
            $existingId = $this->buildRecordIdFromRaw($targetName, $targetType, $record['content'] ?? '');
            if ($existingId === $recordId) {
                continue;
            }
            $remainingRecords[] = [
                'content' => $record['content'],
                'disabled' => !empty($record['disabled']),
            ];
        }

        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);

        if (empty($remainingRecords)) {
            $payload = [
                'rrsets' => [
                    [
                        'name' => $targetName,
                        'type' => $targetType,
                        'changetype' => 'DELETE',
                    ]
                ]
            ];
        } else {
            $payload = [
                'rrsets' => [
                    [
                        'name' => $targetName,
                        'type' => $targetType,
                        'ttl' => $ttl,
                        'changetype' => 'REPLACE',
                        'records' => $remainingRecords,
                    ]
                ]
            ];
        }

        $res = $this->request('PATCH', $endpoint, $payload);

        if (!($res['success'] ?? false)) {
            return ['success' => false, 'errors' => $res['errors'] ?? ['delete failed']];
        }

        if (empty($remainingRecords)) {
            $this->removeZoneCacheRrset($zoneName, $targetName, $targetType);
        } else {
            $this->updateZoneCacheRrset($zoneName, $targetName, $targetType, $remainingRecords, $ttl);
        }
        return ['success' => true, 'result' => []];
    }

    /**
     * Delete all records for a specific name
     */
    public function deleteDomainRecords(string $zoneId, string $domainName): array
    {
        $zoneName = $this->normalizeZoneName($zoneId);
        $recordName = $this->normalizeRecordName($domainName);

        // Get all record types for this name
        $records = $this->getDnsRecords($zoneId, $domainName);
        if (!($records['success'] ?? false)) {
            return ['success' => false, 'errors' => $records['errors'] ?? ['query failed']];
        }

        if (empty($records['result'])) {
            return ['success' => true, 'deleted_count' => 0];
        }

        // Group by type to delete
        $typesSeen = [];
        foreach ($records['result'] as $rec) {
            $typesSeen[$rec['type']] = true;
        }

        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);
        $rrsets = [];
        foreach (array_keys($typesSeen) as $type) {
            $rrsets[] = [
                'name' => $recordName,
                'type' => $type,
                'changetype' => 'DELETE',
            ];
        }

        $payload = ['rrsets' => $rrsets];
        $res = $this->request('PATCH', $endpoint, $payload);

        if (!($res['success'] ?? false)) {
            return ['success' => false, 'errors' => $res['errors'] ?? ['delete failed']];
        }

        foreach (array_keys($typesSeen) as $type) {
            $this->removeZoneCacheRrset($zoneName, $recordName, $type);
        }
        return ['success' => true, 'deleted_count' => count($records['result'])];
        }

    /**
     * Delete records for a name and all its subdomains
     */
    public function deleteDomainRecordsDeep(string $zoneId, string $subdomainRoot): array
    {
        $zoneName = $this->normalizeZoneName($zoneId);
        $target = $this->normalizeRecordName($subdomainRoot);
        $targetNoDot = $this->stripTrailingDot($target);

        // Get all records in zone
        $allRecords = $this->getDnsRecords($zoneId);
        if (!($allRecords['success'] ?? false)) {
            return ['success' => false, 'errors' => $allRecords['errors'] ?? ['query failed']];
        }

        // Find records matching target or *.target
        $toDelete = [];
        foreach (($allRecords['result'] ?? []) as $rec) {
            $recName = strtolower($rec['name'] ?? '');
            if ($recName === $targetNoDot || $this->endsWith($recName, '.' . $targetNoDot)) {
                $key = $rec['name'] . '|' . $rec['type'];
                if (!isset($toDelete[$key])) {
                    $toDelete[$key] = ['name' => $rec['name'], 'type' => $rec['type']];
                }
            }
        }

        if (empty($toDelete)) {
            return ['success' => true, 'deleted_count' => 0, 'note' => 'deep'];
        }

        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);
        $rrsets = [];
        foreach ($toDelete as $item) {
            $rrsets[] = [
                'name' => $this->normalizeRecordName($item['name']),
                'type' => $item['type'],
                'changetype' => 'DELETE',
            ];
        }

        $payload = ['rrsets' => $rrsets];
        $res = $this->request('PATCH', $endpoint, $payload);

        if (!($res['success'] ?? false)) {
            return ['success' => false, 'errors' => $res['errors'] ?? ['delete failed']];
        }

        foreach ($toDelete as $item) {
            $this->removeZoneCacheRrset($zoneName, $item['name'], $item['type']);
        }
        return ['success' => true, 'deleted_count' => count($toDelete), 'note' => 'deep'];
        }

    /**
     * Delete a specific record by name, type, and content
     */
    public function deleteRecordByContent(string $zoneId, string $name, string $type, string $content): array
    {
        $zoneName = $this->normalizeZoneName($zoneId);
        $recordName = $this->normalizeRecordName($name);
        $type = strtoupper($type);

        // Get existing records for this name+type
        $existing = $this->getDnsRecords($zoneId, $name, ['type' => $type]);
        if (!($existing['success'] ?? false)) {
            return ['success' => false, 'errors' => $existing['errors'] ?? ['query failed']];
        }

        // Filter out the record to delete
        $remaining = [];
        $found = false;
        foreach (($existing['result'] ?? []) as $rec) {
            if (strtolower($rec['content'] ?? '') === strtolower($content)) {
                $found = true;
                continue;
            }
            $remaining[] = ['content' => $rec['content'], 'disabled' => $rec['disabled'] ?? false];
        }

        if (!$found) {
            return ['success' => false, 'errors' => ['record not found']];
        }

        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);

        if (empty($remaining)) {
            // Delete the entire RRset
            $payload = [
                'rrsets' => [
                    [
                        'name' => $recordName,
                        'type' => $type,
                        'changetype' => 'DELETE',
                    ]
                ]
            ];
        } else {
            // Replace with remaining records
            $ttl = $existing['result'][0]['ttl'] ?? self::DEFAULT_TTL;
            $payload = [
                'rrsets' => [
                    [
                        'name' => $recordName,
                        'type' => $type,
                        'ttl' => $ttl,
                        'changetype' => 'REPLACE',
                        'records' => $remaining,
                    ]
                ]
            ];
        }

        $res = $this->request('PATCH', $endpoint, $payload);

        if (!($res['success'] ?? false)) {
            return ['success' => false, 'errors' => $res['errors'] ?? ['delete failed']];
}

        if (empty($remaining)) {
            $this->removeZoneCacheRrset($zoneName, $recordName, $type);
        } else {
            $this->updateZoneCacheRrset($zoneName, $recordName, $type, $remaining, $ttl ?? self::DEFAULT_TTL);
        }
        return ['success' => true, 'result' => []];
    }

    /**
     * Create subdomain with default A record
     */
    public function createSubdomain(string $zoneId, string $subdomain, string $ip = '192.0.2.1', bool $proxied = true, string $type = 'A'): array
    {
        return $this->createDnsRecord($zoneId, $subdomain, $type, $ip, 120, false);
    }

    /**
     * Update subdomain
     */
    public function updateSubdomain(string $zoneId, string $recordId, string $subdomain, string $ip, bool $proxied = true): array
    {
        return $this->updateDnsRecord($zoneId, $recordId, [
            'type' => 'A',
            'name' => $subdomain,
            'content' => $ip,
            'ttl' => 120,
        ]);
    }

    /**
     * Create CNAME record
     */
    public function createCNAMERecord(string $zoneId, string $name, string $target, int $ttl = 3600, bool $proxied = false): array
    {
        return $this->createDnsRecord($zoneId, $name, 'CNAME', $target, $ttl, false);
    }

    /**
     * Create MX record
     */
    public function createMXRecord(string $zoneId, string $name, string $mailServer, int $priority = 10, int $ttl = 3600): array
    {
        // PowerDNS MX format: "priority mailserver."
        $content = $priority . ' ' . $this->ensureTrailingDot($mailServer);
        return $this->createDnsRecord($zoneId, $name, 'MX', $content, $ttl, false);
    }

    /**
     * Create SRV record
     */
    public function createSRVRecord(string $zoneId, string $name, string $target, int $port, int $priority = 0, int $weight = 0, int $ttl = 3600): array
    {
        // PowerDNS SRV format: "priority weight port target."
        $content = $priority . ' ' . $weight . ' ' . $port . ' ' . $this->ensureTrailingDot($target);
        return $this->createDnsRecord($zoneId, $name, 'SRV', $content, $ttl, false);
    }

    /**
     * Create CAA record
     */
    public function createCAARecord(string $zoneId, string $name, int $flags, string $tag, string $value, int $ttl = 3600): array
    {
        // PowerDNS CAA format: "flags tag \"value\""
        $content = $flags . ' ' . $tag . ' "' . str_replace('"', '\\"', $value) . '"';
        return $this->createDnsRecord($zoneId, $name, 'CAA', $content, $ttl, false);
    }

    /**
     * Create TXT record
     */
    public function createTXTRecord(string $zoneId, string $name, string $content, int $ttl = 3600): array
    {
        // Ensure TXT content is quoted
        if (strlen($content) > 0 && $content[0] !== '"') {
            $content = '"' . str_replace('"', '\\"', $content) . '"';
        }
        return $this->createDnsRecord($zoneId, $name, 'TXT', $content, $ttl, false);
    }

    /**
     * Toggle proxy (not supported in PowerDNS)
     */
    public function toggleProxy(string $zoneId, string $recordId, bool $proxied): array
    {
        return ['success' => true, 'result' => ['proxied' => false, 'note' => 'PowerDNS does not support proxy']];
    }

    /**
     * Get single DNS record by ID
     */
    public function getDnsRecord(string $zoneId, string $recordId): array
    {
        // PowerDNS doesn't have individual record IDs, need to search
        $records = $this->getDnsRecords($zoneId);
        if (!($records['success'] ?? false)) {
            return ['success' => false, 'errors' => ['query failed']];
        }

        foreach (($records['result'] ?? []) as $rec) {
            if (($rec['id'] ?? '') === $recordId) {
                return ['success' => true, 'result' => $rec];
            }
        }

        return ['success' => false, 'errors' => ['record not found']];
    }

    /**
     * Raw record creation with full payload support
     */
    public function createDnsRecordRaw(string $zoneId, array $payload): array
    {
        if (!isset($payload['type'], $payload['name'])) {
            return ['success' => false, 'errors' => ['missing required fields']];
        }
        return $this->createDnsRecord(
            $zoneId,
            $payload['name'],
            $payload['type'],
            $payload['content'] ?? '',
            $payload['ttl'] ?? self::DEFAULT_TTL,
            false
        );
    }

    /**
     * Raw record update
     */
    public function updateDnsRecordRaw(string $zoneId, string $recordId, array $payload): array
    {
        return $this->updateDnsRecord($zoneId, $recordId, $payload);
    }

    /**
     * Get account/server info
     */
    public function getAccountInfo(): array
    {
        $ok = $this->validateCredentials();
        return ['success' => $ok];
    }

    /**
     * Search zones
     */
    public function searchZone(string $searchTerm): array
    {
        $res = $this->getZones();
        if (!($res['success'] ?? false)) {
            return $res;
        }
        $term = strtolower($searchTerm);
        $filtered = array_values(array_filter($res['result'] ?? [], function ($z) use ($term) {
            return strpos(strtolower($z['name'] ?? ''), $term) !== false;
        }));
        return ['success' => true, 'result' => $filtered];
    }

    /**
     * Get zone details
     */
    public function getZoneDetails(string $zoneId): array
    {
        $zoneName = $this->normalizeZoneName($zoneId);
        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);
        $res = $this->request('GET', $endpoint);
        return [
            'success' => $res['success'] ?? false,
            'result' => $res['result'] ?? [],
        ];
    }

    // Unsupported Cloudflare-specific methods
    public function getZoneSettings(string $zoneId): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function updateZoneSetting(string $zoneId, string $settingName, $value): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function enableCDN(string $zoneId): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function getZoneAnalytics(string $zoneId, string $since = '-7d', string $until = 'now'): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function getFirewallRules(string $zoneId): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function createFirewallRule(string $zoneId, string $expression, string $action = 'block', string $description = ''): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function getPageRules(string $zoneId): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function createPageRule(string $zoneId, string $urlPattern, array $actions, int $priority = 1, string $status = 'active'): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function getRateLimits(string $zoneId): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function createRateLimit(string $zoneId, string $expression, int $threshold, int $period, string $action = 'block'): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function purgeCache(string $zoneId, ?array $files = null): array
    {
        return ['success' => false, 'errors' => ['unsupported' => 'PowerDNS']];
    }

    public function batchUpdateDnsRecords(string $zoneId, array $updates): array
    {
        $results = [];
        foreach ($updates as $update) {
            if (isset($update['id'])) {
                $results[] = $this->updateDnsRecord($zoneId, $update['id'], $update);
            } else {
                $results[] = $this->createDnsRecord(
                    $zoneId,
                    $update['name'] ?? '',
                    $update['type'] ?? 'A',
                    $update['content'] ?? '',
                    $update['ttl'] ?? self::DEFAULT_TTL,
                    false
                );
            }
        }
        return $results;
    }

    private function endsWith(string $haystack, string $needle): bool
    {
        if ($needle === '') {
            return true;
        }
        $len = strlen($needle);
        if (strlen($haystack) < $len) {
            return false;
        }
        return substr($haystack, -$len) === $needle;
    }
}
