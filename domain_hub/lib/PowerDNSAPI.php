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
        $ttl = intval($rrset['ttl'] ?? self::DEFAULT_TTL);

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

    private function loadZoneDetail(string $zoneName): array
    {
        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);
        return $this->request('GET', $endpoint);
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
        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);
        $res = $this->request('GET', $endpoint);

        if (!($res['success'] ?? false)) {
            return ['success' => false, 'errors' => $res['errors'] ?? ['query failed']];
        }

        $rrsets = $res['result']['rrsets'] ?? [];
        $result = [];
        $targetName = $name ? $this->normalizeRecordName($name) : null;
        $typeFilter = !empty($params['type']) ? strtoupper($params['type']) : null;

        foreach ($rrsets as $rrset) {
            $rrsetName = $rrset['name'] ?? '';

            // Filter by name if specified
            if ($targetName !== null) {
                if ($rrsetName !== $targetName) {
                    continue;
                }
            }

            // Filter by type if specified
            if ($typeFilter !== null && ($rrset['type'] ?? '') !== $typeFilter) {
                continue;
            }

            $mapped = $this->mapPdnsToCfRecord($rrset, $zoneId);
            foreach ($mapped as $rec) {
                $result[] = $rec;
            }
        }

        return ['success' => true, 'result' => $result];
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

    /**
     * Create a DNS record
     */
    public function createDnsRecord(string $zoneId, string $name, string $type, string $content, $ttl = 3600, bool $proxied = false): array
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
        $endpoint = '/servers/' . urlencode($this->server_id) . '/zones/' . urlencode($zoneName);
        $zoneRes = $this->request('GET', $endpoint);

        $existingRecords = [];
        if ($zoneRes['success'] ?? false) {
            foreach (($zoneRes['result']['rrsets'] ?? []) as $rrset) {
                if (($rrset['name'] ?? '') === $recordName && ($rrset['type'] ?? '') === $type) {
                    foreach (($rrset['records'] ?? []) as $rec) {
                        $existingRecords[] = ['content' => $rec['content'], 'disabled' => $rec['disabled'] ?? false];
                    }
                    break;
                }
            }
        }

        // Add new record to existing
        $existingRecords[] = ['content' => $content, 'disabled' => false];

        // PATCH the zone with updated RRset
        $payload = [
            'rrsets' => [
                [
                    'name' => $recordName,
                    'type' => $type,
                    'ttl' => $ttl,
                    'changetype' => 'REPLACE',
                    'records' => $existingRecords,
                ]
            ]
        ];

        $res = $this->request('PATCH', $endpoint, $payload);

        if (!($res['success'] ?? false)) {
            return ['success' => false, 'errors' => $res['errors'] ?? ['create failed']];
        }

        $recordId = $this->generateRecordId($this->stripTrailingDot($recordName), $type, $this->stripTrailingDot($content));

        return [
            'success' => true,
            'result' => [
                'id' => $recordId,
                'name' => $this->stripTrailingDot($recordName),
                'type' => $type,
                'content' => $this->stripTrailingDot($content),
                'ttl' => $ttl,
                'proxied' => false,
            ]
        ];
    }

    /**
     * Update a DNS record
     */
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

        $zoneDetail = $this->loadZoneDetail($zoneName);
        if (!($zoneDetail['success'] ?? false)) {
            return ['success' => false, 'errors' => $zoneDetail['errors'] ?? ['query failed']];
        }

        $rrsets = $zoneDetail['result']['rrsets'] ?? [];
        $recordsPayload = [];
        $recordMatched = false;
        $ttlForPatch = $ttl;

        foreach ($rrsets as $rrset) {
            if (($rrset['name'] ?? '') === $recordName && strtoupper($rrset['type'] ?? '') === $type) {
                $ttlForPatch = $this->normalizeTtl($rrset['ttl'] ?? $ttl);
                foreach (($rrset['records'] ?? []) as $record) {
                    $existingId = $this->buildRecordIdFromRaw($recordName, $type, $record['content'] ?? '');
                    if ($existingId === $recordId) {
                        $recordsPayload[] = [
                            'content' => $formattedContent,
                            'disabled' => !empty($record['disabled']),
                        ];
                        $recordMatched = true;
                    } else {
                        $recordsPayload[] = [
                            'content' => $record['content'],
                            'disabled' => !empty($record['disabled']),
                        ];
                    }
                }
                break;
            }
        }

        if (empty($recordsPayload)) {
            $recordsPayload[] = ['content' => $formattedContent, 'disabled' => false];
        } elseif (!$recordMatched) {
            $recordsPayload[] = ['content' => $formattedContent, 'disabled' => false];
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

        $newRecordId = $this->buildRecordIdFromRaw($recordName, $type, $formattedContent);

        return ['success' => true, 'result' => ['id' => $newRecordId]];
    }

    /**
     * Delete a subdomain/record
     */
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
