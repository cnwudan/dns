<?php

class DNSPodIntlAPI {
    private const MAX_RETRIES = 3;
    private const RETRY_BASE_DELAY_MS = 200;

    private $secretId;
    private $secretKey;
    private $endpoint = 'dnspod.intl.tencentcloudapi.com';
    private $service = 'dnspod';
    private $version = '2021-03-23';
    private $region = 'ap-hongkong';

    public function __construct($secretId, $secretKey)
    {
        $this->secretId = trim((string) $secretId);
        $this->secretKey = trim((string) $secretKey);
    }

    private function tc3Request(string $action, array $payload): array
    {
        $attempt = 0;
        $response = [];
        do {
            $attempt++;
            $response = $this->performTc3Request($action, $payload);
            if (!$this->shouldRetry($response) || $attempt >= self::MAX_RETRIES) {
                break;
            }
            usleep($this->retryDelayMicros($attempt));
        } while (true);
        return $response;
    }

    private function performTc3Request(string $action, array $payload): array
    {
        $timestamp = time();
        $date = gmdate('Y-m-d', $timestamp);
        $payloadJson = json_encode($payload, JSON_UNESCAPED_UNICODE);
        $hashedRequestPayload = hash('SHA256', $payloadJson);

        $canonicalHeaders = "content-type:application/json\nhost:{$this->endpoint}\n";
        $signedHeaders = 'content-type;host';
        $canonicalRequest = "POST\n/\n\n{$canonicalHeaders}\n{$signedHeaders}\n{$hashedRequestPayload}";

        $credentialScope = $date . '/' . $this->service . '/tc3_request';
        $stringToSign = 'TC3-HMAC-SHA256' . "\n" . $timestamp . "\n" . $credentialScope . "\n" . hash('SHA256', $canonicalRequest);

        $secretDate = hash_hmac('SHA256', $date, 'TC3' . $this->secretKey, true);
        $secretService = hash_hmac('SHA256', $this->service, $secretDate, true);
        $secretSigning = hash_hmac('SHA256', 'tc3_request', $secretService, true);
        $signature = hash_hmac('SHA256', $stringToSign, $secretSigning);

        $authorization = sprintf(
            'TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s',
            $this->secretId,
            $credentialScope,
            $signedHeaders,
            $signature
        );

        $headers = [
            'Authorization: ' . $authorization,
            'Content-Type: application/json',
            'Host: ' . $this->endpoint,
            'X-TC-Action: ' . $action,
            'X-TC-Version: ' . $this->version,
            'X-TC-Timestamp: ' . $timestamp,
            'X-TC-Region: ' . $this->region,
        ];

        $ch = curl_init('https://' . $this->endpoint);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payloadJson);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $body = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            return ['success' => false, 'errors' => ['curl_error' => $error], 'http_code' => $httpCode];
        }
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            return ['success' => false, 'errors' => ['decode_error' => 'Invalid JSON'], 'http_code' => $httpCode];
        }

        if (!empty($decoded['Response']['Error'])) {
            $err = $decoded['Response']['Error'];
            $code = $err['Code'] ?? 'UnknownError';
            $message = $err['Message'] ?? 'Request failed';
            return ['success' => false, 'errors' => [$code . ': ' . $message], 'http_code' => $httpCode];
        }
        $decoded['success'] = true;
        $decoded['http_code'] = $httpCode;
        return $decoded;
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
        if (!is_array($errors)) {
            return false;
        }
        if (isset($errors['curl_error']) || isset($errors['decode_error'])) {
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

    private function retryDelayMicros(int $attempt): int
    {
        $delayMs = self::RETRY_BASE_DELAY_MS * max(1, $attempt);
        return min(1500, $delayMs) * 1000;
    }

    private function normalizeTtl($ttl): int
    {
        $value = intval($ttl);
        if ($value <= 0) {
            $value = 600;
        }
        return max(60, $value);
    }

    private function normalizeLine(?string $line = null): string
    {
        $line = trim((string) $line);
        if ($line === '' || strtolower($line) === 'default') {
            return '默认';
        }
        return $line;
    }

    private function splitSubDomain(string $name, string $domain): string
    {
        $name = strtolower(rtrim($name, '.'));
        $domain = strtolower(rtrim($domain, '.'));
        if ($name === '' || $name === $domain) {
            return '@';
        }
        if (substr($name, -strlen($domain)) === $domain) {
            $candidate = rtrim(substr($name, 0, -strlen($domain)), '.');
            return $candidate === '' ? '@' : $candidate;
        }
        return $name;
    }

    private function mapRecord(array $record, string $domain): array
    {
        $name = $record['Name'] ?? '';
        $full = $name;
        $domainLower = strtolower(rtrim($domain, '.'));
        $nameLower = strtolower(rtrim($name, '.'));
        if ($nameLower === '' || $nameLower === '@') {
            $full = $domainLower;
        } elseif (!preg_match('/\.' . preg_quote($domainLower, '/') . '$/', $nameLower)) {
            $full = $nameLower . '.' . $domainLower;
        }
        $recordId = $record['RecordId'] ?? null;
        return [
            'id' => $recordId !== null ? intval($recordId) : null,
            'type' => strtoupper($record['Type'] ?? ''),
            'name' => $full,
            'content' => $record['Value'] ?? '',
            'ttl' => intval($record['TTL'] ?? 600),
            'proxied' => false,
        ];
    }

    public function validateCredentials(): bool
    {
        $res = $this->tc3Request('DescribeDomainList', ['Limit' => 1, 'Offset' => 0]);
        return $res['success'] ?? false;
    }

    public function getZoneId($domain)
    {
        $res = $this->tc3Request('DescribeDomain', ['Domain' => $domain]);
        if ($res['success'] ?? false) {
            return $res['Response']['DomainInfo']['Domain'] ?? $domain;
        }
        return false;
    }

    public function checkDomainExists($zone_id, $domain_name)
    {
        $rr = $this->splitSubDomain($domain_name, $zone_id);
        $payload = [
            'Domain' => $zone_id,
            'Limit' => 1,
            'Offset' => 0,
            'Subdomain' => $rr === '@' ? '' : $rr,
        ];
        $res = $this->tc3Request('DescribeRecordList', $payload);
        if (!($res['success'] ?? false)) {
            return false;
        }
        $records = $res['Response']['RecordList'] ?? [];
        return !empty($records);
    }

    public function getDnsRecords($zone_id, $name = null, $params = [])
    {
        $payload = [
            'Domain' => $zone_id,
            'Limit' => min(100, max(20, intval($params['per_page'] ?? 100))),
            'Offset' => 0,
        ];
        if ($name) {
            $rr = $this->splitSubDomain($name, $zone_id);
            if ($rr !== '@') {
                $payload['Subdomain'] = $rr;
            }
        }
        if (!empty($params['type'])) {
            $payload['RecordType'] = strtoupper($params['type']);
        }
        $res = $this->tc3Request('DescribeRecordList', $payload);
        if (!($res['success'] ?? false)) {
            return $res;
        }
        $records = [];
        foreach (($res['Response']['RecordList'] ?? []) as $record) {
            $records[] = $this->mapRecord($record, $zone_id);
        }
        return ['success' => true, 'result' => $records];
    }

    public function getDomainRecords($zone_id, $domain_name)
    {
        $records = $this->getDnsRecords($zone_id, $domain_name);
        return $records['result'] ?? [];
    }

    public function createDnsRecord($zone_id, $name, $type, $content, $ttl = 600, $proxied = true, $line = null)
    {
        $payload = [
            'Domain' => $zone_id,
            'SubDomain' => $this->splitSubDomain($name, $zone_id),
            'RecordType' => strtoupper($type),
            'RecordLine' => $this->normalizeLine($line),
            'Value' => $content,
            'TTL' => $this->normalizeTtl($ttl),
        ];
        $res = $this->tc3Request('CreateRecord', $payload);
        if (!($res['success'] ?? false)) {
            return $res;
        }
        $recordId = $res['Response']['RecordId'] ?? null;
        return ['success' => true, 'result' => ['id' => $recordId !== null ? intval($recordId) : null, 'name' => $name, 'type' => strtoupper($type), 'content' => $content, 'ttl' => $this->normalizeTtl($ttl), 'proxied' => false]];
    }

    public function createCNAMERecord($zone_id, $name, $target, $ttl = 600, $proxied = false)
    {
        return $this->createDnsRecord($zone_id, $name, 'CNAME', $target, $ttl, $proxied);
    }

    public function createMXRecord($zone_id, $name, $mail_server, $priority = 10, $ttl = 600)
    {
        $payload = [
            'Domain' => $zone_id,
            'SubDomain' => $this->splitSubDomain($name, $zone_id),
            'RecordType' => 'MX',
            'RecordLine' => $this->normalizeLine(),
            'Value' => $mail_server,
            'TTL' => $this->normalizeTtl($ttl),
            'MX' => intval($priority),
        ];
        $res = $this->tc3Request('CreateRecord', $payload);
        if (!($res['success'] ?? false)) {
            return $res;
        }
        $recordId = $res['Response']['RecordId'] ?? null;
        return ['success' => true, 'result' => ['id' => $recordId !== null ? intval($recordId) : null]];
    }

    public function createSRVRecord($zone_id, $name, $target, $port, $priority = 0, $weight = 0, $ttl = 600)
    {
        $value = intval($priority) . ' ' . intval($weight) . ' ' . intval($port) . ' ' . $target;
        return $this->createDnsRecord($zone_id, $name, 'SRV', $value, $ttl, false);
    }

    public function createCAARecord($zone_id, $name, $flags, $tag, $value, $ttl = 600)
    {
        $escapedValue = str_replace('"', '\\"', $value);
        $content = intval($flags) . ' ' . trim($tag) . ' "' . $escapedValue . '"';
        return $this->createDnsRecord($zone_id, $name, 'CAA', $content, $ttl, false);
    }

    public function createTXTRecord($zone_id, $name, $content, $ttl = 600)
    {
        return $this->createDnsRecord($zone_id, $name, 'TXT', $content, $ttl, false);
    }

    public function createSubdomain($zone_id, $subdomain, $ip = '192.0.2.1', $proxied = true, $type = 'A')
    {
        return $this->createDnsRecord($zone_id, $subdomain, $type, $ip, 600, $proxied);
    }

    public function createThirdLevelDomain($zone_id, $third_level_name, $parent_subdomain, $ip = '192.0.2.1', $proxied = true)
    {
        $full = $third_level_name . '.' . $parent_subdomain;
        return $this->createSubdomain($zone_id, $full, $ip, $proxied);
    }

    public function updateDnsRecord($zone_id, $record_id, $data)
    {
        $payload = [
            'Domain' => $zone_id,
            'RecordId' => intval($record_id),
            'SubDomain' => $this->splitSubDomain($data['name'] ?? $zone_id, $zone_id),
            'RecordType' => strtoupper($data['type'] ?? 'A'),
            'RecordLine' => $this->normalizeLine($data['line'] ?? null),
            'Value' => $data['content'] ?? '',
            'TTL' => $this->normalizeTtl($data['ttl'] ?? 600),
        ];
        if (strtoupper($payload['RecordType']) === 'MX' && isset($data['priority'])) {
            $payload['MX'] = intval($data['priority']);
        }
        $res = $this->tc3Request('ModifyRecord', $payload);
        if (!($res['success'] ?? false)) {
            return $res;
        }
        return ['success' => true, 'result' => ['id' => intval($record_id)]];
    }

    public function updateSubdomain($zone_id, $record_id, $subdomain, $ip, $proxied = true)
    {
        return $this->updateDnsRecord($zone_id, $record_id, [
            'name' => $subdomain,
            'type' => 'A',
            'content' => $ip,
            'ttl' => 600,
        ]);
    }

    public function updateDnsRecordRaw($zone_id, $record_id, $payload)
    {
        return $this->updateDnsRecord($zone_id, $record_id, $payload);
    }

    public function createDnsRecordRaw($zone_id, $payload)
    {
        $type = strtoupper($payload['type'] ?? 'A');
        $name = $payload['name'] ?? $zone_id;
        $content = $payload['content'] ?? '';
        $ttl = $payload['ttl'] ?? 600;
        $line = $payload['line'] ?? null;
        return $this->createDnsRecord($zone_id, $name, $type, $content, $ttl, false, $line);
    }

    public function deleteSubdomain($zone_id, $record_id)
    {
        $res = $this->tc3Request('DeleteRecord', [
            'Domain' => $zone_id,
            'RecordId' => intval($record_id),
        ]);
        if (!($res['success'] ?? false)) {
            return $res;
        }
        return ['success' => true];
    }

    public function deleteDomainRecords($zone_id, $domain_name)
    {
        $records = $this->getDnsRecords($zone_id, $domain_name);
        if (!($records['success'] ?? false)) {
            return $records;
        }
        $deleted = 0;
        foreach (($records['result'] ?? []) as $record) {
            $res = $this->deleteSubdomain($zone_id, $record['id']);
            if ($res['success'] ?? false) {
                $deleted++;
            }
        }
        return ['success' => true, 'deleted_count' => $deleted];
    }

    public function deleteDomainRecordsDeep($zone_id, $subdomain_root)
    {
        $records = $this->getDnsRecords($zone_id, null);
        if (!($records['success'] ?? false)) {
            return $records;
        }
        $target = strtolower(rtrim($subdomain_root, '.'));
        $deleted = 0;
        foreach (($records['result'] ?? []) as $record) {
            $name = strtolower(rtrim((string) ($record['name'] ?? ''), '.'));
            if ($name === $target || ($target !== '' && substr($name, -strlen($target)) === $target)) {
                $res = $this->deleteSubdomain($zone_id, $record['id']);
                if ($res['success'] ?? false) {
                    $deleted++;
                }
            }
        }
        return ['success' => true, 'deleted_count' => $deleted];
    }

    public function getDnsRecord($zone_id, $record_id)
    {
        $res = $this->tc3Request('DescribeRecord', [
            'Domain' => $zone_id,
            'RecordId' => intval($record_id),
        ]);
        if (!($res['success'] ?? false)) {
            return $res;
        }
        $record = $res['Response']['RecordInfo'] ?? [];
        return ['success' => true, 'result' => $this->mapRecord($record, $zone_id)];
    }

    public function toggleProxy($zone_id, $record_id, $proxied)
    {
        return ['success' => true, 'result' => ['proxied' => false]];
    }

    public function batchUpdateDnsRecords($zone_id, $updates)
    {
        $results = [];
        foreach ($updates as $update) {
            if (isset($update['id'])) {
                $results[] = $this->updateDnsRecordRaw($zone_id, $update['id'], $update);
            } else {
                $results[] = $this->createDnsRecordRaw($zone_id, $update);
            }
        }
        return $results;
    }
}
