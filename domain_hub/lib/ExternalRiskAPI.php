<?php

class ExternalRiskAPI {
    private string $endpoint;
    private ?string $apiKey;

    public function __construct(string $endpoint, ?string $apiKey = null) {
        $this->endpoint = rtrim($endpoint, '/');
        $this->apiKey = $apiKey ? trim($apiKey) : null;
    }

    public function scanSubdomain(string $subdomain, array $extras = []): array {
        $body = $this->buildRequestBody($subdomain, $extras);
        $headers = $this->buildHeaders();
        $ch = $this->createCurlHandle($body, $headers);

        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            return ['success' => false, 'errors' => ['curl_error' => $error], 'http_code' => $http_code];
        }
        $decoded = json_decode($result, true);
        if (!is_array($decoded)) {
            return ['success' => false, 'errors' => ['decode_error' => 'Invalid JSON'], 'http_code' => $http_code];
        }
        return $decoded;
    }

    public function scanBatch(array $jobs, int $maxConcurrent = 5): array {
        $jobs = array_values($jobs);
        $total = count($jobs);
        if ($total === 0) {
            return [];
        }
        $maxConcurrent = max(1, min(20, $maxConcurrent));
        $headers = $this->buildHeaders();
        $results = array_fill(0, $total, null);

        $normalized = [];
        foreach ($jobs as $idx => $job) {
            $subdomain = (string)($job['subdomain'] ?? '');
            if ($subdomain === '') {
                $results[$idx] = ['success' => false, 'errors' => ['invalid_subdomain' => true]];
                continue;
            }
            $extras = is_array($job['extras'] ?? null) ? $job['extras'] : [];
            $normalized[] = [
                'index' => $idx,
                'body' => $this->buildRequestBody($subdomain, $extras),
            ];
        }

        if (empty($normalized)) {
            foreach ($results as $i => $value) {
                if ($value === null) {
                    $results[$i] = ['success' => false, 'errors' => ['no_request' => true]];
                }
            }
            return $results;
        }

        $multi = curl_multi_init();
        $handles = [];
        $cursor = 0;
        $running = null;

        while ($cursor < count($normalized) || !empty($handles)) {
            while ($cursor < count($normalized) && count($handles) < $maxConcurrent) {
                $job = $normalized[$cursor];
                $ch = $this->createCurlHandle($job['body'], $headers);
                curl_multi_add_handle($multi, $ch);
                $handles[(int)$ch] = ['handle' => $ch, 'index' => $job['index']];
                $cursor++;
            }

            do {
                $status = curl_multi_exec($multi, $running);
            } while ($status === CURLM_CALL_MULTI_PERFORM);

            while ($info = curl_multi_info_read($multi)) {
                $ch = $info['handle'];
                $key = (int)$ch;
                $meta = $handles[$key] ?? null;
                $content = curl_multi_getcontent($ch);
                $error = curl_error($ch);
                $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_multi_remove_handle($multi, $ch);
                curl_close($ch);
                unset($handles[$key]);

                if ($meta === null) {
                    continue;
                }

                if ($error) {
                    $results[$meta['index']] = ['success' => false, 'errors' => ['curl_error' => $error], 'http_code' => $http];
                } else {
                    $decoded = json_decode($content, true);
                    if (!is_array($decoded)) {
                        $decoded = ['success' => false, 'errors' => ['decode_error' => 'Invalid JSON'], 'http_code' => $http];
                    }
                    $results[$meta['index']] = $decoded;
                }
            }

            if ($running) {
                $select = curl_multi_select($multi, 1.0);
                if ($select === -1) {
                    usleep(100000);
                }
            }
        }

        curl_multi_close($multi);

        foreach ($results as $i => $value) {
            if ($value === null) {
                $results[$i] = ['success' => false, 'errors' => ['no_response' => true]];
            }
        }
        return $results;
    }

    private function buildHeaders(): array {
        $headers = ['Content-Type: application/json'];
        if ($this->apiKey && $this->apiKey !== '') {
            $headers[] = 'Authorization: Bearer ' . $this->apiKey;
        }
        return $headers;
    }

    private function buildRequestBody(string $subdomain, array $extras = []): string {
        $payload = array_merge(['subdomain' => $subdomain], $extras);
        return json_encode($payload, JSON_UNESCAPED_UNICODE);
    }

    private function createCurlHandle(string $body, array $headers)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->endpoint . '/scan');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        return $ch;
    }
}
