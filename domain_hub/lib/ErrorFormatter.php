<?php

if (!function_exists('cfmod_format_provider_error')) {
    /**
     * 将云解析/供应商返回的错误信息转换为对用户友好的描述，避免暴露底层厂商细节。
     */
    function cfmod_format_provider_error($error, string $fallback = '云解析服务暂时不可用，请稍后再试。'): string
    {
        if ($error instanceof \Throwable) {
            $error = $error->getMessage();
        }

        if (is_array($error)) {
            $error = implode('; ', array_map(function ($item) {
                if ($item instanceof \Throwable) {
                    return $item->getMessage();
                }
                if (is_scalar($item)) {
                    return (string) $item;
                }
                if (is_object($item) && method_exists($item, '__toString')) {
                    return (string) $item;
                }
                return json_encode($item, JSON_UNESCAPED_UNICODE);
            }, $error));
        } elseif (is_object($error) && !method_exists($error, '__toString')) {
            $error = json_encode($error, JSON_UNESCAPED_UNICODE);
        } elseif (is_object($error)) {
            $error = (string) $error;
        }

        $fallback = trim($fallback) !== '' ? $fallback : '云解析服务暂时不可用，请稍后再试。';
        $clean = trim((string) $error);
        if ($clean === '') {
            return $fallback;
        }

        // 去除错误码、厂商名称等信息
        $clean = preg_replace('/^\[[^\]]+\]\s*/', '', $clean);
        $clean = preg_replace('/Ali(?:yun|dns)/i', '云解析服务', $clean);
        $clean = preg_replace('/Cloudflare/i', '云解析服务', $clean);
        $clean = preg_replace('/\s+/', ' ', $clean);

        $lower = function_exists('mb_strtolower') ? mb_strtolower($clean, 'UTF-8') : strtolower($clean);
        $rules = [
            [
                'keywords' => ['conflict', 'duplicate', 'already exist', 'exist'],
                'message' => '记录冲突，请检查是否存在同名记录或删除旧记录后再试。'
            ],
            [
                'keywords' => ['format', 'invalid', 'syntax', 'illegal', '参数'],
                'message' => '记录内容或格式无效，请核对主机记录、记录值以及 TTL/优先级。'
            ],
            [
                'keywords' => ['denied', 'permission', 'auth', 'forbidden'],
                'message' => '权限不足，请检查 AccessKey 配置或域名授权。'
            ],
            [
                'keywords' => ['quota', 'limit', 'too many', 'exceed', 'over limit'],
                'message' => '已达到云解析的数量或频率限制，请稍后再试或联系管理员提升额度。'
            ],
            [
                'keywords' => ['not found', 'not exist', 'no such', 'zone not'],
                'message' => '目标域名不存在或未授权，请确认根域配置后重试。'
            ],
            [
                'keywords' => ['timeout', 'timed out', 'busy', 'unavailable', 'temporarily unable'],
                'message' => '云解析服务响应超时或繁忙，请稍后再试。'
            ],
        ];

        foreach ($rules as $rule) {
            foreach ($rule['keywords'] as $keyword) {
                if ($keyword !== '' && strpos($lower, $keyword) !== false) {
                    return $rule['message'];
                }
            }
        }

        return $clean !== '' ? $clean : $fallback;
    }
}

