<?php

declare(strict_types=1);

if (!function_exists('cfmod_normalize_language_code')) {
    function cfmod_normalize_language_code(?string $language): string
    {
        static $map = [
            // Chinese variants
            'chinese_cn' => 'chinese',
            'chinese' => 'chinese',
            'cn' => 'chinese',
            'zh-cn' => 'chinese',
            'zh_cn' => 'chinese',
            'zh' => 'chinese',
            'zh-hans' => 'chinese',
            'zh-hans-cn' => 'chinese',
            // English variants
            'english' => 'english',
            'english_us' => 'english',
            'english_uk' => 'english',
            'en' => 'english',
            'en-us' => 'english',
            'en_us' => 'english',
            'en-gb' => 'english',
            'en_gb' => 'english',
        ];

        $value = is_string($language) ? strtolower($language) : '';
        return $map[$value] ?? ($value !== '' ? $value : 'english');
    }
}

if (!function_exists('cfmod_resolve_language_preference')) {
    function cfmod_resolve_language_preference(?string $language = null): array
    {
        static $cache = [];

        $cacheKey = $language ?? '__auto__';
        if (isset($cache[$cacheKey])) {
            return $cache[$cacheKey];
        }

        if ($language === null || $language === '') {
            $language = $_SESSION['Language'] ?? ($_SESSION['language'] ?? ($_COOKIE['WHMCSLanguage'] ?? ''));
        }

        $normalized = cfmod_normalize_language_code($language);
        $htmlMap = [
            'chinese' => 'zh-CN',
            'zh-cn' => 'zh-CN',
            'zh_cn' => 'zh-CN',
            'zh-hans' => 'zh-CN',
            'zh-hans-cn' => 'zh-CN',
        ];
        $html = $htmlMap[$normalized] ?? 'en';

        return $cache[$cacheKey] = [
            'raw' => is_string($language) ? strtolower($language) : '',
            'normalized' => $normalized,
            'html' => $html,
        ];
    }
}

if (!function_exists('cfmod_get_current_language_code')) {
    function cfmod_get_current_language_code(): string
    {
        $resolved = cfmod_resolve_language_preference();
        return $resolved['normalized'];
    }
}

if (!function_exists('cfmod_get_html_lang_code')) {
    function cfmod_get_html_lang_code(): string
    {
        $resolved = cfmod_resolve_language_preference();
        return $resolved['html'];
    }
}

if (!function_exists('cfmod_load_language')) {
    function cfmod_load_language(?string $language = null): void
    {
        static $loaded = [];

        global $_LANG;
        if (!is_array($_LANG)) {
            $_LANG = [];
        }

        $resolved = cfmod_resolve_language_preference($language);
        $normalized = $resolved['normalized'];

        $candidates = [];
        $fallback = 'english';
        if ($normalized !== $fallback) {
            $candidates[] = $fallback;
            $candidates[] = $normalized;
        } else {
            $candidates[] = $fallback;
        }
        $candidates = array_values(array_unique(array_filter($candidates, static function ($code) {
            return is_string($code) && $code !== '';
        })));

        $langDir = dirname(__DIR__, 2) . '/lang/';

        foreach ($candidates as $code) {
            if (isset($loaded[$code])) {
                continue;
            }
            $file = $langDir . $code . '.php';
            if (is_file($file)) {
                include $file;
                $loaded[$code] = true;
            }
        }
    }
}

if (!function_exists('cfmod_client_trans')) {
    function cfmod_client_trans(string $key, string $default = ''): string
    {
        if (function_exists('cfmod_load_language')) {
            cfmod_load_language();
        }

        global $_LANG;

        if (isset($_LANG[$key]) && is_string($_LANG[$key])) {
            return (string) $_LANG[$key];
        }

        if (class_exists('\Lang') && method_exists('\Lang', 'trans')) {
            $translated = \Lang::trans($key);
            if (is_string($translated) && $translated !== $key) {
                return $translated;
            }
        }

        return $default !== '' ? $default : $key;
    }
}

if (!function_exists('cfmod_trans')) {
    function cfmod_trans(string $key, string $default = ''): string
    {
        return cfmod_client_trans($key, $default);
    }
}
