<?php
/**
 * TTL normalization helpers shared across client UI, API, and background jobs.
 */
if (!function_exists('cfmod_normalize_ttl')) {
    function cfmod_normalize_ttl($ttl): int {
        $value = intval($ttl);
        if ($value <= 0) {
            $value = 600;
        }
        if ($value < 600) {
            $value = 600;
        }
        return $value;
    }
}
