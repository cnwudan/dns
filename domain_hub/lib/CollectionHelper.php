<?php

if (!function_exists('cfmod_iterable_to_array')) {
    /**
     * Normalize various iterable/query builder results to arrays.
     */
    function cfmod_iterable_to_array($value): array
    {
        if (is_array($value)) {
            return $value;
        }

        if ($value instanceof \Illuminate\Support\Collection) {
            return $value->all();
        }

        if ($value instanceof \Traversable) {
            return iterator_to_array($value);
        }

        if (is_object($value) && method_exists($value, 'toArray')) {
            try {
                $converted = $value->toArray();
                if (is_array($converted)) {
                    return $converted;
                }
            } catch (\Throwable $ignored) {
            }
        }

        if ($value === null) {
            return [];
        }

        return (array) $value;
    }
}
