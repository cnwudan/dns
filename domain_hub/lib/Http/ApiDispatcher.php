<?php

declare(strict_types=1);

class CfApiDispatcher
{
    private static ?self $instance = null;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public function shouldDispatch(): bool
    {
        return function_exists('cf_is_api_request') && cf_is_api_request();
    }

    public function dispatchIfNeeded(): void
    {
        if ($this->shouldDispatch()) {
            $this->dispatch();
        }
    }

    public function dispatch(): void
    {
        if (function_exists('cf_dispatch_api_request')) {
            cf_dispatch_api_request();
        }
    }
}
