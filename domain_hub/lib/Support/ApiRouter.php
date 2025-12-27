<?php

declare(strict_types=1);

class CfApiRouter
{
    public static function isApiRequest(): bool
    {
        if (isset($_GET['api']) || isset($_POST['api'])) {
            return true;
        }
        if (isset($_REQUEST['api_key']) || isset($_REQUEST['api_secret'])) {
            return true;
        }
        if (!empty($_SERVER['HTTP_X_API_KEY']) || !empty($_SERVER['HTTP_X_API_SECRET'])) {
            return true;
        }
        if (isset($_REQUEST['endpoint']) && cf_is_module_request()) {
            return true;
        }
        return false;
    }

    public static function dispatch(): void
    {
        require_once __DIR__ . '/../CloudflareAPI.php';
        require_once __DIR__ . '/../../api_handler.php';
        handleApiRequest();
        exit;
    }
}
