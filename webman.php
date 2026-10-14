<?php

require_once __DIR__ . '/vendor/autoload.php';

use Adapterman\Adapterman;
use Workerman\Timer;
use Workerman\Worker;
use Illuminate\Support\Facades\Cache;

putenv('APP_RUNNING_IN_CONSOLE=false');
define('MAX_REQUEST', 6600);
define('isWEBMAN', true);
// Rewritten when the admin saves the system config (config/v2board.php, then config:cache)
define('WEBMAN_CONFIG_FILES', [__DIR__ . '/config/v2board.php', __DIR__ . '/bootstrap/cache/config.php']);

Adapterman::init();

function webman_config_fingerprint(): string
{
    $parts = [];
    foreach (WEBMAN_CONFIG_FILES as $file) {
        clearstatcache(true, $file);
        $parts[] = is_file($file) ? (string)md5_file($file) : '-';
    }
    return implode(',', $parts);
}

$ncpu = substr_count((string)@file_get_contents('/proc/cpuinfo'), "\nprocessor")+1;

$http_worker                = new Worker('http://127.0.0.1:6600');
$http_worker->count         = $ncpu * 2;
$http_worker->name          = 'AdapterMan';

$http_worker->onWorkerStart = static function () {
    //init();
    $config = webman_config_fingerprint();
    require __DIR__.'/start.php';
    // Workers keep the config they booted with. When the config files change, exit and let the master fork a fresh
    // worker (as with MAX_REQUEST). The SIGTERM sent by ConfigController@save is not enough: it fails when php-fpm and
    // webman run as different users (e.g. www and root). cli-php.ini turns off opcache.validate_timestamps, so drop
    // the cached scripts first or the new worker would load the old config again.
    Timer::add(1, static function () use ($config) {
        if (webman_config_fingerprint() === $config) {
            return;
        }
        if (function_exists('opcache_invalidate')) {
            foreach (WEBMAN_CONFIG_FILES as $file) {
                opcache_invalidate($file, true);
            }
        }
        Worker::stopAll();
    });
};

$http_worker->onMessage = static function ($connection, $request) {
    static $request_count = 0;
    static $pid;
    if ($request_count == 1) {
        $pid = posix_getppid();
        Cache::forget("WEBMANPID");
        Cache::forever("WEBMANPID", $pid);
    }
    $connection->send(run());
    if (++$request_count > MAX_REQUEST) {
        Worker::stopAll();
    }
};

Worker::runAll();
