<?php

require_once __DIR__ . '/vendor/autoload.php';

use Adapterman\Adapterman;
use Adapterman\Http;
use Workerman\Connection\TcpConnection;
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

/**
 * Adapterman's HTTP protocol, except that a request it cannot decode is answered with 400. Adapterman parses the body in
 * the protocol, before onMessage (and Laravel) run: a body sent as JSON that is not a JSON object or array (bad JSON, an
 * empty body, a scalar) throws there, and Workerman then stops the whole worker, failing the requests it holds.
 */
final class WebmanHttp
{
    private static $loggedAt = 0;

    public static function input(string $buffer, TcpConnection $connection): int
    {
        return Http::input($buffer, $connection);
    }

    public static function decode(string $buffer, TcpConnection $connection): void
    {
        try {
            Http::decode($buffer, $connection);
        } catch (\Throwable $e) {
            // At most one line a minute per worker, as anyone can send these
            if (time() - self::$loggedAt >= 60) {
                self::$loggedAt = time();
                Worker::log('Bad request body (answered 400): ' . get_class($e) . ': ' . $e->getMessage());
            }
            $body = '{"message":"Invalid request body"}';
            $connection->close("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " . strlen($body)
                . "\r\nConnection: close\r\n\r\n" . $body, true);
        }
    }

    public static function encode(string $content, TcpConnection $connection): string
    {
        return Http::encode($content, $connection);
    }
}

$ncpu = substr_count((string)@file_get_contents('/proc/cpuinfo'), "\nprocessor")+1;

// tcp:// with the protocol set by hand: with http://, Workerman would put its own HTTP protocol back
$http_worker                = new Worker('tcp://127.0.0.1:6600');
$http_worker->protocol      = WebmanHttp::class;
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
    // WebmanHttp answered a bad request and closed the connection (Workerman before 5.2.3 still calls onMessage then)
    if ($connection->getStatus() !== TcpConnection::STATUS_ESTABLISHED) {
        return;
    }
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
