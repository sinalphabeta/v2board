<?php

namespace App\Console\Commands;

use GuzzleHttp\Client;
use Illuminate\Console\Command;
use ip2region\xdb\Util;

class RiskGeoipUpdate extends Command
{
    protected $signature = 'risk:geoip-update';
    protected $description = 'Download and validate the local risk IP databases';

    private const DATABASES = [
        'v4' => ['version' => 4, 'minimum_size' => 10 * 1024 * 1024],
        'v6' => ['version' => 6, 'minimum_size' => 30 * 1024 * 1024],
    ];

    public function handle()
    {
        $client = new Client(['connect_timeout' => 10, 'timeout' => 300, 'allow_redirects' => true]);
        $failed = false;
        foreach (self::DATABASES as $name => $database) {
            try {
                $this->updateDatabase($client, $name, $database);
                $this->info("Updated GeoIP {$name} database.");
            } catch (\Throwable $e) {
                $failed = true;
                $this->error("Failed to update GeoIP {$name} database: {$e->getMessage()}");
            }
        }
        return $failed ? 1 : 0;
    }

    private function updateDatabase(Client $client, string $name, array $database): void
    {
        $target = (string)config("risk.ip_database_{$name}", '');
        $url = (string)config("risk.ip_database_urls.{$name}", '');
        if ($target === '' || $url === '') throw new \RuntimeException('Database path or URL is not configured.');

        $directory = dirname($target);
        if (!is_dir($directory) && !mkdir($directory, 0755, true) && !is_dir($directory)) {
            throw new \RuntimeException("Unable to create {$directory}.");
        }
        $temporary = $target . '.tmp.' . getmypid() . '.' . bin2hex(random_bytes(4));
        try {
            $client->request('GET', $url, ['sink' => $temporary]);
            $this->validateDatabase($temporary, (int)$database['version'], (int)$database['minimum_size']);
            if (!rename($temporary, $target)) throw new \RuntimeException("Unable to replace {$target}.");
            chmod($target, 0644);
        } finally {
            if (is_file($temporary)) unlink($temporary);
        }
    }

    private function validateDatabase(string $path, int $expectedVersion, int $minimumSize): void
    {
        clearstatcache(true, $path);
        if (!is_file($path) || !is_readable($path)) throw new \RuntimeException('Downloaded database is not readable.');
        if (filesize($path) < $minimumSize) throw new \RuntimeException('Downloaded database is unexpectedly small.');

        $error = Util::verifyFromFile($path);
        if ($error !== null) throw new \RuntimeException("Invalid XDB structure: {$error}");
        $header = Util::loadHeaderFromFile($path);
        if (!$header) throw new \RuntimeException('Unable to read the XDB header.');
        $version = Util::versionFromHeader($header);
        if ((int)$version->id !== $expectedVersion) {
            throw new \RuntimeException("Expected IPv{$expectedVersion}, got {$version->name}.");
        }
    }
}
