<?php

namespace App\Console\Commands;

use GuzzleHttp\Client;
use Illuminate\Console\Command;
use MaxMind\Db\Reader as MaxMindReader;

class RiskGeoipUpdate extends Command
{
    protected $signature = 'risk:geoip-update';
    protected $description = 'Download and validate the local risk GeoIP databases';

    private const QQWRY_SAMPLE_IP = '183.62.57.1';
    private const DBIP_SAMPLE_IP = '23.177.40.137';

    public function handle()
    {
        $directory = (string)config('risk.geoip_directory', '');
        if ($directory === '') {
            $this->error('GeoIP directory is not configured.');
            return 1;
        }
        if (!is_dir($directory) && !mkdir($directory, 0755, true) && !is_dir($directory)) {
            $this->error("Unable to create {$directory}.");
            return 1;
        }

        $lock = fopen($directory . '/update.lock', 'c');
        if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
            if (is_resource($lock)) fclose($lock);
            $this->warn('Another GeoIP update is already running.');
            return 0;
        }

        $temporaryDirectory = $directory . '/.update-' . getmypid() . '-' . bin2hex(random_bytes(4));
        try {
            if (!mkdir($temporaryDirectory, 0755, true)) {
                throw new \RuntimeException("Unable to create {$temporaryDirectory}.");
            }
            $client = new Client([
                'connect_timeout' => 15,
                'timeout' => 600,
                'allow_redirects' => true,
                'headers' => ['User-Agent' => 'V2Board-risk-geoip-updater'],
            ]);
            $release = $this->resolveRelease($client);
            if ($this->isCurrent($release)) {
                $this->info('GeoIP databases are already up to date.');
                return 0;
            }

            $staged = $this->downloadAndValidate($client, $release, $temporaryDirectory);
            $manifest = $this->buildManifest($release, $staged);
            $manifestPath = $temporaryDirectory . '/manifest.json';
            if (file_put_contents($manifestPath, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n") === false) {
                throw new \RuntimeException('Unable to create the GeoIP manifest.');
            }
            $staged['manifest'] = $manifestPath;
            $this->publish($staged);

            $this->info("Updated GeoIP databases: qqwry {$release['qqwry']['version']}, DB-IP {$release['dbip_version']}.");
            return 0;
        } catch (\Throwable $e) {
            $this->error('GeoIP update failed; existing databases were kept: ' . $e->getMessage());
            return 1;
        } finally {
            $this->removeDirectory($temporaryDirectory);
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function resolveRelease(Client $client): array
    {
        $metadataUrl = (string)config('risk.geoip_npm_metadata_url', '');
        $response = $client->request('GET', $metadataUrl);
        $metadata = json_decode((string)$response->getBody(), true);
        $version = $metadata['version'] ?? '';
        $tarball = $metadata['dist']['tarball'] ?? '';
        $integrity = $metadata['dist']['integrity'] ?? '';
        if (!is_string($version) || $version === '' || !filter_var($tarball, FILTER_VALIDATE_URL)) {
            throw new \RuntimeException('The NPM qqwry.ipdb release metadata is invalid.');
        }
        if (!is_string($integrity) || strpos($integrity, 'sha512-') !== 0) {
            throw new \RuntimeException('The NPM qqwry.ipdb release has no SHA-512 integrity value.');
        }

        $month = date('Y-m');
        $urlTemplate = (string)config('risk.geoip_dbip_url', '');
        if (substr_count($urlTemplate, '%s') !== 2) {
            throw new \RuntimeException('The DB-IP URL template is invalid.');
        }
        return [
            'qqwry' => ['version' => $version, 'url' => $tarball, 'integrity' => $integrity],
            'dbip_version' => $month,
            'city' => ['version' => $month, 'url' => sprintf($urlTemplate, 'city', $month)],
            'asn' => ['version' => $month, 'url' => sprintf($urlTemplate, 'asn', $month)],
        ];
    }

    private function isCurrent(array $release): bool
    {
        $manifestPath = (string)config('risk.geoip_manifest', '');
        if (!is_file($manifestPath)) return false;
        $manifest = json_decode((string)file_get_contents($manifestPath), true);
        if (!is_array($manifest)) return false;
        if (($manifest['databases']['qqwry']['version'] ?? null) !== $release['qqwry']['version']) return false;
        if (($manifest['databases']['city']['version'] ?? null) !== $release['dbip_version']) return false;
        if (($manifest['databases']['asn']['version'] ?? null) !== $release['dbip_version']) return false;

        foreach (['qqwry', 'city', 'asn'] as $name) {
            $path = $this->targetPath($name);
            $checksum = $manifest['databases'][$name]['sha256'] ?? '';
            if (!is_file($path) || !is_string($checksum) || !hash_equals($checksum, hash_file('sha256', $path))) {
                return false;
            }
        }
        return true;
    }

    private function downloadAndValidate(Client $client, array $release, string $directory): array
    {
        $archive = $directory . '/qqwry.tgz';
        $qqwry = $directory . '/qqwry.ipdb';
        $this->download($client, $release['qqwry']['url'], $archive);
        $expectedIntegrity = substr($release['qqwry']['integrity'], 7);
        $actualIntegrity = base64_encode(hash_file('sha512', $archive, true));
        if (!hash_equals($expectedIntegrity, $actualIntegrity)) {
            throw new \RuntimeException('The qqwry.ipdb NPM archive failed its SHA-512 integrity check.');
        }
        $this->extractTarGzFile($archive, 'package/qqwry.ipdb', $qqwry);
        $this->validateQqwry($qqwry);

        $staged = ['qqwry' => $qqwry];
        foreach (['city', 'asn'] as $name) {
            $compressed = $directory . "/dbip-{$name}.mmdb.gz";
            $database = $directory . "/dbip-{$name}-lite.mmdb";
            $this->download($client, $release[$name]['url'], $compressed);
            $this->decompressGzip($compressed, $database);
            $this->validateMmdb($database, $name);
            $staged[$name] = $database;
        }
        return $staged;
    }

    private function download(Client $client, string $url, string $target): void
    {
        $client->request('GET', $url, ['sink' => $target]);
        clearstatcache(true, $target);
        if (!is_file($target) || filesize($target) === 0) {
            throw new \RuntimeException("Downloaded an empty file from {$url}.");
        }
    }

    private function extractTarGzFile(string $archive, string $wantedName, string $target): void
    {
        $input = gzopen($archive, 'rb');
        if ($input === false) throw new \RuntimeException('Unable to open the qqwry.ipdb archive.');
        try {
            while (($header = $this->gzReadExact($input, 512)) !== null) {
                if ($header === str_repeat("\0", 512)) break;
                $name = rtrim(substr($header, 0, 100), "\0");
                $sizeText = trim(substr($header, 124, 12), " \0");
                $size = $sizeText === '' ? 0 : octdec($sizeText);
                if ($name === $wantedName) {
                    $output = fopen($target, 'wb');
                    if ($output === false) throw new \RuntimeException('Unable to create the staged qqwry.ipdb file.');
                    try {
                        $this->copyGzipBytes($input, $output, $size);
                    } finally {
                        fclose($output);
                    }
                    return;
                }
                $this->discardGzipBytes($input, $size);
                $padding = (512 - ($size % 512)) % 512;
                if ($padding > 0) $this->discardGzipBytes($input, $padding);
            }
        } finally {
            gzclose($input);
        }
        throw new \RuntimeException('The NPM archive does not contain package/qqwry.ipdb.');
    }

    private function decompressGzip(string $source, string $target): void
    {
        $input = gzopen($source, 'rb');
        $output = fopen($target, 'wb');
        if ($input === false || $output === false) {
            if (is_resource($input)) gzclose($input);
            if (is_resource($output)) fclose($output);
            throw new \RuntimeException('Unable to open a DB-IP compressed file.');
        }
        try {
            while (!gzeof($input)) {
                $chunk = gzread($input, 1024 * 1024);
                if ($chunk === false || ($chunk !== '' && fwrite($output, $chunk) !== strlen($chunk))) {
                    throw new \RuntimeException('Unable to decompress a DB-IP database.');
                }
            }
        } finally {
            gzclose($input);
            fclose($output);
        }
    }

    private function validateQqwry(string $path): void
    {
        if (filesize($path) < 5 * 1024 * 1024) throw new \RuntimeException('qqwry.ipdb is unexpectedly small.');
        $metadata = $this->readIpdbMetadata($path);
        $database = new \ipip\db\City($path);
        try {
            $fields = $metadata['fields'] ?? [];
            foreach (['country_name', 'region_name', 'city_name', 'district_name', 'owner_domain', 'isp_domain'] as $field) {
                if (!in_array($field, $fields, true)) throw new \RuntimeException("qqwry.ipdb is missing {$field}.");
            }
            $sample = $database->findMap(self::QQWRY_SAMPLE_IP, 'CN');
            if (!is_array($sample) || $this->clean($sample['country_name'] ?? '') === '') {
                throw new \RuntimeException('qqwry.ipdb failed its sample lookup.');
            }
        } finally {
            $database->reader->close();
        }
    }

    private function readIpdbMetadata(string $path): array
    {
        $stream = fopen($path, 'rb');
        if ($stream === false) throw new \RuntimeException('Unable to open qqwry.ipdb.');
        try {
            $lengthBytes = fread($stream, 4);
            if ($lengthBytes === false || strlen($lengthBytes) !== 4) {
                throw new \RuntimeException('qqwry.ipdb has a truncated header.');
            }
            $unpacked = unpack('Nlength', $lengthBytes);
            $metadataLength = $unpacked['length'] ?? 0;
            if ($metadataLength < 2 || $metadataLength > 1024 * 1024) {
                throw new \RuntimeException('qqwry.ipdb has an invalid metadata length.');
            }
            $metadataText = fread($stream, $metadataLength);
            if ($metadataText === false || strlen($metadataText) !== $metadataLength) {
                throw new \RuntimeException('qqwry.ipdb has truncated metadata.');
            }
            $metadata = json_decode($metadataText, true);
            $fileSize = filesize($path);
            if (!is_array($metadata) || !isset($metadata['fields'], $metadata['languages'], $metadata['total_size'])) {
                throw new \RuntimeException('qqwry.ipdb metadata is invalid.');
            }
            if ($fileSize === false || 4 + $metadataLength + (int)$metadata['total_size'] !== $fileSize) {
                throw new \RuntimeException('qqwry.ipdb declared size does not match the file.');
            }
            return $metadata;
        } finally {
            fclose($stream);
        }
    }

    private function validateMmdb(string $path, string $kind): void
    {
        $minimumSize = $kind === 'city' ? 10 * 1024 * 1024 : 1024 * 1024;
        if (filesize($path) < $minimumSize) throw new \RuntimeException("DB-IP {$kind} database is unexpectedly small.");
        $reader = new MaxMindReader($path);
        try {
            $databaseType = (string)$reader->metadata()->databaseType;
            if (stripos($databaseType, $kind) === false) {
                throw new \RuntimeException("Unexpected DB-IP {$kind} database type: {$databaseType}.");
            }
            $sample = $reader->get(self::DBIP_SAMPLE_IP);
            if (!is_array($sample)) throw new \RuntimeException("DB-IP {$kind} database failed its sample lookup.");
            $required = $kind === 'city' ? ($sample['country']['iso_code'] ?? '') : ($sample['autonomous_system_number'] ?? '');
            if ($required === '') throw new \RuntimeException("DB-IP {$kind} database failed its sample lookup.");
        } finally {
            $reader->close();
        }
    }

    private function buildManifest(array $release, array $staged): array
    {
        $databases = [];
        foreach (['qqwry', 'city', 'asn'] as $name) {
            $databases[$name] = [
                'version' => $name === 'qqwry' ? $release['qqwry']['version'] : $release['dbip_version'],
                'sha256' => hash_file('sha256', $staged[$name]),
                'size' => filesize($staged[$name]),
                'source' => $release[$name]['url'],
            ];
        }
        return ['updated_at' => date(DATE_ATOM), 'databases' => $databases];
    }

    private function publish(array $staged): void
    {
        $targets = [
            'qqwry' => $this->targetPath('qqwry'),
            'city' => $this->targetPath('city'),
            'asn' => $this->targetPath('asn'),
            'manifest' => (string)config('risk.geoip_manifest', ''),
        ];
        $backups = [];
        $published = [];
        try {
            foreach ($targets as $name => $target) {
                if ($target === '') throw new \RuntimeException("Target path for {$name} is not configured.");
                if (is_file($target)) {
                    $backup = $target . '.bak.' . getmypid();
                    if (!@link($target, $backup) && !copy($target, $backup)) {
                        throw new \RuntimeException("Unable to back up {$target}.");
                    }
                    $backups[$name] = $backup;
                }
                if (!rename($staged[$name], $target)) throw new \RuntimeException("Unable to publish {$target}.");
                chmod($target, 0644);
                $published[$name] = $target;
            }
        } catch (\Throwable $e) {
            foreach (array_reverse($published, true) as $name => $target) {
                if (is_file($target)) unlink($target);
            }
            foreach ($backups as $name => $backup) {
                if (is_file($backup)) {
                    if (is_file($targets[$name])) unlink($targets[$name]);
                    rename($backup, $targets[$name]);
                }
            }
            throw $e;
        }
        foreach ($backups as $backup) {
            if (is_file($backup)) unlink($backup);
        }
    }

    private function targetPath(string $name): string
    {
        return (string)config("risk.geoip_databases.{$name}", '');
    }

    private function gzReadExact($stream, int $length): ?string
    {
        $data = '';
        while (strlen($data) < $length && !gzeof($stream)) {
            $chunk = gzread($stream, $length - strlen($data));
            if ($chunk === false) throw new \RuntimeException('Unable to read the qqwry.ipdb archive.');
            $data .= $chunk;
        }
        if ($data === '') return null;
        if (strlen($data) !== $length) throw new \RuntimeException('The qqwry.ipdb archive is truncated.');
        return $data;
    }

    private function copyGzipBytes($input, $output, int $length): void
    {
        while ($length > 0) {
            $chunk = gzread($input, min(1024 * 1024, $length));
            if ($chunk === false || $chunk === '') throw new \RuntimeException('The qqwry.ipdb archive is truncated.');
            if (fwrite($output, $chunk) !== strlen($chunk)) throw new \RuntimeException('Unable to write qqwry.ipdb.');
            $length -= strlen($chunk);
        }
    }

    private function discardGzipBytes($input, int $length): void
    {
        while ($length > 0) {
            $chunk = gzread($input, min(1024 * 1024, $length));
            if ($chunk === false || $chunk === '') throw new \RuntimeException('The qqwry.ipdb archive is truncated.');
            $length -= strlen($chunk);
        }
    }

    private function removeDirectory(string $directory): void
    {
        if (!is_dir($directory)) return;
        $files = scandir($directory);
        if ($files === false) return;
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') continue;
            $path = $directory . '/' . $file;
            if (is_dir($path)) $this->removeDirectory($path);
            elseif (is_file($path)) unlink($path);
        }
        rmdir($directory);
    }

    private function clean($value): string
    {
        return trim((string)$value);
    }
}
