<?php

namespace App\Services;

use MaxMind\Db\Reader as MaxMindReader;

class IpInfoService
{
    private const UNKNOWN = '归属未知';
    private const LOCAL = '内网/保留地址';
    // While lookupMany() runs: the databases opened so far, by kind and path (null for one that cannot be opened)
    private $readers;

    public function describe(string $ip): string
    {
        return $this->lookup($ip)['ip_info'];
    }

    public function lookup(string $ip): array
    {
        try {
            return $this->result($this->details($ip));
        } catch (\Throwable $e) {
            return $this->result($this->unknown());
        }
    }

    /**
     * Look up many IPs at once, for the admin panel's lists: each database is opened once for all of them. Nothing
     * is cached, so an update of the databases shows at once. Returns, by IP: location (国家 省 市, or 内网/保留地址),
     * network (the ISP or IDC, from qqwry only), asn_number and asn_name, each null when unknown; what lookup() finds.
     */
    public function lookupMany(array $ips): array
    {
        $this->readers = [];
        try {
            $results = [];
            foreach ($ips as $ip) {
                $ip = (string)$ip;
                if (array_key_exists($ip, $results)) continue;
                try {
                    $details = $this->details($ip);
                } catch (\Throwable $e) {
                    $details = $this->unknown();
                }
                $results[$ip] = array_intersect_key($details, array_flip(['location', 'network', 'asn_number', 'asn_name']));
            }
            return $results;
        } finally {
            foreach ($this->readers as $reader) $this->close($reader);
            $this->readers = null;
        }
    }

    public function asnDatabaseAvailable(): bool
    {
        $path = $this->databasePath('asn');
        return $path !== '' && is_file($path) && is_readable($path);
    }

    public function lookupAsn(string $ip): array
    {
        $asn = $this->asnDetails($ip);
        return $this->asnResult($asn['asn'], $asn['asn_number'], $asn['asn_source']);
    }

    /**
     * What lookup() returns (ip_info and asn as shown in alerts, the sources), and the parts for lookupMany().
     */
    private function details(string $ip): array
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return $this->unknown();
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return ['location' => self::LOCAL, 'ip_info' => self::LOCAL, 'location_source' => 'special'] + $this->unknown();
        }

        $qqwry = $this->lookupQqwry($ip);
        if ($qqwry !== null && $this->clean($qqwry['isp_domain'] ?? '') !== '') {
            $location = implode(' ', $this->uniqueValues($qqwry, ['country_name', 'region_name', 'city_name', 'district_name']));
            $network = implode(' ', $this->uniqueValues($qqwry, ['isp_domain', 'owner_domain']));
            $locationSource = 'qqwry';
        } else {
            $location = $this->formatCity($this->lookupMmdb($this->databasePath('city'), $ip));
            $network = '';
            $locationSource = $location === '' ? 'none' : 'dbip-city';
        }
        $ipInfo = $location;
        if ($network !== '') $ipInfo .= ($ipInfo === '' ? '' : ' | ') . $network;

        $asn = $this->asnDetails($ip);

        return [
            'location' => $location !== '' ? $location : null,
            'network' => $network !== '' ? $network : null,
            'asn_number' => $asn['asn_number'],
            'asn_name' => $asn['asn_name'],
            'ip_info' => $ipInfo !== '' ? $ipInfo : self::UNKNOWN,
            'asn' => $asn['asn'],
            'location_source' => $locationSource,
            'asn_source' => $asn['asn_source'],
        ];
    }

    private function asnDetails(string $ip): array
    {
        $none = ['asn' => null, 'asn_number' => null, 'asn_name' => null, 'asn_source' => 'none'];
        try {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) return $none;
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return ['asn_source' => 'special'] + $none;
            }
            $record = $this->lookupMmdb($this->databasePath('asn'), $ip);
            $number = $this->formatAsnNumber($record);
            if ($number === null) return $none;
            $organization = $this->clean($record['autonomous_system_organization'] ?? '');
            return [
                'asn' => $number . ($organization === '' ? '' : ' ' . $organization),
                'asn_number' => $number,
                'asn_name' => $organization !== '' ? $organization : null,
                'asn_source' => 'dbip-asn',
            ];
        } catch (\Throwable $e) {
            return $none;
        }
    }

    private function lookupQqwry(string $ip): ?array
    {
        $path = $this->databasePath('qqwry');
        $database = $this->open("qqwry:{$path}", function () use ($path) {
            if (!is_file($path) || !is_readable($path) || !$this->hasValidIpdbHeader($path)) return null;
            return new \ipip\db\City($path);
        });
        if ($database === null) return null;
        try {
            $result = $database->findMap($ip, 'CN');
            return is_array($result) ? $result : null;
        } catch (\Throwable $e) {
            return null;
        } finally {
            if ($this->readers === null) $this->close($database);
        }
    }

    private function lookupMmdb(string $path, string $ip): ?array
    {
        $reader = $this->open("mmdb:{$path}", function () use ($path) {
            return is_file($path) && is_readable($path) ? new MaxMindReader($path) : null;
        });
        if ($reader === null) return null;
        try {
            $result = $reader->get($ip);
            return is_array($result) ? $result : null;
        } catch (\Throwable $e) {
            return null;
        } finally {
            if ($this->readers === null) $this->close($reader);
        }
    }

    /**
     * Open a database (null if it cannot be): during lookupMany() once for all of its IPs, otherwise for one lookup,
     * closed by the caller.
     */
    private function open(string $key, callable $open)
    {
        if ($this->readers !== null && array_key_exists($key, $this->readers)) return $this->readers[$key];
        try {
            $database = $open();
        } catch (\Throwable $e) {
            $database = null;
        }
        if ($this->readers !== null) $this->readers[$key] = $database;
        return $database;
    }

    private function close($database): void
    {
        try {
            if ($database instanceof MaxMindReader) $database->close();
            if ($database instanceof \ipip\db\City && $database->reader !== null) $database->reader->close();
        } catch (\Throwable $e) {
            // A failed close must not break risk notifications.
        }
    }

    private function formatCity(?array $record): string
    {
        if ($record === null) return '';

        $parts = [
            $this->localizedName($record['country']['names'] ?? [], true),
            $this->localizedName($record['subdivisions'][0]['names'] ?? []),
            $this->localizedName($record['city']['names'] ?? []),
        ];
        $parts = array_values(array_unique(array_filter($parts, function ($value) {
            return $value !== '';
        })));
        return implode(' ', $parts);
    }

    private function formatAsnNumber(?array $record): ?string
    {
        if ($record === null) return null;
        $number = filter_var($record['autonomous_system_number'] ?? null, FILTER_VALIDATE_INT);
        if ($number === false || $number < 1 || $number > 4294967295) return null;
        return 'AS' . $number;
    }

    private function localizedName(array $names, bool $preferChinese = false): string
    {
        $languages = $preferChinese ? ['zh-CN', 'zh', 'en'] : ['en', 'zh-CN', 'zh'];
        foreach ($languages as $language) {
            $value = $this->clean($names[$language] ?? '');
            if ($value !== '') return $value;
        }
        return '';
    }

    private function uniqueValues(array $info, array $fields): array
    {
        $values = [];
        foreach ($fields as $field) {
            $value = $this->clean($info[$field] ?? '');
            if ($value !== '' && !in_array($value, $values, true)) $values[] = $value;
        }
        return $values;
    }

    private function databasePath(string $name): string
    {
        return (string)config("risk.geoip_databases.{$name}", '');
    }

    private function hasValidIpdbHeader(string $path): bool
    {
        $stream = @fopen($path, 'rb');
        if ($stream === false) return false;
        try {
            $lengthBytes = fread($stream, 4);
            if ($lengthBytes === false || strlen($lengthBytes) !== 4) return false;
            $unpacked = unpack('Nlength', $lengthBytes);
            $metadataLength = $unpacked['length'] ?? 0;
            $fileSize = filesize($path);
            if ($metadataLength < 2 || $metadataLength > 1024 * 1024 || $fileSize === false) return false;
            $metadataText = fread($stream, $metadataLength);
            if ($metadataText === false || strlen($metadataText) !== $metadataLength) return false;
            $metadata = json_decode($metadataText, true);
            if (!is_array($metadata) || !isset($metadata['fields'], $metadata['languages'], $metadata['total_size'])) return false;
            return 4 + $metadataLength + (int)$metadata['total_size'] === $fileSize;
        } catch (\Throwable $e) {
            return false;
        } finally {
            fclose($stream);
        }
    }

    private function unknown(): array
    {
        return [
            'location' => null, 'network' => null, 'asn_number' => null, 'asn_name' => null,
            'ip_info' => self::UNKNOWN, 'asn' => null, 'location_source' => 'none', 'asn_source' => 'none',
        ];
    }

    private function result(array $details): array
    {
        return [
            'ip_info' => $details['ip_info'],
            'asn' => $details['asn'],
            'asn_number' => $details['asn_number'],
            'location_source' => $details['location_source'],
            'asn_source' => $details['asn_source'],
        ];
    }

    private function asnResult(?string $asn, ?string $asnNumber, string $asnSource): array
    {
        return [
            'asn' => $asn,
            'asn_number' => $asnNumber,
            'asn_source' => $asnSource,
        ];
    }

    private function clean($value): string
    {
        $value = trim((string)$value);
        return in_array($value, ['', '0', '内网IP'], true) ? '' : $value;
    }
}
