<?php

namespace App\Services;

use MaxMind\Db\Reader as MaxMindReader;

class IpInfoService
{
    private const UNKNOWN = '归属未知';
    private const LOCAL = '内网/保留地址';

    public function describe(string $ip): string
    {
        return $this->lookup($ip)['ip_info'];
    }

    public function lookup(string $ip): array
    {
        try {
            return $this->performLookup($ip);
        } catch (\Throwable $e) {
            return $this->result(self::UNKNOWN, null, null, 'none', 'none');
        }
    }

    public function asnDatabaseAvailable(): bool
    {
        $path = $this->databasePath('asn');
        return $path !== '' && is_file($path) && is_readable($path);
    }

    public function lookupAsn(string $ip): array
    {
        try {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) return $this->asnResult(null, null, 'none');
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $this->asnResult(null, null, 'special');
            }
            $record = $this->lookupMmdb($this->databasePath('asn'), $ip);
            $number = $this->formatAsnNumber($record);
            $asn = $this->formatAsn($record, $number);
            return $this->asnResult($asn, $number, $asn === null ? 'none' : 'dbip-asn');
        } catch (\Throwable $e) {
            return $this->asnResult(null, null, 'none');
        }
    }

    private function performLookup(string $ip): array
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return $this->result(self::UNKNOWN, null, null, 'none', 'none');
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $this->result(self::LOCAL, null, null, 'special', 'none');
        }

        $qqwry = $this->lookupQqwry($ip);
        if ($qqwry !== null && $this->clean($qqwry['isp_domain'] ?? '') !== '') {
            $ipInfo = $this->formatQqwry($qqwry);
            $locationSource = 'qqwry';
        } else {
            $city = $this->lookupMmdb($this->databasePath('city'), $ip);
            $ipInfo = $this->formatCity($city);
            $locationSource = $ipInfo === self::UNKNOWN ? 'none' : 'dbip-city';
        }

        $asnResult = $this->lookupAsn($ip);

        return $this->result($ipInfo, $asnResult['asn'], $asnResult['asn_number'], $locationSource, $asnResult['asn_source']);
    }

    private function lookupQqwry(string $ip): ?array
    {
        $path = $this->databasePath('qqwry');
        if (!is_file($path) || !is_readable($path) || !$this->hasValidIpdbHeader($path)) return null;

        $database = null;
        try {
            $database = new \ipip\db\City($path);
            $result = $database->findMap($ip, 'CN');
            return is_array($result) ? $result : null;
        } catch (\Throwable $e) {
            return null;
        } finally {
            try {
                if ($database !== null) $database->reader->close();
            } catch (\Throwable $e) {
                // A failed close must not break risk notifications.
            }
        }
    }

    private function lookupMmdb(string $path, string $ip): ?array
    {
        if (!is_file($path) || !is_readable($path)) return null;

        $reader = null;
        try {
            $reader = new MaxMindReader($path);
            $result = $reader->get($ip);
            return is_array($result) ? $result : null;
        } catch (\Throwable $e) {
            return null;
        } finally {
            try {
                if ($reader !== null) $reader->close();
            } catch (\Throwable $e) {
                // A failed close must not break risk notifications.
            }
        }
    }

    private function formatQqwry(array $info): string
    {
        $location = $this->uniqueValues($info, ['country_name', 'region_name', 'city_name', 'district_name']);
        $network = $this->uniqueValues($info, ['isp_domain', 'owner_domain']);
        $description = implode(' ', $location);
        if ($network) $description .= ($description === '' ? '' : ' | ') . implode(' ', $network);
        return $description !== '' ? $description : self::UNKNOWN;
    }

    private function formatCity(?array $record): string
    {
        if ($record === null) return self::UNKNOWN;

        $parts = [
            $this->localizedName($record['country']['names'] ?? [], true),
            $this->localizedName($record['subdivisions'][0]['names'] ?? []),
            $this->localizedName($record['city']['names'] ?? []),
        ];
        $parts = array_values(array_unique(array_filter($parts, function ($value) {
            return $value !== '';
        })));
        return $parts ? implode(' ', $parts) : self::UNKNOWN;
    }

    private function formatAsnNumber(?array $record): ?string
    {
        if ($record === null) return null;
        $number = filter_var($record['autonomous_system_number'] ?? null, FILTER_VALIDATE_INT);
        if ($number === false || $number < 1 || $number > 4294967295) return null;
        return 'AS' . $number;
    }

    private function formatAsn(?array $record, ?string $number): ?string
    {
        if ($record === null || $number === null) return null;
        $organization = $this->clean($record['autonomous_system_organization'] ?? '');
        return $number . ($organization === '' ? '' : ' ' . $organization);
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

    private function result(string $ipInfo, ?string $asn, ?string $asnNumber, string $locationSource, string $asnSource): array
    {
        return [
            'ip_info' => $ipInfo,
            'asn' => $asn,
            'asn_number' => $asnNumber,
            'location_source' => $locationSource,
            'asn_source' => $asnSource,
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
