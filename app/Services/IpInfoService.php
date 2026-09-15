<?php

namespace App\Services;

class IpInfoService
{
    private const UNKNOWN = '归属未知';

    public function describe(string $ip): string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return self::UNKNOWN;

        $v4Path = (string)config('risk.ip_database_v4', '');
        $v6Path = (string)config('risk.ip_database_v6', '');
        try {
            $reader = new \Ip2Region(
                'file',
                is_file($v4Path) ? $v4Path : null,
                is_file($v6Path) ? $v6Path : null
            );
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $reader->simple($ip) ?: self::UNKNOWN;
            }
            $info = $reader->getIpInfo($ip);
        } catch (\Throwable $e) {
            return self::UNKNOWN;
        }
        if (!$info) return self::UNKNOWN;

        $location = [];
        foreach (['country', 'province', 'city'] as $field) {
            $value = $this->clean($info[$field] ?? '');
            if ($value !== '' && !in_array($value, $location, true)) $location[] = $value;
        }
        $isp = $this->clean($info['isp'] ?? '');
        $description = implode(' ', $location);
        if ($isp !== '') $description .= ($description === '' ? '' : ' | ') . $isp;
        return $description !== '' ? $description : self::UNKNOWN;
    }

    private function clean($value): string
    {
        $value = trim((string)$value);
        return in_array($value, ['', '0', '内网IP'], true) ? '' : $value;
    }
}
