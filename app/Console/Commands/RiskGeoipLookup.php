<?php

namespace App\Console\Commands;

use App\Services\IpInfoService;
use Illuminate\Console\Command;

class RiskGeoipLookup extends Command
{
    protected $signature = 'risk:geoip-lookup {ip : IPv4 or IPv6 address}';
    protected $description = 'Look up an IP using the local risk GeoIP databases';

    public function handle(IpInfoService $service)
    {
        $ip = (string)$this->argument('ip');
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->error("Invalid IP address: {$ip}");
            return 1;
        }

        $result = $service->lookup($ip);
        $this->line("ip: {$ip}");
        $this->line("ip_info: {$result['ip_info']}");
        $this->line('asn: ' . ($result['asn'] ?? 'N/A'));
        $this->line("location_source: {$result['location_source']}");
        $this->line("asn_source: {$result['asn_source']}");
        return 0;
    }
}
