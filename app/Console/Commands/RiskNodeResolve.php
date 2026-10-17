<?php

namespace App\Console\Commands;

use App\Services\RiskAccessService;
use Illuminate\Console\Command;

class RiskNodeResolve extends Command
{
    protected $signature = 'risk:node-resolve';
    protected $description = 'Look up the node IPs given as domain names (relays with DDNS)';

    public function handle()
    {
        foreach ((new RiskAccessService())->resolveNodeHosts() as $host => $ips) {
            $this->line($host . ': ' . ($ips === null ? 'lookup failed, the IPs found before are kept' : implode(', ', $ips)));
        }
    }
}
