<?php

namespace App\Console\Commands;

use App\Services\RiskConnService;
use App\Services\RiskService;
use Illuminate\Console\Command;

class RiskScan extends Command
{
    protected $signature = 'risk:scan';
    protected $description = 'Alert on IPs that several users subscribed or logged in from today, and on the connection log';

    public function handle()
    {
        $service = new RiskService();
        $ips = $service->links()->scan();
        $users = (new RiskConnService($service))->scan();
        $this->info("{$ips} IPs alerted, {$users} users of the connection log alerted");
    }
}
