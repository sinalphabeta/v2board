<?php

namespace App\Console\Commands;

use App\Services\RiskService;
use Illuminate\Console\Command;

class RiskScan extends Command
{
    protected $signature = 'risk:scan';
    protected $description = 'Alert on IPs that several users subscribed or logged in from today';

    public function handle()
    {
        $this->info((new RiskService())->links()->scan() . ' IPs alerted');
    }
}
