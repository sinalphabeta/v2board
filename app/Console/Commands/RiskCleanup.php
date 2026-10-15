<?php

namespace App\Console\Commands;

use App\Services\RiskService;
use App\Services\RiskSettings;
use Illuminate\Console\Command;

class RiskCleanup extends Command
{
    protected $signature = 'risk:cleanup';
    protected $description = 'Remove risk events and access log rows older than their retention periods';

    public function handle()
    {
        $service = new RiskService();
        $events = $service->cleanup(90);
        $rows = $service->access()->prune((int)RiskSettings::get('access_log_days'));
        $this->info("{$events} events and {$rows} access log rows removed");
    }
}
