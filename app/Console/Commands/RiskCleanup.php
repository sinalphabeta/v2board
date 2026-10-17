<?php

namespace App\Console\Commands;

use App\Services\RiskConnService;
use App\Services\RiskService;
use App\Services\RiskSettings;
use Illuminate\Console\Command;

class RiskCleanup extends Command
{
    protected $signature = 'risk:cleanup';
    protected $description = 'Remove risk events, access log and connection log rows older than their retention periods';

    public function handle()
    {
        $service = new RiskService();
        $events = $service->cleanup(90);
        $rows = $service->access()->prune((int)RiskSettings::get('access_log_days'));
        $connections = (new RiskConnService($service))->prune((int)RiskSettings::get('conn_log_days'));
        $this->info("{$events} events, {$rows} access log rows and {$connections} connection log rows removed");
    }
}
