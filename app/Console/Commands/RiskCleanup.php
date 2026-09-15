<?php

namespace App\Console\Commands;

use App\Services\RiskService;
use Illuminate\Console\Command;

class RiskCleanup extends Command
{
    protected $signature = 'risk:cleanup';
    protected $description = 'Remove risk events older than the retention period';
    public function handle() { $this->info((new RiskService())->cleanup(90) . ' events removed'); }
}
