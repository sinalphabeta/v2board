<?php

namespace App\Console\Commands;

use App\Services\RiskConnService;
use Illuminate\Console\Command;

class RiskConnFlush extends Command
{
    protected $signature = 'risk:conn-flush';
    protected $description = 'Write the devices online that the nodes reported to the connection log';

    public function handle()
    {
        try {
            $this->info((new RiskConnService())->flush() . ' rows written');
        } catch (\Throwable $e) {
            $this->error('Kept for the next run: ' . $e->getMessage());
            return 1;
        }
        return 0;
    }
}
