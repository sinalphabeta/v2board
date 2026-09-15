<?php

namespace App\Console\Commands;

use App\Models\RiskEvent;
use App\Services\RiskService;
use Illuminate\Console\Command;

class RiskSummary extends Command
{
    protected $signature = 'risk:summary';
    protected $description = 'Send the daily risk event summary';

    public function handle()
    {
        $events = RiskEvent::where('last_seen_at', '>=', time() - 86400)->get();
        if (!$events->count()) return;
        $count = $events->sum('occurrences');
        (new RiskService())->notify(null, 'daily-summary', 'aggregate', "events={$events->count()} occurrences={$count}");
        $this->info("{$events->count()} events summarized");
    }
}
