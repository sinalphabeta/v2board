<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class RiskEvent extends Model
{
    public $timestamps = false;
    protected $table = 'v2_risk_event';
    protected $guarded = ['id'];
    protected $casts = ['first_seen_at' => 'timestamp', 'last_seen_at' => 'timestamp'];
}
