<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class RiskIndicator extends Model
{
    protected $table = 'v2_risk_indicator';
    protected $dateFormat = 'U';
    protected $guarded = ['id'];
    protected $casts = ['enabled' => 'boolean', 'created_at' => 'timestamp', 'updated_at' => 'timestamp'];
}
