<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * One risk-control setting per row (see App\Services\RiskSettings).
 */
class RiskSetting extends Model
{
    public $timestamps = false;
    public $incrementing = false;
    protected $table = 'v2_risk_setting';
    protected $primaryKey = 'name';
    protected $keyType = 'string';
    protected $guarded = [];
}
