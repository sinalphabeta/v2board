<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class RiskAudit extends Model
{
    public $timestamps = false;
    protected $table = 'v2_risk_audit';
    protected $guarded = ['id'];
    protected $casts = ['created_at' => 'timestamp'];
}
