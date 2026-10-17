<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * The IPs users connect to the nodes from, one row per day, user and IP (an IPv6 address by its /64), with the nodes
 * that reported it; see RiskConnService. The primary key is that combination, so rows are only read through this model
 * and written by RiskConnService with INSERT … ON DUPLICATE KEY UPDATE.
 */
class RiskConn extends Model
{
    public $timestamps = false;
    public $incrementing = false;
    protected $table = 'v2_risk_conn';
    protected $primaryKey = null;
    protected $guarded = [];
    protected $casts = [
        'record_at' => 'integer', 'user_id' => 'integer', 'reports' => 'integer', 'first_seen_at' => 'integer', 'last_seen_at' => 'integer',
    ];
}
