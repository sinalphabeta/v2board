<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * Every login, registration, subscription and order, one row per day, user, type, result, IP (an IPv6 address by its
 * /64) and user agent; see RiskAccessService. The primary key is that combination, so rows are only read through this
 * model and written by RiskAccessService with INSERT … ON DUPLICATE KEY UPDATE.
 */
class RiskAccess extends Model
{
    public $timestamps = false;
    public $incrementing = false;
    protected $table = 'v2_risk_access';
    protected $primaryKey = null;
    protected $guarded = [];
    protected $casts = [
        'record_at' => 'integer', 'user_id' => 'integer', 'event_type' => 'integer', 'result' => 'integer',
        'ua_hash' => 'integer', 'occurrences' => 'integer', 'first_seen_at' => 'integer', 'last_seen_at' => 'integer',
    ];
}
