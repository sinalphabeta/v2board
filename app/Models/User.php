<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $table = 'v2_user';
    protected $dateFormat = 'U';
    protected $guarded = ['id'];
    protected $casts = [
        'created_at' => 'timestamp',
        'updated_at' => 'timestamp',
        'risk_marked_at' => 'timestamp',
        'risk_status' => 'integer',
        'risk_indicator_id' => 'integer'
    ];
}
