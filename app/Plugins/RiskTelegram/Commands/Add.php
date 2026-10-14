<?php

namespace App\Plugins\RiskTelegram\Commands;

class Add extends IndicatorCommand
{
    public $command = '/add';
    public $description = '隔离：把邮箱加入名单';
    public $sort = 30;
    protected $type = 'email';
    protected $action = 'add';
    protected $usage = '邮箱…';
}
