<?php

namespace App\Plugins\RiskTelegram\Commands;

class ListIp extends IndicatorCommand
{
    public $command = '/listip';
    public $description = 'IP 名单';
    public $sort = 82;
    protected $type = 'ip';
    protected $action = 'list';
    protected $usage = '';
}
