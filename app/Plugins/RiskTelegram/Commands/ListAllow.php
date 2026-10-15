<?php

namespace App\Plugins\RiskTelegram\Commands;

class ListAllow extends IndicatorCommand
{
    public $command = '/listallow';
    public $description = 'IP 白名单';
    public $sort = 105;
    protected $type = 'allow_ip';
    protected $action = 'list';
    protected $usage = '';
}
