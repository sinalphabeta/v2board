<?php

namespace App\Plugins\RiskTelegram\Commands;

class ListUa extends IndicatorCommand
{
    public $command = '/listua';
    public $description = 'UA 名单';
    public $sort = 92;
    protected $type = 'ua';
    protected $action = 'list';
    protected $usage = '';
}
