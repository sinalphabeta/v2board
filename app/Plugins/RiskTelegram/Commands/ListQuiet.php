<?php

namespace App\Plugins\RiskTelegram\Commands;

class ListQuiet extends IndicatorCommand
{
    public $command = '/listquiet';
    public $description = '免告警用户';
    public $sort = 113;
    protected $type = 'quiet';
    protected $action = 'list';
    protected $usage = '';
}
