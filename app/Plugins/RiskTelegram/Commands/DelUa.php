<?php

namespace App\Plugins\RiskTelegram\Commands;

class DelUa extends IndicatorCommand
{
    public $command = '/delua';
    public $description = '停用 UA 名单';
    public $sort = 91;
    protected $type = 'ua';
    protected $action = 'del';
    protected $usage = '关键字';
}
