<?php

namespace App\Plugins\RiskTelegram\Commands;

class AddUa extends IndicatorCommand
{
    public $command = '/addua';
    public $description = '添加 UA 名单（关键字）';
    public $sort = 90;
    protected $type = 'ua';
    protected $action = 'add';
    protected $usage = '关键字';
}
