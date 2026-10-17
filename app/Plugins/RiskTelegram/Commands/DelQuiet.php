<?php

namespace App\Plugins\RiskTelegram\Commands;

class DelQuiet extends IndicatorCommand
{
    public $command = '/delquiet';
    public $description = '停用免告警（恢复告警）';
    public $sort = 112;
    protected $type = 'quiet';
    protected $action = 'del';
    protected $usage = '邮箱或uid…';
}
