<?php

namespace App\Plugins\RiskTelegram\Commands;

class AddQuiet extends IndicatorCommand
{
    public $command = '/addquiet';
    public $description = '添加免告警用户：邮箱或 uid，照样记录，连接和订阅的告警不发';
    public $sort = 111;
    protected $type = 'quiet';
    protected $action = 'add';
    protected $usage = '邮箱或uid…';
}
