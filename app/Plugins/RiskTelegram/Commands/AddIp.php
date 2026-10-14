<?php

namespace App\Plugins\RiskTelegram\Commands;

class AddIp extends IndicatorCommand
{
    public $command = '/addip';
    public $description = '添加 IP 名单（IP 或 CIDR）';
    public $sort = 80;
    protected $type = 'ip';
    protected $action = 'add';
    protected $usage = 'IP或CIDR…';
}
