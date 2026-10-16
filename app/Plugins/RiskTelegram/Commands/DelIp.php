<?php

namespace App\Plugins\RiskTelegram\Commands;

class DelIp extends IndicatorCommand
{
    public $command = '/delip';
    public $description = '停用 IP 名单';
    public $sort = 81;
    protected $type = 'ip';
    protected $action = 'del';
    protected $usage = 'IP或CIDR…';
}
