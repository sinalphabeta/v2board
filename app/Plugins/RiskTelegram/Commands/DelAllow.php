<?php

namespace App\Plugins\RiskTelegram\Commands;

class DelAllow extends IndicatorCommand
{
    public $command = '/delallow';
    public $description = '删除 IP 白名单';
    public $sort = 104;
    protected $type = 'allow_ip';
    protected $action = 'del';
    protected $usage = 'IP或CIDR…';
}
