<?php

namespace App\Plugins\RiskTelegram\Commands;

class AddAllow extends IndicatorCommand
{
    public $command = '/addallow';
    public $description = '添加 IP 白名单：命中 IP、ASN 名单不告警';
    public $sort = 103;
    protected $type = 'allow_ip';
    protected $action = 'add';
    protected $usage = 'IP或CIDR…';
}
