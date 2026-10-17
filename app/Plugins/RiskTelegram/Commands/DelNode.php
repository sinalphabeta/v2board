<?php

namespace App\Plugins\RiskTelegram\Commands;

class DelNode extends IndicatorCommand
{
    public $command = '/delnode';
    public $description = '停用节点 IP';
    public $sort = 107;
    protected $type = 'node_ip';
    protected $action = 'del';
    protected $usage = 'IP、CIDR或域名…';
}
