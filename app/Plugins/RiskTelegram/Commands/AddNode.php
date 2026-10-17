<?php

namespace App\Plugins\RiskTelegram\Commands;

class AddNode extends IndicatorCommand
{
    public $command = '/addnode';
    public $description = '添加节点 IP：节点的出口、中转机的 IP 或域名，和白名单一样';
    public $sort = 106;
    protected $type = 'node_ip';
    protected $action = 'add';
    protected $usage = 'IP、CIDR或域名…';
}
