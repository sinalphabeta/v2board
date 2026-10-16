<?php

namespace App\Plugins\RiskTelegram\Commands;

class DelNode extends IndicatorCommand
{
    public $command = '/delnode';
    public $description = '删除节点 IP';
    public $sort = 107;
    protected $type = 'node_ip';
    protected $action = 'del';
    protected $usage = 'IP或CIDR…';
}
