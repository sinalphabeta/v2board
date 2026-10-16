<?php

namespace App\Plugins\RiskTelegram\Commands;

class ListNode extends IndicatorCommand
{
    public $command = '/listnode';
    public $description = '节点 IP';
    public $sort = 108;
    protected $type = 'node_ip';
    protected $action = 'list';
    protected $usage = '';
}
