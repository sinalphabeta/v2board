<?php

namespace App\Plugins\RiskTelegram\Commands;

class ListCommand extends IndicatorCommand
{
    public $command = '/list';
    public $description = '邮箱名单';
    public $sort = 70;
    protected $type = 'email';
    protected $action = 'list';
    protected $usage = '';
}
