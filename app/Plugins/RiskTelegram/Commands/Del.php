<?php

namespace App\Plugins\RiskTelegram\Commands;

class Del extends IndicatorCommand
{
    public $command = '/del';
    public $description = '解除：停用邮箱名单';
    public $sort = 40;
    protected $type = 'email';
    protected $action = 'del';
    protected $usage = '邮箱…';
}
