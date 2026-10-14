<?php

namespace App\Plugins\RiskTelegram\Commands;

class AddAsn extends IndicatorCommand
{
    public $command = '/addasn';
    public $description = '添加 ASN 名单';
    public $sort = 100;
    protected $type = 'asn';
    protected $action = 'add';
    protected $usage = 'AS号…';
}
