<?php

namespace App\Plugins\RiskTelegram\Commands;

class DelAsn extends IndicatorCommand
{
    public $command = '/delasn';
    public $description = '停用 ASN 名单';
    public $sort = 101;
    protected $type = 'asn';
    protected $action = 'del';
    protected $usage = 'AS号…';
}
