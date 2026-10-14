<?php

namespace App\Plugins\RiskTelegram\Commands;

class ListAsn extends IndicatorCommand
{
    public $command = '/listasn';
    public $description = 'ASN 名单';
    public $sort = 102;
    protected $type = 'asn';
    protected $action = 'list';
    protected $usage = '';
}
