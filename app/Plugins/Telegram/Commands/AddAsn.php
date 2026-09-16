<?php
namespace App\Plugins\Telegram\Commands;
class AddAsn extends RiskCommand { public $command='/addasn'; public $description='添加 ASN 风险名单'; public function handle($message,$match=[]){$this->add($message,'asn');} }
