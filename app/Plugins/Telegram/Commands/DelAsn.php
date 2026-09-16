<?php
namespace App\Plugins\Telegram\Commands;
class DelAsn extends RiskCommand { public $command='/delasn'; public $description='删除 ASN 风险名单'; public function handle($message,$match=[]){$this->delete($message,'asn');} }
