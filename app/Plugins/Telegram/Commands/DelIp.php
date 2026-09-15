<?php
namespace App\Plugins\Telegram\Commands;
class DelIp extends RiskCommand { public $command='/delip'; public $description='删除 IP 风险名单'; public function handle($message,$match=[]){$this->delete($message,'ip');} }
