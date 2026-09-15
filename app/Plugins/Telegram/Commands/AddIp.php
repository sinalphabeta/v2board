<?php
namespace App\Plugins\Telegram\Commands;
class AddIp extends RiskCommand { public $command='/addip'; public $description='添加 IP 风险名单'; public function handle($message,$match=[]){$this->add($message,'ip');} }
