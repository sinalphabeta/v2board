<?php
namespace App\Plugins\Telegram\Commands;
class DelUa extends RiskCommand { public $command='/delua'; public $description='删除 UA 风险名单'; public function handle($message,$match=[]){$this->delete($message,'ua');} }
