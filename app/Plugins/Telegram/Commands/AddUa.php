<?php
namespace App\Plugins\Telegram\Commands;
class AddUa extends RiskCommand { public $command='/addua'; public $description='添加 UA 风险名单'; public function handle($message,$match=[]){$this->add($message,'ua');} }
