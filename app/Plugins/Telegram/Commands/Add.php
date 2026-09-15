<?php
namespace App\Plugins\Telegram\Commands;
class Add extends RiskCommand { public $command='/add'; public $description='添加邮箱风险名单'; public function handle($message,$match=[]){$this->add($message,'email');} }
