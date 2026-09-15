<?php
namespace App\Plugins\Telegram\Commands;
class Del extends RiskCommand { public $command='/del'; public $description='删除邮箱风险名单'; public function handle($message,$match=[]){$this->delete($message,'email');} }
