<?php
namespace App\Plugins\Telegram\Commands;
class Id extends RiskCommand { public $command='/id'; public $description='显示 Telegram ID'; public function handle($message,$match=[]){$this->sendReply($message,(string)($message->sender_id ?? $message->chat_id));} }
