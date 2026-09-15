<?php
namespace App\Plugins\Telegram\Commands;
class Help extends RiskCommand { public $command='/help'; public $description='显示风险 Bot 命令'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $this->telegramService->sendMessage($message->chat_id,'/add /del /edit /list /riskusers /search /addip /delip /listip /addua /delua /listua /find /audit /health /id');} }
