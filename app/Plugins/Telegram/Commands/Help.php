<?php
namespace App\Plugins\Telegram\Commands;
class Help extends RiskCommand { public $command='/help'; public $description='显示风险 Bot 命令'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $this->sendReply($message,'/add /del /edit /list /riskusers /search /addip /delip /listip /addua /delua /listua /addasn /delasn /listasn /find /audit /health /id');} }
