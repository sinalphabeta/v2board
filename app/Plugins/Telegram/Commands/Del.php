<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
use App\Services\RiskService;
class Del extends RiskCommand { public $command='/del'; public $description='删除邮箱风险名单'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $i=RiskIndicator::where('type','email')->where('value',(new RiskService())->normalizeEmail($message->args[0]??''))->first(); if($i)(new RiskService())->removeIndicator($i,$this->actorId); $this->telegramService->sendMessage($message->chat_id,'已删除');} }
