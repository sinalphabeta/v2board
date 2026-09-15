<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
use App\Services\RiskService;
class DelIp extends RiskCommand { public $command='/delip'; public $description='删除 IP 风险名单'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $i=RiskIndicator::where('type','ip')->where('value',$message->args[0]??'')->first(); if($i)(new RiskService())->removeIndicator($i,$this->actorId); $this->telegramService->sendMessage($message->chat_id,'已删除');} }
