// Copyright 1998-2018 Epic Games, Inc. All Rights Reserved.

#include "CryptoNet.h"
#include "CryptoNetHandlerComponent.h"
#include "Modules/ModuleManager.h"
// #include "Interfaces/IPluginManager.h"

#define LOCTEXT_NAMESPACE "FCryptoNetModule"

TSharedPtr<HandlerComponent> FCryptoNetModule::CreateComponentInstance(FString& Options)
{
	return MakeShareable(new CryptoNetHandlerComponent());
}

#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FCryptoNetModule, CryptoNet)
