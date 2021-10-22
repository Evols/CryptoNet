// Copyright 1998-2018 Epic Games, Inc. All Rights Reserved.

#pragma once

#include "PacketHandler.h"

class FCryptoNetModule : public FPacketHandlerComponentModuleInterface
{
public:
	virtual TSharedPtr<HandlerComponent> CreateComponentInstance(FString& Options) override;
};
