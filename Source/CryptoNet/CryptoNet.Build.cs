// Copyright 1998-2018 Epic Games, Inc. All Rights Reserved.

using UnrealBuildTool;
using System.IO;

public class CryptoNet : ModuleRules
{
    public CryptoNet(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = ModuleRules.PCHUsageMode.UseExplicitOrSharedPCHs;

        // PublicDefinitions.Add("_HAS_EXCEPTIONS=0");

        PublicDependencyModuleNames.AddRange(new string[] {
            "Core", "CoreUObject", "Engine",
            "NetCore",
            "PacketHandler"
        });

        LoadCryptoPP(Target);
    }

    public void LoadCryptoPP(ReadOnlyTargetRules Target)
    {
        PrivateDependencyModuleNames.AddRange(new string[] {
            "OpenSSL",
        });

        /*
        string LibFolder = "lib/";
        string LibExtension = "";
        string CryptoPPPath = Path.GetFullPath(Path.Combine(ModuleDirectory, "../../ThirdParty/CryptoPP/"));
        string PluginThirdPartyPath = Path.GetFullPath(Path.Combine(ModuleDirectory, "../../ThirdParty/"));

        // if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            PublicIncludePaths.Add(CryptoPPPath + "include");
            PublicIncludePaths.Add(PluginThirdPartyPath);
            PublicIncludePaths.Add(Target.UEThirdPartySourceDirectory);
            LibFolder += "Win64/VS2015/";
            LibExtension = ".lib";
            PublicLibraryPaths.Add(CryptoPPPath + LibFolder);
        }

        PublicAdditionalLibraries.Add("cryptlib" + LibExtension);
        */
    }
}
