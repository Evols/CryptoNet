// Copyright 1998-2018 Epic Games, Inc. All Rights Reserved.

#pragma once

#include "EncryptionComponent.h"


namespace OpenSSL
{
#pragma warning(disable:4668 4005)

#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>
}

DECLARE_LOG_CATEGORY_EXTERN(LogCryptoNet, Log, All);

#define ASYM_ALGO RSA
#define ASYM_KEY_SIZE 2048
#define ASYM_HASH_ALGO SHA256
#define ASYM_HASH_SIZE 256 // In bits (but has to be a multiple of 8). Can be smaller than digest's size if you want to truncate it. Zero means no hash

#define ALGO_MODE_OPENSSL EVP_aes_256_ecb // If SYM_MODE_CUSTOM_CTS is 0, this is the algo and mode used to encrypt data. Unused otherwise

#define SYM_MODE_CUSTOM_CTS 1 // To enable CTS (ciphertext stealing). This reduces the overhead added by cryptography
#define SYM_ALGO(x) AES##x // Replace the part before ##x with the algo you want to use
#define SYM_KEY_SIZE 256 // Key size, in bits (but has to be a multiple of 8)

#define SYM_HASH_ALGO SHA256
#define SYM_HASH_SIZE 32 // In bits (but has to be a multiple of 8). Can be smaller than digest's size if you want to truncate it. Zero means no hash

#define PACKET_STATS 1 // If we want to store and show stats. You may want to disable this when releasing your game

// Internals

#define SYM_HASH_SIZE_BYTES (SYM_HASH_SIZE/8)
#define ASYM_HASH_SIZE_BYTES (ASYM_HASH_SIZE/8)

class CRYPTONET_API CryptoNetHandlerComponent : public HandlerComponent
{
public:

	CryptoNetHandlerComponent();

	virtual ~CryptoNetHandlerComponent();

	virtual void Initialize() override;

public:

	void SymmetricEncrypt(const TArray<uint8>& InData, TArray<uint8>& OutData);
	void SymmetricDecrypt(const TArray<uint8>& InData, TArray<uint8>& OutData);
	void SymmetricHash(const TArray<uint8>& Data, TArray<uint8>& Hash);
	void AsymmetricEncryptWithPublic(const TArray<uint8>& Plaintext, TArray<uint8>& Ciphertext);
	void AsymmetricDecryptWithPrivate(const TArray<uint8>& Ciphertext, TArray<uint8>& Plaintext);
	void AsymmetricHash(const TArray<uint8>& Data, TArray<uint8>& Hash);

	void SetSymmetricKey(const TArray<uint8>& NewKey);

#if SYM_MODE_CUSTOM_CTS
	OpenSSL::SYM_ALGO(_KEY) EncryptionSymmetricKey;
	OpenSSL::SYM_ALGO(_KEY) DecryptionSymmetricKey;
#else
	TArray<uint8> SymmetricKey;
#endif

	TArray<uint8> IV;

	bool bSymmetricKeyShared;

	bool bEnableCrypto;

	TArray<uint8> PrivateKeyPEM;

public:

#if PACKET_STATS
	int32 TotalPlaintextBitsSent;
	int32 TotalCipheredBitsSent;

	int32 TotalPlaintextBitsRecv;
	int32 TotalCipheredBitsRecv;
#endif

public:

	bool IsValid() const override;

	void Incoming(FBitReader& Packet) override;

	void Outgoing(FBitWriter& Packet, FOutPacketTraits& Traits) override;

	void IncomingConnectionless(const TSharedPtr<const FInternetAddr>& Address, FBitReader& Packet) override {};

	void OutgoingConnectionless(const TSharedPtr<const FInternetAddr>& Address, FBitWriter& Packet, FOutPacketTraits& Traits) override {};
	
	int32 GetReservedPacketBits() const override;

	void NotifyHandshakeBegin() override;
	
};
