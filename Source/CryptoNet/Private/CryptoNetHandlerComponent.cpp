// Copyright 1998-2018 Epic Games, Inc. All Rights Reserved.

#pragma warning(disable:4706)

#include "CryptoNetHandlerComponent.h"
#include "Net/Core/Misc/PacketAudit.h"

#include "HAL/PlatformFilemanager.h"
#include "HAL/PlatformFile.h"
#include "Misc/Paths.h"
#include "Misc/FileHelper.h"
#include "CoreGlobals.h"
#include "Misc/ConfigCacheIni.h"
#include "Engine/Engine.h"


namespace OpenSSL
{
#pragma warning(disable:4668 4005)
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <openssl/sha.h>

#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>
}

#include <iostream>

DEFINE_LOG_CATEGORY(LogCryptoNet);

#define PUBLIC_KEY \
"-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyTzI1e3g8/mplZKLSnD8\n"\
"Sb8Uirgk9KeohP6SX8nVae5FLGyycr6+KpdUZWvTi+3sdLnAfUBEoE4fNKTD97UT\n"\
"JZXfwrz9r1RQgJv7KCyO6eQPo6vspiwC5PyyZ71LUhjAZArvAQZAN+MBFnR7RnIH\n"\
"GgJFEpbpZfcFGZlFYoG50WWCC74keQ8BzaUJdc8dAhrnmg3h1yrxIN35Kr+fd8Vo\n"\
"Azpy6pEMiL2pdYuALu6WvLHBA9TxQRwX8/mh+4S/tRtu1sNY1Gh+148RYFcOHlyR\n"\
"JDcc7K4xRU87AqZOUj8WsORFIpCEZc0Zd/eb8oTz4ZyA2mnObg9vXJo2mwpmAR1F\n"\
"yQIDAQAB\n"\
"-----END PUBLIC KEY-----\n"

#define RSA_PADDING_METHOD RSA_PKCS1_PADDING

void CryptoNetHandlerComponent::SymmetricEncrypt(const TArray<uint8>& ConstPlaintext, TArray<uint8>& Ciphertext)
{
	auto Plaintext = ConstPlaintext;

#if SYM_MODE_CUSTOM_CTS

	// Add hash
	if (SYM_HASH_SIZE_BYTES > 0)
	{
		TArray<uint8> Hash;
		SymmetricHash(Plaintext, Hash);
		Plaintext.Append(Hash);
	}

	// Add the terminator if needed
	if (Plaintext.Last() == 0xFF || Plaintext.Last() == 0x00)
	{
		Plaintext.Add(0xFF);
	}

	const int32 n = SYM_ALGO(_BLOCK_SIZE); // Block size

	// If the plaintext is smaller than block size, directly cipher it, without mode or anything
	if (Plaintext.Num() <= n)
	{
		// Pad the thing
		while (Plaintext.Num() < n)
		{
			Plaintext.Add(0x00);
		}

		// Cipher the block
		TArray<uint8> ThisBlockCipher; ThisBlockCipher.SetNum(n);
		OpenSSL::SYM_ALGO(_encrypt)(Plaintext.GetData(), ThisBlockCipher.GetData(), &EncryptionSymmetricKey);
		Ciphertext.Append(ThisBlockCipher);
	}
	// If the plaintext is bigger than a block, use CTS
	else
	{
		const int32 k = Plaintext.Num(); // Plaintext size
		const int32 s = k % n; // The part of the plaintext that doesn't fit into a block
		const uint8* P = Plaintext.GetData(); // Plaintext

		// Encrypt classic blocks, aka ones that are not involved in CTS
		{
			TArray<uint8> CipherBlocks;

			const int32 ClassicBlockCount = k / n - 1;
			CipherBlocks.SetNum(ClassicBlockCount * n);
			for (int32 i = 0; i < ClassicBlockCount; i++)
			{
				OpenSSL::SYM_ALGO(_encrypt)(P + i * n, CipherBlocks.GetData() + i * n, &EncryptionSymmetricKey);
			}

			Ciphertext.Append(CipherBlocks);
		}

		// Actually do the CTS
		{
			TArray<uint8> A; A.SetNum(n); // A is the cipher of the near-to-last plaintext block
			OpenSSL::SYM_ALGO(_encrypt)(P + (k / n - 1) * n, A.GetData(), &EncryptionSymmetricKey);

			const TArray<uint8> A1(A.GetData(), s); // A1 is the part of A that will be written to the output
			const TArray<uint8> A2(A.GetData() + s, n - s); // A2 is the part of A that gets stolen

			TArray<uint8> B; B.SetNum(n); // B is the plaintext formed from the end of plaintext and the stolen ciphertext
			FMemory::Memcpy(B.GetData(), A2.GetData(), A2.Num());
			FMemory::Memcpy(B.GetData() + A2.Num(), P + (k / n) * n, s);

			TArray<uint8> C; C.SetNum(n); // C is the cipher of B
			OpenSSL::SYM_ALGO(_encrypt)(B.GetData(), C.GetData(), &EncryptionSymmetricKey);

			// Write down computed things
			Ciphertext.Append(C);
			Ciphertext.Append(A1);
		}
	}

#else

	auto* AlgoModeOpenSSL = OpenSSL::ALGO_MODE_OPENSSL();
	
	OpenSSL::EVP_CIPHER_CTX* OpenSSLContext = OpenSSL::EVP_CIPHER_CTX_new(); if (!OpenSSLContext) return;
	int32 ReturnCode = OpenSSL::EVP_EncryptInit_ex(OpenSSLContext, AlgoModeOpenSSL, nullptr, SymmetricKey.GetData(), IV.GetData());
	if (ReturnCode != 1)
	{
		UE_LOG(LogCryptoNet, Warning, TEXT("SymmetricEncrypt1: %s"), *FString(OpenSSL::ERR_error_string(ReturnCode, nullptr)));
		return;
	}

	int32 len;
	Ciphertext.SetNum(Plaintext.Num() + AlgoModeOpenSSL->ctx_size);
	ReturnCode = OpenSSL::EVP_EncryptUpdate(OpenSSLContext, Ciphertext.GetData(), &len, Plaintext.GetData(), Plaintext.Num());
	if (ReturnCode != 1)
	{
		UE_LOG(LogCryptoNet, Warning, TEXT("SymmetricEncrypt2: %s"), *FString(OpenSSL::ERR_error_string(ReturnCode, nullptr)));
		return;
	}

	int32 ciphertext_len = len;

	ReturnCode = OpenSSL::EVP_EncryptFinal_ex(OpenSSLContext, Ciphertext.GetData() + len, &len);
	if (ReturnCode != 1)
	{
		UE_LOG(LogCryptoNet, Warning, TEXT("SymmetricEncrypt3: %s"), *FString(OpenSSL::ERR_error_string(ReturnCode, nullptr)));
		return;
	}
	ciphertext_len += len;

	OpenSSL::EVP_CIPHER_CTX_free(OpenSSLContext);

	Ciphertext.SetNum(ciphertext_len);

#endif
}

void CryptoNetHandlerComponent::SymmetricDecrypt(const TArray<uint8>& ConstCiphertext, TArray<uint8>& Plaintext)
{
	auto Ciphertext = ConstCiphertext;

#if SYM_MODE_CUSTOM_CTS

	const int32 n = SYM_ALGO(_BLOCK_SIZE); // Block size

	// If it's just a padded single-block, process it
	if(Ciphertext.Num() <= n)
	{
		if (Ciphertext.Num() < n)
		{
			// WTF
			return;
		}

		Plaintext.SetNum(n);
		OpenSSL::SYM_ALGO(_decrypt)(Ciphertext.GetData(), Plaintext.GetData(), &DecryptionSymmetricKey);
	}
	// Do CTS
	else
	{
		const int32 k = Ciphertext.Num(); // Plaintext size
		const int32 s = k % n; // The part of the plaintext that doesn't fit into a block
		const uint8* X = Ciphertext.GetData(); // Ciphertext

		// Decrypt classic blocks, aka ones that are not involved in CTS
		{
			// Decrypt classic blocks, aka ones that are not involved in CTS
			const int32 ClassicBlockCount = Ciphertext.Num() / n - 1;
			TArray<uint8> PlaintextBlocks; PlaintextBlocks.SetNum(ClassicBlockCount * n);
			for (int32 i = 0; i < ClassicBlockCount; i++)
			{
				OpenSSL::SYM_ALGO(_decrypt)(X + i * n, PlaintextBlocks.GetData() + i * n, &DecryptionSymmetricKey);
			}

			Plaintext.Append(PlaintextBlocks);
		}

		// Actually do the CTS
		{
			const TArray<uint8> A1(X + (k / n) * n, s); // The part of the plaintext that doesn't fit into a block
			const TArray<uint8> C(X + (k / n - 1) * n, n); // The near-to-last ciphered block

			TArray<uint8> B; B.SetNum(n); // B is the plaintext of C
			OpenSSL::SYM_ALGO(_decrypt)(C.GetData(), B.GetData(), &DecryptionSymmetricKey);

			const TArray<uint8> A2(B.GetData(), n - s); // A2 is the part of A that gets stolen

			TArray<uint8> A; A.SetNum(n); // A is the cipher of the near-to-last plaintext block
			FMemory::Memcpy(A.GetData(), A1.GetData(), A1.Num());
			FMemory::Memcpy(A.GetData() + A1.Num(), A2.GetData(), A2.Num());

			TArray<uint8> Z; Z.SetNum(n); // Z is the plaintext of A
			OpenSSL::SYM_ALGO(_decrypt)(A.GetData(), Z.GetData(), &DecryptionSymmetricKey);

			// Write down computed things
			Plaintext.Append(Z);
			Plaintext.Append(B.GetData() + A2.Num(), B.Num() - A2.Num());
		}
	}

	// Unpad
	while (Plaintext.Last() == 0x00) Plaintext.Pop();
	if(Plaintext.Last() == 0xFF) Plaintext.Pop();

	// Check hash
	if (SYM_HASH_SIZE_BYTES > 0)
	{
		TArray<uint8> ReceivedHash(Plaintext.GetData() + Plaintext.Num() - SYM_HASH_SIZE_BYTES, SYM_HASH_SIZE_BYTES);
		Plaintext.SetNum(Plaintext.Num() - SYM_HASH_SIZE_BYTES);
		TArray<uint8> ComputedHash;
		SymmetricHash(Plaintext, ComputedHash);

		bool bEqual = true;
		for (int32 i = 0; i < SYM_HASH_SIZE_BYTES; i++)
		{
			bEqual = bEqual || (ComputedHash[i] == ReceivedHash[i]);
		}

		if (!bEqual)
		{
			Plaintext.SetNum(0);
			return;
		}
	}

#else

	auto* AlgoModeOpenSSL = OpenSSL::ALGO_MODE_OPENSSL();
	Plaintext.SetNum(Ciphertext.Num() + AlgoModeOpenSSL->block_size * 8);

	OpenSSL::EVP_CIPHER_CTX* OpenSSLContext = OpenSSL::EVP_CIPHER_CTX_new(); if (!OpenSSLContext) return;

	int32 ReturnCode = OpenSSL::EVP_DecryptInit_ex(OpenSSLContext, AlgoModeOpenSSL, nullptr, SymmetricKey.GetData(), IV.GetData());
	if (ReturnCode != 1)
	{
		UE_LOG(LogCryptoNet, Warning, TEXT("SymmetricDecrypt1: %s"), *FString(OpenSSL::ERR_error_string(ReturnCode, nullptr)));
		return;
	}

	int32 len = 0;
	ReturnCode = OpenSSL::EVP_DecryptUpdate(OpenSSLContext, Plaintext.GetData(), &len, Ciphertext.GetData(), Ciphertext.Num());
	if (ReturnCode != 1)
	{
		UE_LOG(LogCryptoNet, Warning, TEXT("SymmetricDecrypt2: %s"), *FString(OpenSSL::ERR_error_string(ReturnCode, nullptr)));
		return;
	}
	
	int32 plaintext_len = len;

	ReturnCode = OpenSSL::EVP_DecryptFinal_ex(OpenSSLContext, Plaintext.GetData() + len, &len);
	if (ReturnCode != 1)
	{
		UE_LOG(LogCryptoNet, Warning, TEXT("SymmetricDecrypt3: %s"), *FString(OpenSSL::ERR_error_string(ReturnCode, nullptr)));
		return;
	}

	plaintext_len += len;

	OpenSSL::EVP_CIPHER_CTX_free(OpenSSLContext);
	Plaintext.SetNum(plaintext_len);

#endif
}

void CryptoNetHandlerComponent::SymmetricHash(const TArray<uint8>& Data, TArray<uint8>& Hash)
{
	Hash.SetNum(SHA256_DIGEST_LENGTH);
	OpenSSL::SHA256_CTX sha256;
	OpenSSL::SHA256_Init(&sha256);
	OpenSSL::SHA256_Update(&sha256, Data.GetData(), Data.Num());
	OpenSSL::SHA256_Final(Hash.GetData(), &sha256);

	Hash.SetNum(SYM_HASH_SIZE_BYTES);
}

OpenSSL::RSA* CreatePublicRSA()
{
	OpenSSL::BIO* KeyBio = OpenSSL::BIO_new_mem_buf(reinterpret_cast<const void*>(PUBLIC_KEY), sizeof(PUBLIC_KEY));
	
	if (!KeyBio)
	{
		UE_LOG(LogCryptoNet, Log, TEXT("CreatePublicRSA: No bio"));
		return nullptr;
	}

	OpenSSL::RSA* Rsa = NULL;
	Rsa = OpenSSL::PEM_read_bio_RSA_PUBKEY(KeyBio, &Rsa, NULL, NULL);
	
	if (!Rsa)
	{
		UE_LOG(LogCryptoNet, Log, TEXT("CreatePublicRSA: No Rsa"));
		return nullptr;
	}

	return Rsa;
}

OpenSSL::RSA* CreatePrivateRSA(const TArray<uint8>& PrivateKeyPEM)
{
	OpenSSL::BIO* KeyBio = OpenSSL::BIO_new_mem_buf(reinterpret_cast<const void*>(PrivateKeyPEM.GetData()), PrivateKeyPEM.Num());
	OpenSSL::RSA* Rsa = nullptr;
	Rsa = OpenSSL::PEM_read_bio_RSAPrivateKey(KeyBio, &Rsa, NULL, NULL);
	return Rsa;
}

void CryptoNetHandlerComponent::AsymmetricEncryptWithPublic(const TArray<uint8>& ConstPlaintext, TArray<uint8>& Ciphertext)
{
	auto Plaintext = ConstPlaintext;

	// Add hash
	if (ASYM_HASH_SIZE_BYTES > 0)
	{
		TArray<uint8> Hash;
		AsymmetricHash(Plaintext, Hash);
		Plaintext.Append(Hash);
	}

	const int32 PlaintextSize = Plaintext.Num();
	OpenSSL::RSA* Rsa = CreatePublicRSA();

	Plaintext.SetNum(4096);
	Ciphertext.SetNum(4096);
	const int32 OutDataSize = OpenSSL::RSA_public_encrypt(PlaintextSize, Plaintext.GetData(), Ciphertext.GetData(), Rsa, RSA_PADDING_METHOD);

	if (OutDataSize <= 0)
	{
		Ciphertext.Empty();
		return;
	}
	else
	{
		Ciphertext.SetNum(OutDataSize);
	}
}

void CryptoNetHandlerComponent::AsymmetricDecryptWithPrivate(const TArray<uint8>& ConstCiphertext, TArray<uint8>& Plaintext)
{
	auto Ciphertext = ConstCiphertext;

	OpenSSL::RSA* Rsa = CreatePrivateRSA(PrivateKeyPEM);

	Plaintext.SetNum(4096);
	const int32 OutDataSize = OpenSSL::RSA_private_decrypt(Ciphertext.Num(), Ciphertext.GetData(), Plaintext.GetData(), Rsa, RSA_PADDING_METHOD);

	if (OutDataSize <= 0)
	{
		Plaintext.Empty();
		return;
	}
	else
	{
		Plaintext.SetNum(OutDataSize);
	}

	// Check hash
	if (ASYM_HASH_SIZE_BYTES > 0)
	{
		TArray<uint8> ReceivedHash(Plaintext.GetData() + Plaintext.Num() - ASYM_HASH_SIZE_BYTES, ASYM_HASH_SIZE_BYTES);
		Plaintext.SetNum(Plaintext.Num() - ASYM_HASH_SIZE_BYTES);
		TArray<uint8> ComputedHash;
		AsymmetricHash(Plaintext, ComputedHash);

		bool bEqual = true;
		for (int32 i = 0; i < ASYM_HASH_SIZE_BYTES; i++)
		{
			bEqual = bEqual || (ComputedHash[i] == ReceivedHash[i]);
		}

		if (!bEqual)
		{
			Plaintext.SetNum(0);
			return;
		}
	}
}

void CryptoNetHandlerComponent::AsymmetricHash(const TArray<uint8>& Data, TArray<uint8>& Hash)
{
	Hash.SetNum(SHA256_DIGEST_LENGTH);
	OpenSSL::SHA256_CTX sha256;
	OpenSSL::SHA256_Init(&sha256);
	OpenSSL::SHA256_Update(&sha256, Data.GetData(), Data.Num());
	OpenSSL::SHA256_Final(Hash.GetData(), &sha256);
}

void CryptoNetHandlerComponent::SetSymmetricKey(const TArray<uint8>& NewKey)
{
#if SYM_MODE_CUSTOM_CTS
	OpenSSL::SYM_ALGO(_set_encrypt_key)(NewKey.GetData(), SYM_KEY_SIZE, &EncryptionSymmetricKey);
	OpenSSL::SYM_ALGO(_set_decrypt_key)(NewKey.GetData(), SYM_KEY_SIZE, &DecryptionSymmetricKey);
#else
	SymmetricKey = NewKey;
#endif
}

CryptoNetHandlerComponent::CryptoNetHandlerComponent()
{
	SetActive(true);

	bRequiresHandshake = true;
	bRequiresReliability = true;

	bSymmetricKeyShared = false;
	bEnableCrypto = true;

#if PACKET_STATS
	TotalPlaintextBitsSent = 0;
	TotalCipheredBitsSent = 0;
	TotalPlaintextBitsRecv = 0;
	TotalCipheredBitsRecv = 0;
#endif
}

CryptoNetHandlerComponent::~CryptoNetHandlerComponent()
{
	if (!Handler) return;
#if PACKET_STATS
	auto* ServerModeText = (Handler->Mode == Handler::Mode::Server) ? TEXT("Server") : TEXT("Client");

	UE_LOG(LogCryptoNet, Log, TEXT("Bits sent (%s). ciphered: %d, plaintext: %d (%f%% more)"), ServerModeText, TotalCipheredBitsSent, TotalPlaintextBitsSent, ((float)TotalCipheredBitsSent / (float)TotalPlaintextBitsSent - 1.f) * 100.f);
	UE_LOG(LogCryptoNet, Log, TEXT("Bits received (%s). ciphered: %d, plaintext: %d (%f%% more)"), ServerModeText, TotalCipheredBitsRecv, TotalPlaintextBitsRecv, ((float)TotalCipheredBitsRecv / (float)TotalPlaintextBitsRecv - 1.f) * 100.f);
#endif
}

void CryptoNetHandlerComponent::Initialize()
{
	QUICK_SCOPE_CYCLE_COUNTER(STAT_CryptoNet_Initialize);
	
	// Read ini file, to see if crypto is enabled
	GConfig->GetBool(
		TEXT("CryptoNet"),
		TEXT("bEnableCrypto"),
		bEnableCrypto,
		GEngineIni
	);
	
	bEnableCrypto = true;

	// If crypto is disabled, don't initialize it
	if (!bEnableCrypto)
	{
		UE_LOG(LogCryptoNet, Log, TEXT("Crypto disabled"));
		Initialized();
		return;
	}

	// Tell the user what to do !
	UE_LOG(LogCryptoNet, Log, TEXT("Crypto enabled ! Initializing..."));
	
	if (Handler->Mode == Handler::Mode::Server)
	{
		// openssl genrsa -out private-key.pem 2048 | openssl rsa -in private.pem -outform PEM -pubout -out public-key.pem

		const FString PrivateKeyPath = FPaths::ProjectSavedDir() / "private-key.pem";
		FFileHelper::LoadFileToArray(PrivateKeyPEM, *PrivateKeyPath);
	}
}

bool CryptoNetHandlerComponent::IsValid() const
{
	return true;
}

void CryptoNetHandlerComponent::Incoming(FBitReader& Packet)
{
	QUICK_SCOPE_CYCLE_COUNTER(STAT_CryptoNet_Incoming);
	
	if (!bEnableCrypto) return;

	// Read first bit. If it's a 1, it's the key exchange. If it's a 0, it's a ciphered message
	const uint8 FirstBit = Packet.ReadBit();
	
	if (Packet.GetBytesLeft() == 0) return;

	// If it's the new key, decipher it !
	if (FirstBit == 1 && !bSymmetricKeyShared && Handler->Mode == Handler::Mode::Server)
	{
		// Get cipher
		TArray<uint8> Cipher;
		Cipher.SetNum(Packet.GetBytesLeft());
		Packet.Serialize(Cipher.GetData(), Packet.GetBytesLeft());

		// Decipher it
		TArray<uint8> PlainTextWithHash;
		AsymmetricDecryptWithPrivate(Cipher, PlainTextWithHash);

		// Extract the actual readable data (aka remove the hash)
		TArray<uint8> Plaintext = PlainTextWithHash;

		// Write out to symmetric key and IV
#if SYM_MODE_CUSTOM_CTS
		SetSymmetricKey(TArray<uint8>(Plaintext.GetData(), SYM_KEY_SIZE / 8));
#else
		auto* AlgoModeOpenSSL = OpenSSL::ALGO_MODE_OPENSSL();
		SetSymmetricKey(TArray<uint8>(Plaintext.GetData(), AlgoModeOpenSSL->key_len));
		IV = TArray<uint8>(Plaintext.GetData() + AlgoModeOpenSSL->key_len, AlgoModeOpenSSL->iv_len);
#endif

		// Go !
		bSymmetricKeyShared = true;
		Initialized();

		// Tell the engine not to use this packet
		Packet = FBitReader();
		return;
	}
	// If it's a classic ciphered message, and the key has been received, decipher it !
	else if (FirstBit == 0 && bSymmetricKeyShared)
	{
#if PACKET_STATS
		TotalCipheredBitsRecv += Packet.GetBitsLeft();
#endif

		// Get cipher text from packet, and init plaintext buffer
		TArray<uint8> Ciphertext;
		Ciphertext.SetNum(Packet.GetBytesLeft());
		Packet.SerializeBits(Ciphertext.GetData(), Packet.GetBitsLeft());
		
		TArray<uint8> PlaintextWithHash;
		SymmetricDecrypt(Ciphertext, PlaintextWithHash);

		// Hash-related things
		TArray<uint8> Plaintext = PlaintextWithHash;

		// Overwrite the old packet
		Packet = FBitReader(Plaintext.GetData(), Plaintext.Num() * 8);

#if PACKET_STATS
		TotalPlaintextBitsRecv += Packet.GetBitsLeft();
#endif
	}
	// Error
	else
	{
		UE_LOG(PacketHandlerLog, Error, TEXT("CryptoNetHandlerComponent::Incoming: Error"));
		Packet.SetData(nullptr, 0);
		return;
	}
}

void CryptoNetHandlerComponent::Outgoing(FBitWriter& Packet, FOutPacketTraits& Traits)
{
	QUICK_SCOPE_CYCLE_COUNTER(STAT_CryptoNet_Outgoing);
	
	if (!bEnableCrypto) return;

	// If Symmetric key was not shared, we can't decipher the message. Return an error
	if (!bSymmetricKeyShared)
	{
		UE_LOG(PacketHandlerLog, Error, TEXT("CryptoNetHandlerComponent::Outgoing: Error: The symmetric key wasn't shared (yet?)"));
		Packet = FBitWriter();
		return;
	}
	
#if PACKET_STATS
	TotalPlaintextBitsSent += Packet.GetNumBits();
#endif

	// Compute and insert the hash
	TArray<uint8> Plaintext(Packet.GetData(), Packet.GetNumBytes());
	TArray<uint8> PlaintextWithHash(Plaintext);

	// Cipher it
	TArray<uint8> BytesCiphertext;
	SymmetricEncrypt(PlaintextWithHash, BytesCiphertext);

	// Overwrite the old packet
	Packet = FBitWriter(BytesCiphertext.Num() * 8 + 1);
	Packet.WriteBit(0); // <- This zero means it's a ciphered message (so not the key exchange)
	Packet.Serialize(BytesCiphertext.GetData(), BytesCiphertext.Num());

#if PACKET_STATS
	TotalCipheredBitsSent += Packet.GetNumBits();
#endif
}

int32 CryptoNetHandlerComponent::GetReservedPacketBits() const
{
	if (!bEnableCrypto) return 0;

	int32 ReservedCount = 0;

	// Just one bit to know if it's the encryption key or not
	ReservedCount += 1;
	// Block count
#if SYM_MODE_CUSTOM_CTS
	ReservedCount += SYM_ALGO(_BLOCK_SIZE) * 8;
#else
	const OpenSSL::evp_cipher_st* AlgoModeOpenSSL = OpenSSL::ALGO_MODE_OPENSSL();
	ReservedCount += AlgoModeOpenSSL->block_size * 8;
#endif

	return ReservedCount;
}

void CryptoNetHandlerComponent::NotifyHandshakeBegin()
{
	QUICK_SCOPE_CYCLE_COUNTER(STAT_CryptoNet_Handshake);
	
	if (!bEnableCrypto) return;

	// The server sends the asymmetric key
	if (Handler->Mode == Handler::Mode::Client)
	{
		// Generate key
		TArray<uint8> NewSymmetricKey;

#if SYM_MODE_CUSTOM_CTS
		NewSymmetricKey.SetNum(SYM_KEY_SIZE / 8);
#else
		const OpenSSL::evp_cipher_st* AlgoModeOpenSSL = OpenSSL::ALGO_MODE_OPENSSL();
		NewSymmetricKey.SetNum(AlgoModeOpenSSL->key_len);
#endif
		OpenSSL::RAND_bytes(NewSymmetricKey.GetData(), NewSymmetricKey.Num());
		SetSymmetricKey(NewSymmetricKey);

		// Generate IV
#if !SYM_MODE_CUSTOM_CTS
		IV.SetNum(AlgoModeOpenSSL->iv_len);
		OpenSSL::RAND_bytes(IV.GetData(), IV.Num());
#endif

		// Gen the plaintext to encrypt
		TArray<uint8> Plaintext;
		Plaintext.Append(NewSymmetricKey);
		Plaintext.Append(IV);

		// Encode the cipher to bin data
		TArray<uint8> BinDataToSend;
		AsymmetricEncryptWithPublic(Plaintext, BinDataToSend);

		// Write bin data to packet
		FBitWriter OutPacket;
		OutPacket.SetAllowResize(true);
		OutPacket.AllowAppend(true);
		OutPacket.WriteBit(1);
		OutPacket.Serialize(BinDataToSend.GetData(), BinDataToSend.Num());

		// Send
		FOutPacketTraits Traits;
		Handler->SendHandlerPacket(this, OutPacket, Traits);

		// Go !
		UE_LOG(LogCryptoNet, Log, TEXT("Client sent handshake !"));
		bSymmetricKeyShared = true;
		Initialized();
	}
}
