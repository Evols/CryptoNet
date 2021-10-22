
# CryptoNet

## Description

CryptoNet encrypts your game's network traffic (all the things that are replicated, both RPC and variables) to prevent hackers from exploiting its network traffic. As CryptoNet works on top of replication, you don’t have to modify any of your game's code. Just plug it in, configure it, and your game's network is now safe!

CryptoNet is built to resist eavesdropping (hackers can't read your network traffic) and MITM attacks (hackers can’t alter your network traffic). As CryptoNet was made with modularity in mind, you can tweak the encryption parameters, and choose how secure you want your game to be. This way, the security level perfectly fits your needs, in terms of both performance and security.

The plugin is provided with encryption that should be strong enough for most games. So, even if you don't know a lot about cybersecurity, you can be assured your game will still be secure, even with the defaults settings.

## Technical details

Features:
- Encrypts your game's network traffic
- Keep your code as it is! CryptoNet works on top of UE4 replication, so it's totally independant from your code
- Uses symmetric cryptography to encrypt your network traffic, and asymmetric cryptography to exchange the symmetric key
- Verifies packets integrity using hashes, so you're sure they haven't been modified by a hacker
- Highly customisable: you can change the symmetric algorithm, key sizes, and hash sizes, in one line each
- Code Modules: CryptoNet (Runtime)

Documentation: See [DOCS.md](./DOCS.md)
