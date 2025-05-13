# Secure Seed-Based Messaging

A seed-driven “book cipher” that hides your message in a deterministic pseudo-random text stream. Instead of sending encrypted files, you share a short hex pointer plus an encrypted phrase. With the same seed, the recipient regenerates just the right block of text, forces in the phrase, and extracts it.

---

## How It Works

1. **Agree on a seed**  
   You and your correspondent pick a secret string (the seed).

2. **Generate text blocks**  
   - Each block (default 1024 characters) is created by hashing `seed + block_index`.  
   - A pseudo-random generator uses that hash to produce the block on demand.

3. **Map phrase to location**  
   - Hash `phrase + seed` to pick a block index and offset within it.  
   - Compute a numeric location = `block_index * block_size + offset`.

4. **Create an opaque pointer**  
   - XOR that location with a 64-bit key derived from the seed hash.  
   - Encode the result in hex.

5. **Encrypt the phrase**  
   - XOR each byte of your phrase with a repeating key from `SHA-256(seed)`.  
   - Convert to hex and append after the pointer, separated by `:`.

6. **Retrieve the message**  
   - Split the pointer and encrypted phrase by `:`.  
   - Reverse the XOR on the location to get `block_index` and `offset`.  
   - Regenerate that block, overwrite it with the decrypted phrase, and extract your message.

---

## Quickstart

git clone https://github.com/gitgitgitgitgitgitgitgitgitgitgitgit/Cipherless_relay/tree/main
cd secure-seed-messaging
python3 main.py


Enter a seed (or press Enter for default).

Choose mode

search: enter the text you want to hide → get a pointer string

get : paste the pointer → get back the hidden text snippet

Requirements  
Python 3.7 or later  
Uses only standard library modules (hashlib, random, etc.)

License  
All rights reserved. See LICENSE.
