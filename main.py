import hashlib
import random

# ---- Global Configuration ----
global_seed = None  # Will be set by user input or default
block_size = 1024  # Characters per block.
character_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;?!\n"

# ---- Deterministic Text Generation ----
def generate_block(block_index, block_size=block_size):
    """
    Generate a block of text deterministically based on the global seed and block_index.
    """
    if global_seed is None:
        raise ValueError("Global seed has not been set.")
    combined_seed = f"{global_seed}-{block_index}"
    seed_val = int(hashlib.sha256(combined_seed.encode('utf-8')).hexdigest(), 16)
    rnd = random.Random(seed_val)
    text = ''.join(rnd.choice(character_set) for _ in range(block_size))
    return text

# ---- Location Pointer Encoding & Decoding ----
def encode_location(block_index, offset, block_size=block_size):
    """
    Encode a location (block_index, offset) into an opaque hexadecimal string.
    """
    if global_seed is None:
        raise ValueError("Global seed has not been set.")
    loc_value = block_index * block_size + offset
    key = int(hashlib.sha256(global_seed.encode('utf-8')).hexdigest(), 16) & ((1 << 64) - 1)
    encrypted = loc_value ^ key
    pointer_location = hex(encrypted)[2:]  # Remove the '0x' prefix.
    return pointer_location

def decode_location(pointer_location, block_size=block_size):
    """
    Decode the hexadecimal pointer location back into (block_index, offset).
    """
    if global_seed is None:
        raise ValueError("Global seed has not been set.")
    encrypted = int(pointer_location, 16)
    key = int(hashlib.sha256(global_seed.encode('utf-8')).hexdigest(), 16) & ((1 << 64) - 1)
    loc_value = encrypted ^ key
    block_index = loc_value // block_size
    offset = loc_value % block_size
    return block_index, offset

# ---- Mapping a Phrase to a Location (Forced Injection) ----
def map_phrase_to_location(phrase):
    """
    Deterministically map a phrase to a block index and an offset within that block.
    """
    if global_seed is None:
        raise ValueError("Global seed has not been set.")
    h = int(hashlib.sha256((phrase + global_seed).encode('utf-8')).hexdigest(), 16)
    block_index = h % 100000  # Maps into a space of 100,000 blocks.
    offset = (h >> 32) % (block_size - len(phrase))  # Ensure the phrase fits in the block.
    return block_index, offset

# ---- Simple XOR Encryption for the Phrase ----
def encrypt_phrase(phrase):
    """
    Encrypt the phrase using a key derived from the global seed.
    """
    if global_seed is None:
        raise ValueError("Global seed has not been set.")
    key = hashlib.sha256(global_seed.encode('utf-8')).digest()
    phrase_bytes = phrase.encode('utf-8')
    encrypted = bytearray()
    for i, b in enumerate(phrase_bytes):
        encrypted.append(b ^ key[i % len(key)])
    return encrypted.hex()

def decrypt_phrase(encrypted_hex):
    """
    Decrypt the phrase using the global seed.
    """
    if global_seed is None:
        raise ValueError("Global seed has not been set.")
    key = hashlib.sha256(global_seed.encode('utf-8')).digest()
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted = bytearray()
    for i, b in enumerate(encrypted_bytes):
        decrypted.append(b ^ key[i % len(key)])
    return decrypted.decode('utf-8')

# ---- Generating a Block with Forced Injection of the Phrase ----
def generate_block_with_phrase(block_index, offset, phrase):
    """
    Generate the block at block_index, but force the given phrase into the block at offset.
    """
    text = list(generate_block(block_index))
    text[offset:offset+len(phrase)] = phrase  # Overwrite with the forced phrase.
    return ''.join(text)

# ---- CLI Interface Functions ----
def search_phrase(phrase):
    """
    'Search' mode: deterministically compute where to force the phrase.
    Returns an opaque pointer that encodes the location and the encrypted phrase.
    """
    block_index, offset = map_phrase_to_location(phrase)
    pointer_location = encode_location(block_index, offset)
    encrypted_phrase = encrypt_phrase(phrase)
    pointer = f"{pointer_location}:{encrypted_phrase}"
    return pointer

def get_text_from_pointer(pointer, window=100):
    """
    'Get' mode: Given a pointer, decode it to obtain the block index, offset, and phrase.
    Then generate the block with forced injection and return a snippet around the phrase.
    """
    try:
        pointer_location, encrypted_phrase = pointer.split(":")
    except ValueError:
        print("Invalid pointer format. Expected format: <location>:<encrypted_phrase>")
        return None
    phrase = decrypt_phrase(encrypted_phrase)
    block_index, offset = decode_location(pointer_location)
    block_text = generate_block_with_phrase(block_index, offset, phrase)
    start = max(0, offset - window//2)
    end = min(len(block_text), offset + window//2)
    return block_text[start:end], block_index, offset, phrase

# ---- Main CLI Interface ----
if __name__ == '__main__':
    user_seed = input("Enter a seed (or press Enter for default 'geeeegg'): ").strip()
    if not user_seed:
        global_seed = "geeeegg"
    else:
        global_seed = user_seed
    print(f"Using seed: {global_seed}")

    mode = input("Enter mode (search/get): ").strip().lower()
    if mode == "search":
        phrase = input("Enter text to search for: ")
        pointer = search_phrase(phrase)
        print(f"Location pointer:\n{pointer}")
    elif mode == "get":
        pointer = input("Enter location pointer: ").strip()
        result = get_text_from_pointer(pointer)
        if result:
            snippet, block_index, offset, phrase = result
            print(f"Text from block {block_index} (offset {offset}) with forced phrase '{phrase}':\n")
            print(snippet)
    else:
        print("Invalid mode. Use 'search' to map a phrase or 'get' to retrieve text from a pointer.")

