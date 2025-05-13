# Cipherless_relay
Seed-based “book cipher” mapping secret text into a deterministic pseudo-random text stream. You share only an opaque pointer and encrypted phrase. The recipient uses the same seed to regenerate the block, force in the phrase, and extract it. Without the seed, the message is unrecoverable.
