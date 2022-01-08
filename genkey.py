#!/usr/bin/env python3

import cpm

if __name__ == "__main__":
    key = cpm.genkey()
    keyfile = "key.bin"
    print(f"Secret key: {cpm.b2a(key)}")
    f = open(keyfile, "wb")
    f.write(key)
    f.close()
    print(f"Saved to: {keyfile}")
