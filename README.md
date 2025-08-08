

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y build-essential libssl-dev libcurl4-openssl-dev libsecp256k1-dev git make
```


2. **Build the scanner:**
   ```bash
   make scanner
   ```


#### 1. Basic Scan
```bash
./scanner 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa 10000000:1fffffff
```

#### 2. Custom Threads and Stats Interval
```bash
./scanner -s 5 -t 8 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa 10000000:1fffffff
```

#### 3. Large Range Scan
```bash
./scanner 15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP 8000000000000000000000000000000000000000:ffffffffffffffffffffffffffffffffffffffff
```

### Range Format

The key range must be specified in hexadecimal format:
- **Format**: `START:END`
- **Example**: `10000000:1fffffff`
- **Maximum**: Up to 64-character hex strings (256-bit)



#### 1. Compilation Errors
```bash
# Missing dependencies
sudo apt install libssl-dev libcurl4-openssl-dev libsecp256k1-dev
```

#### 2. libcurl Warning
```bash
# This warning is harmless and can be ignored
./scanner: /usr/local/lib/libcurl.so.4: no version information available
```


#### 3. Low Performance
- Increase thread count: `-t 16`
- Use smaller ranges for testing
- Close other CPU-intensive applications

### Error Messages

| Error | Solution |
|-------|----------|
| `Invalid address checksum` | Check Bitcoin address format |
| `Invalid range format` | Use START:END format in hex |
| `Failed to create secp256k1 context` | Install libsecp256k1-dev |
| `Unknown option` | Check command line syntax |

