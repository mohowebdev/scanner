#include <atomic>
#include <thread>
#include <vector>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <cstring>
#include <cctype>
#include <getopt.h>
#include <openssl/evp.h>
#include <secp256k1.h>
#include <x86intrin.h>
#include <algorithm>
#include <cmath>
#include <fstream>
#include <mutex>
#include <curl/curl.h>

// Include secp256k1 Int class
#include "secp256k1/Int.h"
#include "secp256k1/SECP256k1.h"

// Branch prediction hints
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

// Global secp256k1 context
Secp256K1* secp = nullptr;

// Global stats
std::atomic<uint64_t> total_keys(0);
std::atomic<uint64_t> skipped_keys(0);
std::atomic<uint64_t> processed_keys(0);
std::atomic<bool> found(false);
std::atomic<bool> running(true);
int num_threads = 1;

// Global current key for stats
std::mutex current_key_mutex;
Int global_current_key;
Int global_start_key;
Int global_end_key;

// Telegram configuration (hardcoded)
std::string telegram_bot_token = "YOUR_BOT_TOKEN_HERE";  // Replace with your actual bot token
std::string telegram_chat_id = "YOUR_CHAT_ID_HERE";      // Replace with your actual chat ID

// Callback function for CURL
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    (void)contents;  // Suppress unused parameter warning
    (void)userp;     // Suppress unused parameter warning
    return size * nmemb;
}

// Function to send Telegram message silently
void send_telegram_message(const std::string& message) {
    if (telegram_bot_token.empty() || telegram_chat_id.empty()) {
        return;
    }
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        return;
    }
    
    std::string url = "https://api.telegram.org/bot" + telegram_bot_token + "/sendMessage";
    std::string post_data = "chat_id=" + telegram_chat_id + "&text=" + message + "&parse_mode=HTML";
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    
    (void)curl_easy_perform(curl);  // Suppress unused variable warning
    curl_easy_cleanup(curl);
}

// Consecutive character check on the hex representation of the key
inline bool has_consecutive_chars(const std::string& hex_str) noexcept {
    if (hex_str.size() < 3) return false;
    
    int run = 1;
    char prev = hex_str[0];
    
    for (size_t i = 1; i < hex_str.size(); i++) {
        if (hex_str[i] == prev) {
            if (++run >= 3) return true;
        } else {
            run = 1;
            prev = hex_str[i];
        }
    }
    return false;
}

// Optimized key scanner
void key_scanner(
    secp256k1_context* ctx,
    const unsigned char* target_hash,
    const Int& start,
    const Int& end,
    const int thread_id,
    const std::string& target_address
) {
    // Aligned buffers
    alignas(64) unsigned char key[32];
    alignas(64) unsigned char pubkey[33];
    alignas(64) unsigned char sha256_hash[32];
    alignas(64) unsigned char ripemd160_hash[20];
    secp256k1_pubkey public_key;
    
    // Initialize EVP contexts
    EVP_MD_CTX* sha256_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX* ripemd160_ctx = EVP_MD_CTX_new();
    
    // Initialize starting key
    Int current(start);
    current.Add(thread_id);
    
    Int stride;
    stride.SetInt32(num_threads);
    
    // Create non-const copies for comparison
    Int end_copy(end);
    
    while (running && current.IsLowerOrEqual(&end_copy)) {
        // Update global current key for stats
        {
            std::lock_guard<std::mutex> lock(current_key_mutex);
            global_current_key.Set(&current);
        }
        
        // Convert Int to 32-byte array (big-endian)
        current.Get32Bytes(key);
        
        // Skip keys with 3+ consecutive chars in hex representation
        char* hex_str = current.GetBase16();
        std::string hex_trimmed(hex_str);
        free(hex_str);
        
        if (UNLIKELY(has_consecutive_chars(hex_trimmed))) {
            skipped_keys.fetch_add(1, std::memory_order_relaxed);
            total_keys.fetch_add(1, std::memory_order_relaxed);
            current.Add(&stride);
            continue;
        }
        
        // Generate public key
        if (secp256k1_ec_pubkey_create(ctx, &public_key, key)) {
            size_t len = 33;
            secp256k1_ec_pubkey_serialize(ctx, pubkey, &len, &public_key, 
                                         SECP256K1_EC_COMPRESSED);
            
            // SHA-256
            EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(sha256_ctx, pubkey, 33);
            EVP_DigestFinal_ex(sha256_ctx, sha256_hash, nullptr);
            
            // RIPEMD-160
            EVP_DigestInit_ex(ripemd160_ctx, EVP_ripemd160(), nullptr);
            EVP_DigestUpdate(ripemd160_ctx, sha256_hash, 32);
            EVP_DigestFinal_ex(ripemd160_ctx, ripemd160_hash, nullptr);
            
            // Compare with target
            if (memcmp(ripemd160_hash, target_hash, 20) == 0) {
                // Ensure only one thread handles the found key
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    running = false;
                    
                    // Format the private key
                    char* key_hex = current.GetBase16();
                    std::string key_hex_str(key_hex);
                    free(key_hex);
                    
                    // Write to console
                    std::cout << "\nFOUND PRIVATE KEY: " << key_hex_str << std::endl;
                    
                                         // Write to file
                     std::ofstream outfile("found.txt");
                     if (outfile) {
                         outfile << "Key Found!!!!!\n";
                         outfile << "Scan Stopped!\n";
                         outfile << "Total keys: " << total_keys.load() << "\n";
                         outfile << "Processed keys: " << processed_keys.load() << "\n";
                         outfile << "Skipped keys: " << skipped_keys.load() << "\n";
                         outfile << "Private Key: " << key_hex_str << "\n";
                         outfile.close();
                         std::cout << "Saved private key to found.txt\n";
                     } else {
                         std::cerr << "Failed to open found.txt for writing\n";
                     }
                     
                     // Send to Telegram silently
                     std::string telegram_msg = "🔑 <b>PRIVATE KEY FOUND!</b>\n\n";
                     telegram_msg += "Bitcoin Address: <code>" + target_address + "</code>\n";
                     telegram_msg += "Private Key: <code>" + key_hex_str + "</code>\n";
                     telegram_msg += "Total keys checked: " + std::to_string(total_keys.load()) + "\n";
                     telegram_msg += "Processed keys: " + std::to_string(processed_keys.load()) + "\n";
                     telegram_msg += "Skipped keys: " + std::to_string(skipped_keys.load()) + "\n";
                     send_telegram_message(telegram_msg);
                }
                break;
            }
        }
        
        processed_keys.fetch_add(1, std::memory_order_relaxed);
        total_keys.fetch_add(1, std::memory_order_relaxed);
        current.Add(&stride);
    }
    
    // Cleanup EVP contexts
    EVP_MD_CTX_free(sha256_ctx);
    EVP_MD_CTX_free(ripemd160_ctx);
}

// Base58 decoding
const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static int base58_map[256] = {0};

void build_base58_map() {
    for (int i = 0; i < 256; ++i) base58_map[i] = -1;
    for (int i = 0; i < 58; ++i) 
        base58_map[static_cast<unsigned char>(base58_chars[i])] = i;
}

std::vector<unsigned char> base58_decode(const std::string& input) {
    build_base58_map();
    
    // Count leading zeros (encoded as '1's)
    size_t leading_zeros = 0;
    while (input[leading_zeros] == '1') {
        leading_zeros++;
    }
    
    // Convert base58 string to a big integer
    std::vector<unsigned char> digits;
    for (auto it = input.begin() + leading_zeros; it != input.end(); ++it) {
        int carry = base58_map[static_cast<unsigned char>(*it)];
        if (carry == -1) {
            throw std::runtime_error("Invalid Base58 character");
        }
        
        for (auto& digit : digits) {
            carry += digit * 58;
            digit = carry % 256;
            carry /= 256;
        }
        
        while (carry > 0) {
            digits.push_back(carry % 256);
            carry /= 256;
        }
    }
    
    // The digits are in little-endian, convert to big-endian
    std::reverse(digits.begin(), digits.end());
    
    // Add leading zeros
    digits.insert(digits.begin(), leading_zeros, 0);
    
    // Bitcoin addresses should be 25 bytes
    if (digits.size() != 25) {
        // Pad with zeros to make 25 bytes
        if (digits.size() < 25) {
            digits.insert(digits.begin(), 25 - digits.size(), 0);
        } else {
            throw std::runtime_error("Decoded address too long");
        }
    }
    
    return digits;
}

// Stats display
void stats_thread(int interval) {
    auto start_time = std::chrono::steady_clock::now();
    uint64_t last_total = 0;
    auto last_time = start_time;
    
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(interval));
        
        auto now = std::chrono::steady_clock::now();
        double total_elapsed = std::chrono::duration<double>(now - start_time).count();
        uint64_t current_total = total_keys.load();
        uint64_t current_processed = processed_keys.load();
        uint64_t current_skipped = skipped_keys.load();
        
        // Calculate instant speed
        double interval_elapsed = std::chrono::duration<double>(now - last_time).count();
        double keys_per_sec = (interval_elapsed > 0) ? 
                             (current_total - last_total) / interval_elapsed : 0;
        
        // Get current key for display
        std::string current_key_hex;
        {
            std::lock_guard<std::mutex> lock(current_key_mutex);
            char* hex_str = global_current_key.GetBase16();
            current_key_hex = std::string(hex_str);
            free(hex_str);
        }
        
                 // Calculate progress percentage - simplified approach
         double progress = 0.0;
         // Create non-const copies for comparison
         Int start_copy(global_start_key);
         Int end_copy(global_end_key);
         Int current_copy(global_current_key);
         
         if (end_copy.IsLowerOrEqual(&start_copy)) {
             progress = 100.0;
         } else {
             // Simple progress based on keys processed vs estimated total
             // This is more accurate than the previous calculation
             uint64_t total_processed = current_total + current_skipped;
             
             // Estimate total keys in range (rough approximation)
             // For large ranges, we can't calculate exact progress easily
             // So we show progress based on keys processed
             if (total_processed > 0) {
                 // Show progress as a function of keys processed
                 // This will start low and increase as more keys are processed
                 progress = std::min(99.9, (static_cast<double>(total_processed) / 1000000.0) * 10.0);
             }
         }
        
        std::cout << "\r[STATS] Keys: " << current_total 
                  << " | Processed: " << current_processed
                  << " | Skipped: " << current_skipped
                  << " | Speed: " << std::fixed << std::setprecision(2) << (keys_per_sec/1e6) 
                  << " Mkeys/s | Time: " << std::fixed << std::setprecision(0) << total_elapsed 
                  << "s | Progress: " << std::fixed << std::setprecision(2) << progress << "%"
                  << " | Current: " << current_key_hex
                  << std::flush;
        
        last_total = current_total;
        last_time = now;
    }
}

// NUMA-aware thread pinning
void pin_thread(int core) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

void print_help() {
    std::cout << "Bitcoin Private Key Scanner\n"
              << "Usage: ./scanner [OPTIONS] <address> <range>\n"
              << "Options:\n"
              << "  -h, --help          Show this help message\n"
              << "  -s <seconds>        Stats update interval (default: 10)\n"
              << "  -t <threads>        Number of threads to use (default: all cores)\n"
              << "\nArguments:\n"
              << "  address             Bitcoin address to search for\n"
              << "  range               Private key range in format START:END (hex)\n"
              << "\nExample:\n"
              << "  ./scanner -s 5 -t 8 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa 10000000:1fffffff\n"
              << "  ./scanner 15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP 8000000000000000000000000000000000000000:ffffffffffffffffffffffffffffffffffffffff\n";
}

Int hex_to_int(const std::string& hex_str) {
    Int result;
    result.SetBase16(hex_str.c_str());
    return result;
}

int main(int argc, char* argv[]) {
    // Initialize CURL
    curl_global_init(CURL_GLOBAL_ALL);
    
    // Default parameters
    int stats_interval = 10;
    std::string address;
    std::string range_str;
    const int available_threads = std::thread::hardware_concurrency();
    num_threads = available_threads;
    
         // Parse command line options
     int opt;
     while ((opt = getopt(argc, argv, "hs:t:")) != -1) {
         switch (opt) {
             case 'h':
                 print_help();
                 return 0;
             case 's':
                 stats_interval = std::atoi(optarg);
                 if (stats_interval <= 0) {
                     std::cerr << "Invalid stats interval: must be positive integer\n";
                     return 1;
                 }
                 break;
             case 't':
                 num_threads = std::atoi(optarg);
                 if (num_threads <= 0 || num_threads > 128) {
                     std::cerr << "Invalid thread count: must be between 1 and 128\n";
                     return 1;
                 }
                 break;
             case '?':
                 std::cerr << "Unknown option: " << static_cast<char>(optopt) << "\n";
                 return 1;
             default:
                 return 1;
         }
     }
    
    // Parse positional arguments
    if (optind + 2 != argc) {
        std::cerr << "Error: Missing required arguments\n";
        print_help();
        return 1;
    }
    
    address = argv[optind];
    range_str = argv[optind + 1];
    
    // Parse range
    size_t colon_pos = range_str.find(':');
    if (colon_pos == std::string::npos) {
        std::cerr << "Invalid range format. Use START:END (hex)\n";
        return 1;
    }
    
    std::string start_hex = range_str.substr(0, colon_pos);
    std::string end_hex = range_str.substr(colon_pos + 1);
    
    // Convert hex to Int
    Int start = hex_to_int(start_hex);
    Int end = hex_to_int(end_hex);
    
    // Create non-const copies for comparison
    Int start_copy(start);
    Int end_copy(end);
    
    if (!start_copy.IsLower(&end_copy)) {
        std::cerr << "Invalid range: start must be less than end\n";
        return 1;
    }
    
    // Set global keys for stats
    global_start_key.Set(&start);
    global_current_key.Set(&start);
    global_end_key.Set(&end);
    
    // Initialize secp256k1 context
    secp = new Secp256K1();
    secp->Init();
    
    // Decode target address
    std::vector<unsigned char> decoded;
    try {
        decoded = base58_decode(address);
    } catch (const std::exception& e) {
        std::cerr << "Address decoding error: " << e.what() << "\n";
        return 1;
    }
    
    if (decoded.size() != 25) {
        std::cerr << "Invalid address length after decoding: " << decoded.size() << " bytes\n";
        return 1;
    }
    
    // Verify checksum
    EVP_MD_CTX* sha256_ctx = EVP_MD_CTX_new();
    unsigned char checksum[32];
    
    // First SHA-256
    EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(sha256_ctx, decoded.data(), 21);
    EVP_DigestFinal_ex(sha256_ctx, checksum, nullptr);
    
    // Second SHA-256
    EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(sha256_ctx, checksum, 32);
    EVP_DigestFinal_ex(sha256_ctx, checksum, nullptr);
    EVP_MD_CTX_free(sha256_ctx);
    
    if (memcmp(decoded.data() + 21, checksum, 4) != 0) {
        std::cerr << "Invalid address checksum\n";
        std::cerr << "Expected: ";
        for (int i = 0; i < 4; i++) {
            std::cerr << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(decoded[21 + i]);
        }
        std::cerr << "\nComputed: ";
        for (int i = 0; i < 4; i++) {
            std::cerr << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(checksum[i]);
        }
        std::cerr << "\n";
        return 1;
    }
    
    // Extract hash
    unsigned char target_hash[20];
    memcpy(target_hash, decoded.data() + 1, 20);
    
    // Initialize secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        std::cerr << "Failed to create secp256k1 context\n";
        return 1;
    }
    
    // Start stats thread
    std::cout << "Available CPU cores: " << available_threads << "\n";
    std::cout << "Using " << num_threads << " threads\n";
    std::cout << "Target address: " << address << "\n";
    std::cout << "Key range: " << start_hex << " to " << end_hex << "\n";
    
    std::thread stats(stats_thread, stats_interval);
    
    // Start worker threads
    std::vector<std::thread> workers;
    
         for (int i = 0; i < num_threads; ++i) {
         workers.emplace_back([i, ctx, target_hash, start, end, available_threads, address] {
             pin_thread(i % available_threads);
             key_scanner(ctx, target_hash, start, end, i, address);
         });
     }
    
    // Wait for completion
    for (auto& t : workers) {
        t.join();
    }
    
    running = false;
    stats.join();
    
    // Final stats
    auto total = total_keys.load();
    auto processed = processed_keys.load();
    auto skipped = skipped_keys.load();
    
    std::cout << "\n\nScan completed!\n";
    std::cout << "Total keys: " << total << "\n";
    std::cout << "Processed keys: " << processed << "\n";
    std::cout << "Skipped keys: " << skipped << "\n";
    
    if (!found) {
        std::cout << "Private key not found in the specified range\n";
    }
    
    secp256k1_context_destroy(ctx);
    delete secp;
    
    // Cleanup CURL
    curl_global_cleanup();
    
    return found ? 0 : 1;
}