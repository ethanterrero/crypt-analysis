#include "server.h"
#include "httplib.h"

#include "crypto/aes_cipher.h"
#include "crypto/chacha_cipher.h"
#include "benchmark/profiler.h"
#include "analysis/avalanche.h"
#include "analysis/entropy.h"
#include "analysis/frequency.h"

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal JSON helpers — avoids pulling in a JSON library
// ---------------------------------------------------------------------------

static std::string json_bool(bool v) { return v ? "true" : "false"; }

static std::string json_str(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    out += "\"";
    return out;
}

// ---------------------------------------------------------------------------
// Run all tests and build the JSON result string
// ---------------------------------------------------------------------------

static std::string run_test(const std::string& cipher_str,
                             const std::string& file_name,
                             const std::vector<uint8_t>& plaintext)
{
    const std::string TEST_KEY = "crypt-analysis-test-key-2024";

    // Select cipher
    std::unique_ptr<Encryptor> encryptor;
    CipherType cipher_type;
    std::string cipher_label;

    if (cipher_str == "chacha20") {
        encryptor   = std::make_unique<ChaChaCipher>();
        cipher_type = CipherType::CHACHA20;
        cipher_label = "ChaCha20";
    } else {
        encryptor   = std::make_unique<AesCipher>();
        cipher_type = CipherType::AES256_CBC;
        cipher_label = "AES-256";
    }

    // --- Integrity + Performance ---
    std::vector<uint8_t> ciphertext, decrypted;

    Profiler enc_prof, dec_prof;

    enc_prof.start();
    bool enc_ok = encryptor->encrypt(plaintext, TEST_KEY, ciphertext);
    enc_prof.stop();

    bool dec_ok = false;
    if (enc_ok) {
        dec_prof.start();
        dec_ok = encryptor->decrypt(ciphertext, TEST_KEY, decrypted);
        dec_prof.stop();
    }

    bool roundtrip = enc_ok && dec_ok && (decrypted == plaintext);

    // --- Analysis (only on successful ciphertext) ---
    EntropyResult   ent{};
    FrequencyResult freq{};
    AvalancheResult aval{};
    bool entropy_ok   = false;
    bool frequency_ok = false;
    bool avalanche_ok = false;

    if (enc_ok && !ciphertext.empty()) {
        ent  = measure_entropy(ciphertext);
        freq = run_frequency_test(ciphertext);
        entropy_ok   = true;
        frequency_ok = true;
    }

    // Avalanche uses the uploaded plaintext as its test input
    if (!plaintext.empty()) {
        size_t bits = std::min(plaintext.size() * 8, size_t(256));
        aval = run_avalanche_test(cipher_type, plaintext, bits);
        avalanche_ok = true;
    }

    // --- Derive pass/fail ---
    bool integrity_pass = roundtrip;
    bool entropy_pass   = entropy_ok && (ent.entropy >= 7.0);
    bool freq_pass      = frequency_ok && (freq.p_value >= 0.05 && freq.p_value <= 0.95);

    // Avalanche: AES-256 should be near 50%; ChaCha20 is ~0% by design
    bool aval_applicable = (cipher_type == CipherType::AES256_CBC);
    bool aval_pass = !aval_applicable ||
                     (avalanche_ok && aval.avg_bit_change_pct >= 45.0 && aval.avg_bit_change_pct <= 55.0);
    std::string aval_note = aval_applicable ? ""
        : "Stream ciphers do not have the avalanche property by design. "
          "A ~0% result is correct and expected, not a weakness.";

    // Sizes
    size_t file_size  = plaintext.size();
    size_t ct_size    = ciphertext.size();

    // --- Serialize to JSON ---
    std::ostringstream j;
    j << "{\n";
    j << "  \"cipher\": " << json_str(cipher_label) << ",\n";
    j << "  \"file_name\": " << json_str(file_name) << ",\n";
    j << "  \"file_size_bytes\": " << file_size << ",\n";
    j << "  \"ciphertext_size_bytes\": " << ct_size << ",\n";

    // integrity
    j << "  \"integrity\": {\n";
    j << "    \"passed\": "          << json_bool(integrity_pass) << ",\n";
    j << "    \"encrypt_success\": " << json_bool(enc_ok)         << ",\n";
    j << "    \"decrypt_success\": " << json_bool(dec_ok)         << ",\n";
    j << "    \"roundtrip_match\": " << json_bool(roundtrip)      << "\n";
    j << "  },\n";

    // performance
    j << "  \"performance\": {\n";
    j << "    \"encrypt_seconds\": "       << enc_prof.getSeconds()                         << ",\n";
    j << "    \"encrypt_mb_per_second\": " << enc_prof.getMBPerSecond(file_size)             << ",\n";
    j << "    \"encrypt_cycles\": "        << enc_prof.getTotalCycles()                      << ",\n";
    j << "    \"encrypt_cycles_per_byte\":" << enc_prof.getCyclesPerByte(file_size)          << ",\n";
    j << "    \"decrypt_seconds\": "       << dec_prof.getSeconds()                         << ",\n";
    j << "    \"decrypt_mb_per_second\": " << (dec_ok ? dec_prof.getMBPerSecond(ct_size) : 0.0) << ",\n";
    j << "    \"decrypt_cycles\": "        << dec_prof.getTotalCycles()                      << ",\n";
    j << "    \"decrypt_cycles_per_byte\":" << (dec_ok ? dec_prof.getCyclesPerByte(ct_size) : 0.0) << "\n";
    j << "  },\n";

    // entropy
    j << "  \"entropy\": {\n";
    j << "    \"available\": "           << json_bool(entropy_ok) << ",\n";
    j << "    \"entropy_bits_per_byte\": " << (entropy_ok ? ent.entropy : 0.0)     << ",\n";
    j << "    \"min_byte_freq\": "       << (entropy_ok ? ent.min_byte_freq : 0.0) << ",\n";
    j << "    \"max_byte_freq\": "       << (entropy_ok ? ent.max_byte_freq : 0.0) << ",\n";
    j << "    \"total_bytes\": "         << (entropy_ok ? ent.total_bytes  : 0)    << ",\n";
    j << "    \"passed\": "              << json_bool(entropy_pass) << "\n";
    j << "  },\n";

    // frequency
    j << "  \"frequency\": {\n";
    j << "    \"available\": "         << json_bool(frequency_ok) << ",\n";
    j << "    \"chi_squared\": "       << (frequency_ok ? freq.chi_squared : 0.0) << ",\n";
    j << "    \"p_value\": "           << (frequency_ok ? freq.p_value     : 0.0) << ",\n";
    j << "    \"degrees_of_freedom\": " << (frequency_ok ? freq.degrees_of_freedom : 0) << ",\n";
    j << "    \"total_bytes\": "       << (frequency_ok ? freq.total_bytes  : 0)  << ",\n";
    j << "    \"passed\": "            << json_bool(freq_pass) << "\n";
    j << "  },\n";

    // avalanche
    j << "  \"avalanche\": {\n";
    j << "    \"applicable\": "           << json_bool(aval_applicable) << ",\n";
    j << "    \"available\": "            << json_bool(avalanche_ok)    << ",\n";
    j << "    \"avg_bit_change_pct\": "   << (avalanche_ok ? aval.avg_bit_change_pct : 0.0) << ",\n";
    j << "    \"min_bit_change_pct\": "   << (avalanche_ok ? aval.min_bit_change_pct : 0.0) << ",\n";
    j << "    \"max_bit_change_pct\": "   << (avalanche_ok ? aval.max_bit_change_pct : 0.0) << ",\n";
    j << "    \"std_dev\": "              << (avalanche_ok ? aval.std_dev            : 0.0) << ",\n";
    j << "    \"bits_tested\": "          << (avalanche_ok ? aval.bits_tested         : 0)  << ",\n";
    j << "    \"ciphertext_bits\": "      << (avalanche_ok ? aval.ciphertext_bits      : 0)  << ",\n";
    j << "    \"note\": "                 << json_str(aval_note) << ",\n";
    j << "    \"passed\": "              << json_bool(aval_pass) << "\n";
    j << "  }\n";
    j << "}";

    return j.str();
}

// ---------------------------------------------------------------------------
// HTTP Server
// ---------------------------------------------------------------------------

void run_server(int port) {
    httplib::Server svr;

    // CORS pre-flight
    svr.Options(".*", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin",  "http://localhost:5173");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.status = 204;
    });

    auto add_cors = [](httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin",  "http://localhost:5173");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
    };

    // GET /api/ciphers
    svr.Get("/api/ciphers", [&](const httplib::Request&, httplib::Response& res) {
        add_cors(res);
        res.set_content(R"({"ciphers":["aes256","chacha20"]})", "application/json");
    });

    // GET /health
    svr.Get("/health", [&](const httplib::Request&, httplib::Response& res) {
        add_cors(res);
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    // POST /api/test  (multipart: cipher=<str>, file=<binary>)
    svr.Post("/api/test", [&](const httplib::Request& req, httplib::Response& res) {
        add_cors(res);

        if (!req.has_file("file")) {
            res.status = 400;
            res.set_content(R"({"error":"missing 'file' field"})", "application/json");
            return;
        }

        const auto file_part = req.get_file_value("file");
        std::string file_name = file_part.filename.empty() ? "unknown" : file_part.filename;
        std::vector<uint8_t> plaintext(file_part.content.begin(), file_part.content.end());

        std::string cipher_str = "aes256";
        if (req.has_file("cipher")) {
            cipher_str = req.get_file_value("cipher").content;
        }

        if (plaintext.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"uploaded file is empty"})", "application/json");
            return;
        }

        std::string json_result = run_test(cipher_str, file_name, plaintext);
        res.set_content(json_result, "application/json");
    });

    std::cout << "Crypto test server running on http://localhost:" << port << "\n";
    std::cout << "Dashboard: http://localhost:5173\n";
    std::cout << "Press Ctrl+C to stop.\n";

    svr.listen("127.0.0.1", port);
}
