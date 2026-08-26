// qr_login_manager.cpp
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <json/json.h> // nlohmann/json recommended
#include <qrencode.h>

using namespace std;

const int SALT_LEN = 16;
const int NONCE_LEN = 12;
const int KEY_LEN = 32;
const int ITERATIONS = 100000;

vector<unsigned char> derive_key(const string& password, const vector<unsigned char>& salt) {
    vector<unsigned char> key(KEY_LEN);
    int ok = PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                              salt.data(), salt.size(),
                              ITERATIONS, EVP_sha256(),
                              KEY_LEN, key.data());
    if (!ok) throw runtime_error("PBKDF2 failed");
    return key;
}

vector<unsigned char> encrypt_data(const vector<unsigned char>& data, const string& password) {
    vector<unsigned char> salt(SALT_LEN), nonce(NONCE_LEN);
    if (RAND_bytes(salt.data(), salt.size()) != 1) throw runtime_error("RAND_bytes");
    if (RAND_bytes(nonce.data(), nonce.size()) != 1) throw runtime_error("RAND_bytes");
    auto key = derive_key(password, salt);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new");
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptInit_ex");
    }
    vector<unsigned char> ciphertext(data.size());
    int len = 0, tmplen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptUpdate");
    }
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptFinal_ex");
    }
    len += tmplen;
    vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_CTRL_GCM_GET_TAG");
    }
    EVP_CIPHER_CTX_free(ctx);
    // result = salt + nonce + ciphertext + tag
    vector<unsigned char> result;
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + len);
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

vector<unsigned char> decrypt_data(const vector<unsigned char>& encrypted, const string& password) {
    if (encrypted.size() < SALT_LEN + NONCE_LEN + 16) throw runtime_error("Invalid data");
    vector<unsigned char> salt(encrypted.begin(), encrypted.begin() + SALT_LEN);
    vector<unsigned char> nonce(encrypted.begin() + SALT_LEN, encrypted.begin() + SALT_LEN + NONCE_LEN);
    size_t ciphertext_len = encrypted.size() - SALT_LEN - NONCE_LEN - 16;
    vector<unsigned char> ciphertext(encrypted.begin() + SALT_LEN + NONCE_LEN,
                                     encrypted.begin() + SALT_LEN + NONCE_LEN + ciphertext_len);
    vector<unsigned char> tag(encrypted.end() - 16, encrypted.end());
    auto key = derive_key(password, salt);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new");
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptInit_ex");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_CTRL_GCM_SET_TAG");
    }
    vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, tmplen = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptUpdate");
    }
    int r = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    if (r <= 0) throw runtime_error("Decryption failed (tag mismatch)");
    len += tmplen;
    plaintext.resize(len);
    return plaintext;
}

vector<string> generate_codes(int count, int length) {
    const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, chars.size() - 1);
    vector<string> codes;
    for (int i = 0; i < count; ++i) {
        string code;
        for (int j = 0; j < length; ++j) {
            code += chars[dis(gen)];
        }
        codes.push_back(code);
    }
    return codes;
}

struct BackupData {
    string created;
    vector<string> codes;
};

void save_to_file(const BackupData& data, const string& password, const string& filename) {
    Json::Value root;
    root["created"] = data.created;
    for (const auto& c : data.codes) root["codes"].append(c);
    string json = root.toStyledString();
    vector<unsigned char> data_bytes(json.begin(), json.end());
    auto encrypted = encrypt_data(data_bytes, password);
    ofstream ofs(filename, ios::binary);
    ofs.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    cout << "Saved encrypted backup to " << filename << endl;
}

BackupData load_from_file(const string& filename, const string& password) {
    ifstream ifs(filename, ios::binary);
    vector<unsigned char> encrypted((istreambuf_iterator<char>(ifs)), istreambuf_iterator<char>());
    auto decrypted = decrypt_data(encrypted, password);
    string json(decrypted.begin(), decrypted.end());
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(json, root)) throw runtime_error("Invalid JSON");
    BackupData data;
    data.created = root["created"].asString();
    for (const auto& c : root["codes"]) data.codes.push_back(c.asString());
    return data;
}

void list_codes(const string& filename, const string& password) {
    auto data = load_from_file(filename, password);
    cout << "Backup: " << filename << endl;
    cout << "Created: " << data.created << endl;
    cout << "Codes:" << endl;
    for (const auto& c : data.codes) cout << "  " << c << endl;
}

void generate_qr(const string& filename, const string& password, const string& output) {
    auto data = load_from_file(filename, password);
    string codes_str;
    for (size_t i = 0; i < data.codes.size(); ++i) {
        if (i > 0) codes_str += "\n";
        codes_str += data.codes[i];
    }
    QRcode* qr = QRcode_encodeString(codes_str.c_str(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (!qr) throw runtime_error("QR generation failed");
    // Save as PNG using libpng (simplified) – for brevity we just print message
    // In real code, you'd use libpng or ImageMagick.
    cout << "QR code generated (PNG saving not implemented in C++ demo)." << endl;
    QRcode_free(qr);
}

void check_code(const string& filename, const string& password, const string& code) {
    auto data = load_from_file(filename, password);
    bool found = false;
    for (const auto& c : data.codes) {
        if (c == code) { found = true; break; }
    }
    if (found)
        cout << "Code '" << code << "' is valid (found in backup)." << endl;
    else
        cout << "Code '" << code << "' is NOT in backup." << endl;
}

int main(int argc, char* argv[]) {
    string generate, output, password, list, qr, check;
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--generate" && i+1 < argc) generate = argv[++i];
        else if (arg == "--output" && i+1 < argc) output = argv[++i];
        else if (arg == "--password" && i+1 < argc) password = argv[++i];
        else if (arg == "--list" && i+1 < argc) list = argv[++i];
        else if (arg == "--qr" && i+1 < argc) qr = argv[++i];
        else if (arg == "--check" && i+1 < argc) check = argv[++i];
    }
    try {
        if (!generate.empty()) {
            if (output.empty() || password.empty()) throw runtime_error("--output and --password required");
            int count = stoi(generate);
            auto codes = generate_codes(count, 8);
            BackupData data;
            data.created = to_string(chrono::system_clock::now().time_since_epoch().count());
            data.codes = codes;
            save_to_file(data, password, output);
        } else if (!list.empty()) {
            if (password.empty()) throw runtime_error("--password required");
            list_codes(list, password);
        } else if (!qr.empty()) {
            if (password.empty() || output.empty()) throw runtime_error("--password and --output required for QR");
            generate_qr(qr, password, output);
        } else if (!check.empty()) {
            if (list.empty() || password.empty()) throw runtime_error("--list and --password required for check");
            check_code(list, password, check);
        } else {
            cout << "Use --help for usage." << endl;
        }
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}
