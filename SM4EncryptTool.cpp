#include "SM4EncryptTool.h"
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>

// 获取 OpenSSL 错误字符串
std::string SM4EncryptTool::GetOpenSSLError() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

// ---------- SM4 ----------
bool SM4EncryptTool::SM4_CBC_Encrypt(const std::string& key,
                             const std::string& iv,
                             const std::string& plaintext,
                             std::string& ciphertext) {
    if (key.size() != 16) {
        ERR_put_error(ERR_LIB_USER, 0, 0, __FILE__, __LINE__);
        return false;
    }
    if (iv.size() != 16) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool success = false;
    if (EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()),
                           reinterpret_cast<const unsigned char*>(iv.data())) == 1) {
        size_t outlen = plaintext.size() + EVP_CIPHER_CTX_block_size(ctx);
        ciphertext.resize(outlen);
        int len = 0, tmplen = 0;
        if (EVP_EncryptUpdate(ctx,
                              reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                              reinterpret_cast<const unsigned char*>(plaintext.data()),
                              plaintext.size()) == 1) {
            if (EVP_EncryptFinal_ex(ctx,
                                    reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &tmplen) == 1) {
                len += tmplen;
                ciphertext.resize(len);
                success = true;
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool SM4EncryptTool::SM4_CBC_Decrypt(const std::string& key,
                             const std::string& iv,
                             const std::string& ciphertext,
                             std::string& plaintext) {
    if (key.size() != 16 || iv.size() != 16) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool success = false;
    if (EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()),
                           reinterpret_cast<const unsigned char*>(iv.data())) == 1) {
        size_t outlen = ciphertext.size();
        plaintext.resize(outlen);
        int len = 0, tmplen = 0;
        if (EVP_DecryptUpdate(ctx,
                              reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                              reinterpret_cast<const unsigned char*>(ciphertext.data()),
                              ciphertext.size()) == 1) {
            if (EVP_DecryptFinal_ex(ctx,
                                    reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &tmplen) == 1) {
                len += tmplen;
                plaintext.resize(len);
                success = true;
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return success;
}