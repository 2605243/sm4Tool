#ifndef SM4_ENCRYPT_TOOL_H
#define SM4_ENCRYPT_TOOL_H

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "EncodeTool.h"

class SM4EncryptTool {
public:
    // ---------- SM4 对称加解密 ----------
    // 使用 CBC 模式，PKCS7 填充
    static bool SM4_CBC_Encrypt(const std::string& key,
                                const std::string& iv,
                                const std::string& plaintext,
                                std::string& ciphertext);

    static bool SM4_CBC_Decrypt(const std::string& key,
                                const std::string& iv,
                                const std::string& ciphertext,
                                std::string& plaintext);

    // 获取 OpenSSL 错误信息
    static std::string GetOpenSSLError();

private:
    // 内存释放器 (用于 std::unique_ptr)
    struct EVP_PKEY_Deleter {
        void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
    };
    struct BIO_Deleter {
        void operator()(BIO* b) const { if (b) BIO_free(b); }
    };
};

#endif 