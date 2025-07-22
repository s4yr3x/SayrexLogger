//yandex_decryptor.cpp
// github: github.com/s4yr3x
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <windows.h>
#include <bcrypt.h>
#include "aes256gcm.h"

#pragma comment(lib, "bcrypt.lib")

Aes256GcmDecryptor::Aes256GcmDecryptor() {
    _alg_handle = nullptr;
    _key_handle = nullptr;
}

Aes256GcmDecryptor::~Aes256GcmDecryptor() {
    if (_key_handle)
        BCryptDestroyKey(_key_handle);
    if (_alg_handle)
        BCryptCloseAlgorithmProvider(_alg_handle, 0);
}

void Aes256GcmDecryptor::init(const uint8_t* key, size_t key_size) {
    if (key_size != 32)
        throw std::exception("LE key must be 32 bytes (256 bits)");

    NTSTATUS status;

    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&_alg_handle, BCRYPT_AES_ALGORITHM, NULL, 0)))
        throw std::exception("Cannot initialize crypto provider");

    if (!BCRYPT_SUCCESS(status = BCryptSetProperty(_alg_handle, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        throw std::exception("Cannot set chaining mode");

    if (!BCRYPT_SUCCESS(status = BCryptGenerateSymmetricKey(_alg_handle, &_key_handle,
        NULL, 0, (PUCHAR)key, (ULONG)key_size, 0)))
        throw std::exception("Cannot initialize symmetric key");
}

void Aes256GcmDecryptor::decrypt(uint8_t* out, size_t* out_len, size_t max_out_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* in, size_t in_len,
    const uint8_t* ad, size_t ad_len)
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);

    auth_info.pbNonce = (PUCHAR)nonce;
    auth_info.cbNonce = (ULONG)nonce_len;

    auth_info.pbTag = (PUCHAR)(in + in_len - 16);
    auth_info.cbTag = 16;

    if (ad && ad_len > 0) {
        auth_info.pbAuthData = (PUCHAR)ad;
        auth_info.cbAuthData = (ULONG)ad_len;
    }

    *out_len = 0;

    NTSTATUS status = BCryptDecrypt(_key_handle,
        (PUCHAR)in, (ULONG)(in_len - 16),
        &auth_info, NULL, 0,
        (PUCHAR)out, (ULONG)max_out_len,
        (ULONG*)out_len, 0);

    if (!BCRYPT_SUCCESS(status)) {
        throw std::exception("Cannot decrypt ciphertext");
    }
}
