// Copyright 2021 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

// This code invoke the EVP interface of OpenSSL.
// See https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
// Regarding GCM, see NIST Special Publication 800-38D
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

#ifndef MUMBLE_CRYPTSTATEAES256GCM_H
#define MUMBLE_CRYPTSTATEAES256GCM_H

#include "crypto/CryptState.h"

#include <openssl/evp.h>


class CryptStateAES256GCM : public CryptState {
public:
    static const unsigned int ivLength  = 96 / 8;
    static const unsigned int keyLength = 256 / 8;

    // See NIST SP 800-38D (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
    // for required tag length
    static const unsigned int tagLength = 64 / 8;

    /// The head of the packet is one iv byte plus tag.
    static const unsigned int headLength = tagLength + 1;


    CryptStateAES256GCM();
    ~CryptStateAES256GCM(){};

    bool isValid() const Q_DECL_OVERRIDE;
    void genKey() Q_DECL_OVERRIDE;
    bool setKey(const std::string &rkey, const std::string &eiv, const std::string &div) Q_DECL_OVERRIDE;
    bool setRawKey(const std::string &rkey) Q_DECL_OVERRIDE;
    bool setEncryptIV(const std::string &iv) Q_DECL_OVERRIDE;
    bool setDecryptIV(const std::string &iv) Q_DECL_OVERRIDE;
    std::string getRawKey() Q_DECL_OVERRIDE;
    std::string getEncryptIV() Q_DECL_OVERRIDE;
    std::string getDecryptIV() Q_DECL_OVERRIDE;

    bool decrypt(const unsigned char *source, unsigned char *dst, unsigned int encrypted_length,
                 unsigned int &plain_length) Q_DECL_OVERRIDE;
    bool encrypt(const unsigned char *source, unsigned char *dst, unsigned int plain_length,
                 unsigned int &encrypted_length) Q_DECL_OVERRIDE;

private:
    const EVP_CIPHER *cipher;

    unsigned char raw_key[keyLength];
    unsigned char encrypt_iv[ivLength];
    unsigned char decrypt_iv[ivLength];
    unsigned char decrypt_history[0x100];
};


#endif //MUMBLE_CRYPTSTATEAES256GCM_H
