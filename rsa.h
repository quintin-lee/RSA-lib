

/*
	RSA-lib - Copyright (c) 2017 loreloc - lorenzoloconte@outlook.it

	This software is provided 'as-is', without any express or implied
	warranty. In no event will the authors be held liable for any damages
	arising from the use of this software.

	Permission is granted to anyone to use this software for any purpose,
	including commercial applications, and to alter it and redistribute it
	freely, subject to the following restrictions:

	1. The origin of this software must not be misrepresented; you must not
	claim that you wrote the original software. If you use this software
	in a product, an acknowledgement in the product documentation would be
	appreciated but is not required.
	2. Altered source versions must be plainly marked as such, and must not be
	misrepresented as being the original software.
	3. This notice may not be removed or altered from any source distribution.
*/

///
/// \file rsa.h
///

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <immintrin.h>
#include <gmp.h>

/// \brief RSA key size, the size in bits of modulus n
///
typedef enum
{
	RSA_KEY_256   = (1 <<  8), ///<   256 bits
	RSA_KEY_512   = (1 <<  9), ///<   512 bits
	RSA_KEY_1024  = (1 << 10), ///<  1024 bits
	RSA_KEY_2048  = (1 << 11), ///<  2048 bits
	RSA_KEY_4096  = (1 << 12), ///<  4096 bits
	RSA_KEY_8192  = (1 << 13), ///<  8192 bits
	RSA_KEY_16384 = (1 << 14)  ///< 16384 bits

} rsa_key_size;

/// \brief RSA public key (n, e)
///
typedef struct
{
	mpz_t n; ///< Modulus
	mpz_t e; ///< Public exponent

} rsa_public_key_t;

/// \brief RSA private key (n, d)
///
typedef struct
{
	mpz_t n; ///< Modulus
	mpz_t d; ///< Private exponent

} rsa_private_key_t;

/// \brief Generate the public key and the private key
/// \param[in] pbk The public key to generate pointer
/// \param[in] prk The private key to generate pointer
/// \param[in] ks  The size of the key
///
void rsa_generate_keys(rsa_public_key_t* pbk, rsa_private_key_t* prk, rsa_key_size ks);

/// \brief Destroy the public key
/// \param[in] pbk The public key to destroy pointer
///
void rsa_destroy_public_key(rsa_public_key_t* pbk);

/// \brief Destroy the private key
/// \param[in] prk The private key to destroy pointer
///
void rsa_destroy_private_key(rsa_private_key_t* prk);

/// \brief Encrypt a message
/// \param[in] pbk The public key
/// \param[in] m Plaintext buffer pointer
/// \param[in] m_size Plaintext buffer size
/// \param[out] c_size Chipertext buffer size
/// \return A pointer to the chipertext buffer
///
uint8_t* rsa_encrypt(rsa_public_key_t pbk, uint8_t* m, size_t m_size, size_t* c_size);

/// \brief Decrypt a message
/// \param[in] prk The public key
/// \param[in] c Chipertext buffer pointer
/// \param[in] c_size Chipertext buffer size
/// \param[out] m_size Plaintext buffer size
/// \return A pointer to the plaintext buffer
///
uint8_t* rsa_decrypt(rsa_private_key_t prk, uint8_t* c, size_t c_size, size_t* m_size);



