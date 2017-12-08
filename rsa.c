
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

#include "rsa.h"

void rsa_random_prime(mpz_t x, mp_bitcnt_t n)
{
	// number of limbs
	mp_size_t size = (n / 8) / sizeof(mp_limb_t);

	// get a pointer to the x limb array
	mp_limb_t* x_lp = mpz_limbs_write(x, size);

	// generate a random number
	for(mp_size_t i = 0; i < size; ++i)
	{
		// use hardware generated random numbers
		_rdrand64_step(&x_lp[i]);
	}

	// update n limbs
	mpz_limbs_finish(x, size);

	// set the lowest bit
	mpz_setbit(x, 0);

	// set the highest bit
	mpz_setbit(x, n - 1);

	// find the next prime number
	mpz_nextprime(x, x);
}

void rsa_generate_keys(rsa_public_key_t* pbk, rsa_private_key_t* prk, rsa_key_size ks)
{
	// big prime numbers
	mpz_t p, q;
	mpz_init(p);
	mpz_init(q);

	// modulus n, the product of p and q
	mpz_t n;
	mpz_init(n);

	// phi(n), the numbers of numbers less than n and coprime with n
	mpz_t phi;
	mpz_init(phi);
	
	// generate p big prime number
	rsa_random_prime(p, (mp_bitcnt_t)ks / 2);

	// generate q big prime number not equal to p
	do
	{
		rsa_random_prime(q, (mp_bitcnt_t)ks / 2);

	} while(mpz_cmp(p, q) == 0);

	// calculate the modulus n
	mpz_mul(n, p, q);
	mpz_init_set(pbk->n, n);
	mpz_init_set(prk->n, n);

	// calculate phi(n)
	// phi(n) = phi(p*q) = phi(p)*phi(q) = (p-1)*(q-1)
	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
	mpz_mul(phi, p, q);

	// initialize the public exponent
	mpz_init(pbk->e);

	// gcd will hold the greatest commond divisor between e and phi(n)
	mpz_t gcd;
	mpz_init(gcd);

	// find e such that it is coprime with phi(n) and less than phi(n)
	do
	{
		// generate a random prime number of the same size of the prime numbers
		rsa_random_prime(pbk->e, (mp_bitcnt_t)ks / 2);

		// calculate the gcd between e and phi(n)
		mpz_gcd(gcd, pbk->e, phi);

	} while(mpz_cmp_ui(gcd, 1) != 0);

	// initialize the private exponent
	mpz_init(prk->d);

	// find d such that e*d = 1 (mod phi(n))
	mpz_invert(prk->d, pbk->e, phi);

	// set the keys size
	pbk->s = ks;
	prk->s = ks;

	// clear stuff
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n);
	mpz_clear(phi);
	mpz_clear(gcd);
}

void rsa_destroy_public_key(rsa_public_key_t* pbk)
{
	mpz_clear(pbk->n);
	mpz_clear(pbk->e);
}

void rsa_destroy_private_key(rsa_private_key_t* prk)
{
	mpz_clear(prk->n);
	mpz_clear(prk->d);
}

void rsa_encrypt(rsa_public_key_t* pbk, uint8_t* c, uint8_t* m, size_t size)
{
	// the key size in bytes
	mp_size_t ksize = (mp_bitcnt_t)pbk->s / 8;

	// the size of the slice to encrypt
	mp_size_t m_slice_size = ksize - sizeof(uint8_t);

	// the number of complete slices to encrypt
	mp_size_t m_slices_cnt = size / m_slice_size;

	// last slice size to encrypt
	mp_size_t m_last_slice_size = size - m_slices_cnt * m_slice_size;

	// the size of the encrypted slice
	mp_size_t c_slice_size = ksize;

	// the last pointer
	uint8_t* m_last = m + m_slices_cnt * m_slice_size;

	mpz_t data;
	mpz_init(data);

	while(m != m_last)
	{
		mpz_import(data, m_slice_size, -1, sizeof(uint8_t), 0, 0, m);

		// encrypt data
		mpz_powm(data, data, pbk->e, pbk->n);

		mpz_export(c, NULL, -1, sizeof(uint8_t), 0, 0, data);

		m += m_slice_size;
		c += c_slice_size;
	}

	if(m_last_slice_size != 0)
	{
		mpz_import(data, m_last_slice_size, -1, sizeof(uint8_t), 0, 0, m);

		// encrypt data
		mpz_powm(data, data, pbk->e, pbk->n);

		mpz_export(c, NULL, -1, sizeof(uint8_t), 0, 0, data);
	}

	mpz_clear(data);
}

void rsa_decrypt(rsa_private_key_t* prk, uint8_t* m, uint8_t* c, size_t size)
{
	// the size of the encrypted slice
	mp_size_t c_slice_size = (mp_bitcnt_t)prk->s / 8;

	// the last pointer
	uint8_t* c_last = c + size;

	mpz_t data;
	mpz_init(data);

	// the size of the decrypted slice
	size_t m_slice_size;

	while(c != c_last)
	{
		mpz_import(data, c_slice_size, -1, sizeof(uint8_t), 0, 0, c);

		// decrypt data
		mpz_powm(data, data, prk->d, prk->n);

		mpz_export(m, &m_slice_size, -1, sizeof(uint8_t), 0, 0, data);

		c += c_slice_size;
		m += m_slice_size;
	}

	mpz_clear(data);
}

size_t rsa_chipertext_size(rsa_public_key_t* pbk, size_t size)
{
	// the key size in bytes
	mp_size_t ksize = (mp_bitcnt_t)pbk->s / 8;

	return ((size / ksize) + 1) * ksize;
}

