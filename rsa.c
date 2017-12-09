
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
	size_t size = (n / 8) / sizeof(mp_limb_t);

	do
	{
		// get a pointer to the x limb array
		size_t* x_lp = mpz_limbs_write(x, size);

		// generate a random number
		for(size_t i = 0; i < size; ++i)
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

	} while(mpz_sizeinbase(x, 2) > n); // prevent prime overflow
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

uint8_t* rsa_encrypt(rsa_public_key_t pbk, uint8_t* m, size_t m_size, size_t* c_size)
{
	// the key size in bytes
	size_t ksize = mpz_size(pbk.n) * sizeof(mp_limb_t);

	// the size of the slice to encrypt
	size_t m_slice_size = ksize - 1;

	// the number of slices to encrypt
	size_t m_slices_cnt = m_size / m_slice_size;

	// last slice to encrypt size
	size_t m_last_slice_size = m_size - m_slices_cnt * m_slice_size;

	// the number of chipertext slices
	size_t c_slices_cnt = (m_last_slice_size == 0) ? m_slices_cnt : (m_slices_cnt + 1);

	// calculate the size of the chipertext buffer
	*c_size = c_slices_cnt * ksize;

	// create the chipertext buffer
	uint8_t* c_buffer = (uint8_t*)calloc(*c_size, sizeof(uint8_t));

	if(!c_buffer)
	{
		*c_size = 0;

		return NULL;
	}

	// the plaintext last pointer
	uint8_t* m_last = m + m_slices_cnt * m_slice_size;

	// the chipertext pointer
	uint8_t* c = c_buffer;

	mpz_t data;
	mpz_init(data);

	// encrypt all the slices
	while(m != m_last)
	{
		mpz_import(data, m_slice_size, -1, sizeof(uint8_t), 0, 0, m);

		// encrypt data
		mpz_powm(data, data, pbk.e, pbk.n);

		mpz_export(c, NULL, -1, sizeof(uint8_t), 0, 0, data);

		m += m_slice_size;
		c += ksize;
	}

	// encrypt the last slice
	if(m_last_slice_size != 0)
	{
		mpz_import(data, m_last_slice_size, -1, sizeof(uint8_t), 0, 0, m);

		// encrypt data
		mpz_powm(data, data, pbk.e, pbk.n);

		mpz_export(c, NULL, -1, sizeof(uint8_t), 0, 0, data);
	}

	mpz_clear(data);

	return c_buffer;
}

uint8_t* rsa_decrypt(rsa_private_key_t prk, uint8_t* c, size_t c_size, size_t* m_size)
{
	// the key size in bytes
	size_t ksize = mpz_size(prk.n) * sizeof(mp_limb_t);

	// create the plaintext buffer
	uint8_t* m_buffer = (uint8_t*)calloc(0, sizeof(uint8_t));

	// set to zero the plaintext buffer size
	*m_size = 0;

	if(!m_buffer)
	{
		return NULL;
	}

	// the chipertext last pointer
	uint8_t* c_last = c + c_size;

	mpz_t data;
	mpz_init(data);

	// decrypt all the slices
	while(c != c_last)
	{
		mpz_import(data, ksize, -1, sizeof(uint8_t), 0, 0, c);

		// decrypt data
		mpz_powm(data, data, prk.d, prk.n);

		// the last plaintext buffer size
		size_t m_last_size = *m_size;

		// the size of the decrypted slice
		// https://gmplib.org/manual/Integer-Import-and-Export.html
		size_t m_slice_size = (mpz_sizeinbase(data, 2) + 7) / 8;

		// increment the plaintext buffer size
		*m_size += m_slice_size;

		// expand the plaintext buffer
		m_buffer = (uint8_t*)realloc(m_buffer, *m_size);

		if(!m_buffer)
		{
			*m_size = 0;
			
			break;
		}

		// the pointer of the destination slice
		uint8_t* m_slice = m_buffer + m_last_size;

		mpz_export(m_slice, NULL, -1, sizeof(uint8_t), 0, 0, data);

		c += ksize;
	}

	mpz_clear(data);

	return m_buffer;
}

