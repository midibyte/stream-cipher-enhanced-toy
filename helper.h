# ifndef HELPER_H
# define HELPER_H

#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sstream>
#include <stdlib.h>
#include <tomcrypt.h>
#include <fstream>
#include <stdio.h>
#include <iterator>

const int CHUNK_SIZE = 1024;
const int SHA256SIZEBYTES = 32;

//===================SHA256 Function=========================================
unsigned char* hashSHA2(const std::string& input)
{
	unsigned char* hash_res = new unsigned char[sha256_desc.hashsize];
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, (const unsigned char*) input.c_str(), input.size());
    sha256_done(&md, hash_res);
    return hash_res;
}
unsigned char* hashSHA2(unsigned char * input, size_t input_size)
{
	unsigned char* hash_res = new unsigned char[sha256_desc.hashsize];
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, (const unsigned char*) input, input_size);
    sha256_done(&md, hash_res);
    return hash_res;
}
//----------------------------------------------------------------------------------
//===================HMAC Function based on SHA256=========================================
// void HMAC_Computation(char *message, unsigned char *mac, unsigned char *key)
void HMAC_Computation(unsigned char *message, unsigned char *mac, unsigned char *key)
{
    int idx;
    hmac_state hmac;
    unsigned char dst[MAXBLOCKSIZE];
    unsigned long dstlen;
    register_hash(&sha256_desc);
    idx = find_hash("sha256");
    hmac_init(&hmac, idx, key, 32);
    hmac_process(&hmac, (const unsigned char*) message, sizeof(message));
    dstlen = sizeof(dst);
    hmac_done(&hmac, dst, &dstlen);
    memcpy(mac, dst, dstlen);
}

//===================AES Encryption in CTR mode=========================================
unsigned char* AESctr_encrypt(unsigned char *buffer, unsigned char *key)
{
    // hardcoded IV
    unsigned char IV[32] = "abcdefghijklmnopqrstuvwxyzabcde";
		symmetric_CTR ctr;
    // int x;
    /* register AES first */
   register_cipher(&aes_desc);
   ctr_start(
             find_cipher("aes"),    /* index of desired cipher */
             IV,                        /* the initial vector */
             key,                       /* the secret key */
             32,                        /* length of secret key (16 bytes) */
             0,                         /* 0 == default # of rounds */
             CTR_COUNTER_LITTLE_ENDIAN, /* Little endian counter */
             &ctr);                    /* where to store the CTR state */
             		ctr_setiv(IV,
              32,
              &ctr);

	 ctr_encrypt(buffer,         /* plaintext */
                buffer,         /* ciphertext */
                sizeof(buffer), /* length of plaintext pt */
                &ctr);          /* CTR state */

    zeromem(key, sizeof(key));
    zeromem(&ctr, sizeof(ctr));
    return buffer;
}
//---------------------------------------------------------------------------
//=====================AES Decryption in CTR mode=========================================
unsigned char* AESctr_decrypt(unsigned char *buffer, unsigned char *key)
{
    // same as encrypt!
    unsigned char IV[32] = "abcdefghijklmnopqrstuvwxyzabcde";

    symmetric_CTR ctr;
    // int x;
		register_cipher(&aes_desc);
    ctr_start(
             find_cipher("aes"),    /* index of desired cipher */
             IV,                        /* the initial vector */
             key,                       /* the secret key */
             32,                        /* length of secret key (16 bytes) */
             0,                         /* 0 == default # of rounds */
             CTR_COUNTER_LITTLE_ENDIAN, /* Little endian counter */
             &ctr);
		ctr_setiv(IV,
              32,
              &ctr);
		ctr_decrypt( buffer, /* ciphertext */
								buffer, /* plaintext */
								sizeof(buffer), /* length of plaintext */
								&ctr); /* CTR state */
  	ctr_done(&ctr);

		zeromem(key, sizeof(key));
    zeromem(&ctr, sizeof(ctr));
    return buffer;
}

//--------------------------------------------------------------------------------------------

//==============================================================================
// print out a string char by char
template <class T>
void print_string_hex(T * str, size_t len)
{
            // prints out the chunk
        for (size_t i = 0; i < len; ++i)
        {
            printf("%02hhX ", str[i]);

        }
        // printf ("\n\n");
}

unsigned char * HMAC_update(unsigned char * HMAC_current, unsigned char * HMAC_aggregate)
{
    // *HMAC_aggregate = *HMAC_aggregate || *HMAC_current;
    // ASSUMING || in the docs means concatinate
    // concat into one string
    std::string temp;
    for (int i =0; i < SHA256SIZEBYTES; ++i)
        temp.push_back(HMAC_current[i]);
    for (int i =0; i < SHA256SIZEBYTES; ++i)
        temp.push_back(HMAC_aggregate[i]);

    // hash and return 
    return hashSHA2(temp);

}
//==============================================================================
// returns the files size in bytes
size_t get_file_size(FILE * fd)
{  
    fseek(fd, 0L, SEEK_END);
    size_t size = ftell(fd);
    // return the file descriptor to where it was before the check
    // fseek(fd, 0L, SEEK_SET);
    rewind(fd);
    return size;
}

# endif