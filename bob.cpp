
#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sstream>
#include <stdlib.h>
#include <tomcrypt.h>
#include <fstream>
#include <stdio.h>

using namespace std;

//===================SHA256 Function=========================================
unsigned char* hashSHA2(const string& input)
{
	unsigned char* hash_res = new unsigned char[sha256_desc.hashsize];
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, (const unsigned char*) input.c_str(), input.size());
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
//---------------------------------------------------------------------------------
//===================AES Encryption in CTR mode=========================================
unsigned char* AESctr_encrypt(unsigned char *buffer, unsigned char *key)
{
    // hardcoded IV
    unsigned char IV[32] = "abcdefghijklmnopqrstuvwxyzabcde";
		symmetric_CTR ctr;
    int x;
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
    // unsigned char IV[32] = "bbcdefhij12345bbcdefhij12345aaa";
    unsigned char IV[32] = "abcdefghijklmnopqrstuvwxyzabcde";

    symmetric_CTR ctr;
    int x;
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

// print out a string char by char
template <class T>
void print_string_hex(T str, size_t len)
{
            // prints out the chunk
        for (int i = 0; i < len; ++i)
        {
            printf("%02hhX ", str[i]);

        }
        // printf ("\n\n");
}
//==============================================================================

//==============================================================================
// BEGIN MAIN
int main(){
    //==============================================================================
    // OPEN FILES

    // open C file descriptors
    FILE * HMACs_fd = fopen("HMACs_bob.txt", "w");
    FILE * ciphertexts_fd = fopen("ciphertexts_bob.txt", "w");
    FILE * plaintext_fd = fopen("Plaintext_bob.txt", "w");
    FILE * plaintext_hex_fd = fopen("Plaintext_hex_bob.txt", "w");
    FILE * HMAC_aggregate_fd = fopen("matchedAggregatedHMAC.txt", "w");

    // Bob reads the key
    std::ifstream key_file;
    std::string key; //char buffer
    key_file.open("InitialKey.txt");
    if(key_file.is_open() ) {
        key_file >> key;
    }
    key_file.close();

    //==============================================================================
    // RECEIVE CIPHERTEXT
    //  Prepare our context and socket
    zmq::context_t context (2);
    zmq::socket_t socket (context, zmq::socket_type::rep);
    socket.bind ("tcp://*:5555");
    
    // request will hold the recieved data
    zmq::message_t request;
    zmq::recv_result_t ret = socket.recv(request, zmq::recv_flags::none);

    // convert recieved data to unsigned char vector - identical to sent version
    vector<unsigned char> ciphertexts(ret.value());
    memcpy(ciphertexts.data(), request.data(), ret.value());

    // print recvd ciphertexts to file
    for(int i =0; i < ciphertexts.size(); ++i)
        {
            // ciphertexts_vector.push_back(msg[i]);
            // printf("%02hhX", ciphertexts.data()[i]);
            fprintf(ciphertexts_fd, "%02hhX",  ciphertexts.data()[i]);
        }
    
    printf("recvd size: %d\n", ret.value());
    
    //==============================================================================
    // process ciphertexts and compute HMACs

    // split messages file into 1024byte messages 
    unsigned CHUNK_SIZE = 1024;
    size_t CHUNK_SIZE_BYTES = (CHUNK_SIZE * sizeof(char));
    size_t currentChunk = 0;

    // for (size_t i = 0; i < ciphertexts.size(); i += CHUNK_SIZE, currentChunk++)
    for (size_t currentChunk = 0; currentChunk < ciphertexts.size()/CHUNK_SIZE; ++currentChunk)
    {

        // printf("i, CHUNK_SIZE_BYTES, currentChunk: %d %d %d\n\n", i, CHUNK_SIZE_BYTES, currentChunk);

        // 1024byte chunk of ciphertext
        unsigned char * ciphertext_chunk = (unsigned char*)malloc(CHUNK_SIZE_BYTES);
        memcpy(ciphertext_chunk, &(ciphertexts.data()[currentChunk * CHUNK_SIZE]), CHUNK_SIZE_BYTES);

        // print_string_hex(ciphertext_chunk, CHUNK_SIZE_BYTES);

        // convert KEY
        // convert std string to unsigned char array
        unsigned char* key_cstr = (unsigned char *)malloc(key.size());
        memcpy(key_cstr, key.data(), key.size() );
        key_cstr = reinterpret_cast <unsigned char*> (key_cstr);

        // compute HMAC 
        unsigned char HMAC[MAXBLOCKSIZE];
        HMAC_Computation(ciphertext_chunk, HMAC, key_cstr);

        // write HMAC to file
        for (int i = 0; i < MAXBLOCKSIZE; ++i)
        {
            fprintf(HMACs_fd, "%02hhX", HMAC[i]);
        }
        
        //==============================================================================
        // BEGIN DECRYPT

        unsigned char * plaintext_chunk = (unsigned char *)malloc(CHUNK_SIZE_BYTES);
        memcpy(plaintext_chunk, ciphertext_chunk, sizeof(ciphertext_chunk));

        plaintext_chunk = AESctr_decrypt(plaintext_chunk, key_cstr);
        char * plaintext_chunk_cast = reinterpret_cast<char *>(plaintext_chunk);

        for (int i = 0; i < CHUNK_SIZE_BYTES; ++i )
        {
            fprintf(plaintext_fd, "%c", plaintext_chunk_cast[i]);
            fprintf(plaintext_hex_fd, "%02hhX", plaintext_chunk[i]);
            printf("%02hhX", plaintext_chunk[i]);
        }
        printf("\n");
        fprintf(plaintext_hex_fd, "\n");


        free(ciphertext_chunk);
        free(key_cstr);
        free(plaintext_chunk);
        // free(msg);
        // free(HMAC);
        // free(buffer);

        // printf("===================================================================================\n");
    }













    // zmq::message_t request2;
    
    //  Wait for next request from client (remember- 2 parts)
    // socket.recv (request2, zmq::recv_flags::none);
    // std::string rpl2 = std::string(static_cast<char*>(request2.data()), request2.size());


    // HMAC_Computation(rpl, mac, key);

    // if (mac == rpl2){
    //     std::cout << "The aggregated HMAC matches with the received one!" << std::endl;
        
    //     ofstream myfile;
    //     myfile.open ("Plaintexts.txt");
    //     myfile << AESctr_decrypt(rpl, key);
    //     myfile.close();

    //     ofstream myfile;
    //     myfile.open ("matchedAggregatedHMAC.txt");
    //     myfile << mac;
    //     myfile.close();

    // }else std::cout << "The Authentication Process Went Wrong" << std::endl; 

    fclose(HMACs_fd);
    fclose(plaintext_fd);
    fclose(ciphertexts_fd);

}