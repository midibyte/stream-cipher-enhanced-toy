
#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sstream>
#include <stdlib.h>
#include <tomcrypt.h>
#include <fstream>
#include <stdio.h>
#include "helper.h"
//==============================================================================
// BEGIN MAIN
int main(){
    //==============================================================================
    // OPEN FILES
    FILE * plaintext_fd = fopen("Plaintexts.txt", "wb");
    FILE * HMAC_aggregate_fd = fopen("matchedAggregatedHMAC.txt", "w");
    FILE * key_fd = fopen("InitialKey.txt", "r");

    unsigned char * HMAC_aggregate;
    unsigned char * HMAC_aggregate_recvd;
    unsigned char * key;
    unsigned char * key_prev;

    size_t CHUNK_SIZE_BYTES = (CHUNK_SIZE * sizeof(char));


    // malloc memory
    HMAC_aggregate = (unsigned char *) malloc(SHA256SIZEBYTES);
    HMAC_aggregate_recvd = (unsigned char *)malloc(SHA256SIZEBYTES);

    // read in the secret key into "key"
    // get key file size
    size_t key_size = get_file_size(key_fd);
    key = (unsigned char *)malloc(key_size);
    key_prev = (unsigned char *)malloc(key_size);
    for(size_t i = 0; i < key_size; ++i)
    {
        //read key from file
        fread(key, key_size, 1, key_fd);
    }

    // set prev key to zero
    memset(key_prev, 0, key_size);

    //==============================================================================
    // RECEIVE CIPHERTEXT
    //  Prepare our context and socket
    zmq::context_t context (2);
    zmq::socket_t socket (context, zmq::socket_type::rep);
    socket.bind ("tcp://*:5555");
    
    // request will hold the recieved data
    zmq::message_t request_ciphertext;
    zmq::recv_result_t ret = socket.recv(request_ciphertext, zmq::recv_flags::none);
    zmq::message_t request_HMAC_aggregate;
    zmq::recv_result_t ret2 = socket.recv(request_HMAC_aggregate, zmq::recv_flags::none);

    // convert recieved data to unsigned char vector - identical to sent version
    std::vector<unsigned char> ciphertexts(ret.value());
    memcpy(ciphertexts.data(), request_ciphertext.data(), ret.value());

    // store recvd HMAC agg to compare to later
    // set test HMAC_agg to zero
    memset(HMAC_aggregate, 0, SHA256SIZEBYTES);
    memcpy(HMAC_aggregate_recvd, request_HMAC_aggregate.data(), ret2.value());

    // process ciphertexts and compute HMACs
    // split messages file into 1024byte messages 
    for (size_t currentChunk = 0; currentChunk < ciphertexts.size()/CHUNK_SIZE; ++currentChunk)
    {
        //make copy of key
        memcpy(key_prev, key, key_size);

        // gat a 1024byte chunk of ciphertext
        unsigned char plaintext_chunk[CHUNK_SIZE_BYTES];
        unsigned char ciphertext_chunk[CHUNK_SIZE_BYTES];
        unsigned char HMAC[SHA256SIZEBYTES];
        // index into data to get correct chunk start address
        memcpy(ciphertext_chunk, ciphertexts.data() + currentChunk * CHUNK_SIZE, CHUNK_SIZE_BYTES);

        // compute HMAC and aggregate 
        HMAC_Computation(ciphertext_chunk, HMAC, key_prev);
        HMAC_aggregate = HMAC_update(HMAC, HMAC_aggregate);

        //==============================================================================
        // BEGIN DECRYPT
        // copy ciphertext into plaintext buffer, will be replaced by decrypt function
        memcpy(plaintext_chunk, ciphertext_chunk, CHUNK_SIZE_BYTES);

        AESctr_decrypt(plaintext_chunk, key);

        // write the plain text chunk to file
        fwrite(plaintext_chunk, CHUNK_SIZE, 1, plaintext_fd);
        
        //make new key with hash of old key 
        key = hashSHA2(key_prev, key_size);
    }

    //save hmac aggregate to file
    for (auto i = 0; i < SHA256SIZEBYTES; ++i)
    {
        fprintf(HMAC_aggregate_fd, "%02hhX", HMAC_aggregate[i]);
    }

    // check if aggregate HMACs match
    int match_flag = 0;
    for (auto i =0; i < SHA256SIZEBYTES; ++i)
    {
        if(HMAC_aggregate_recvd[i] == HMAC_aggregate[i]) continue;
        else match_flag = -1;
    }

    if (match_flag != -1) printf("The aggregated HMAC matches with the received one!\n");


    fclose(plaintext_fd);
    fclose(HMAC_aggregate_fd);
    fclose(key_fd);
}