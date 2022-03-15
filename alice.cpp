
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
#include "helper.h"

//==============================================================================
// BEGIN MAIN
int main(void)
{
    //constants
    // encryption chunk size - number of chars
    // unsigned CHUNK_SIZE = 1024;
    size_t CHUNK_SIZE_BYTES = CHUNK_SIZE * sizeof(char);
    // message must be this size in bytes!
    size_t MESSAGE_SIZE = 100 * 1024;
    uint8_t DEBUG = 0;


    // setup files
    FILE * ciphertexts_fd = fopen("TheCiphertexts.txt", "w");
    FILE * HMACs_fd = fopen("HMACs.txt", "w");
    FILE * HMAC_aggregate_fd = fopen("AggregatedHMAC.txt", "w");
    FILE * message_fd = fopen("Messages.txt", "rb");
    FILE * key_fd = fopen("InitialKey.txt", "r");

    //variables 
    unsigned char * HMAC_aggregate;
    unsigned char * key;
    unsigned char * key_prev;
    std::vector<unsigned char> ciphertexts_vector;

    //==============================================================================
    // begin program
    // check message size, if not correct quit program
    size_t sizeCheck = get_file_size(message_fd);
    if(DEBUG) printf("Messages file size: %ld\n", sizeCheck);
    if(sizeCheck != MESSAGE_SIZE)
    {
        printf("Message is not %ldBytes\nActual size: %ldBytes", MESSAGE_SIZE, sizeCheck);
        exit(EXIT_FAILURE);
    }

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

    //holds aggregate HMAC
    HMAC_aggregate = (unsigned char *) malloc(SHA256SIZEBYTES);
    // set to zero initially
    memset(HMAC_aggregate, 0, SHA256SIZEBYTES);

    //==============================================================================
    // BEGIN ENCRYPTION
    for (size_t currentChunk = 0; currentChunk < sizeCheck/CHUNK_SIZE; ++currentChunk)
    {
        unsigned char ciphertext_buffer[CHUNK_SIZE_BYTES];
        unsigned char HMAC[SHA256SIZEBYTES];
        unsigned char message_chunk[CHUNK_SIZE];

        //copy key
        memcpy(key_prev, key, key_size);

        if (DEBUG > 0) printf(" msg_len, CHUNK_SIZE_BYTES, currentChunk: %ld %ld %ld\n\n", sizeCheck/CHUNK_SIZE, CHUNK_SIZE_BYTES, currentChunk);

        // get a 1024 char chunk of the messages file
        size_t size_read = fread(message_chunk, sizeof(char), CHUNK_SIZE, message_fd);

        // make sure chunk size is correct
        if (size_read != CHUNK_SIZE)
        {
            printf("Chunk size less than 1024 Bytes, read error\nExpected 1024B, got %ldB\n", size_read);
            exit(EXIT_FAILURE);
        }

        // copy chunk to ciphertext_buffer since the encryption function modifies the input
        memcpy(ciphertext_buffer, message_chunk, CHUNK_SIZE_BYTES);

        //==============================================================================
        // ENCRYPTION STEP        
        // encrypts data in buffer then returns ciphertext
        // erases key
        AESctr_encrypt(ciphertext_buffer, key);

        // compute HMAC of cipher text
        HMAC_Computation(ciphertext_buffer, HMAC, key_prev);
        // print HMAC to file
        for (auto i = 0; i < SHA256SIZEBYTES; ++i)
        {
            fprintf(HMACs_fd, "%02hhX", HMAC[i]);
        }

        // update HMAC aggregate
        HMAC_aggregate = HMAC_update(HMAC, HMAC_aggregate);

        // add ciphertext to ciphertexts_vector
        // push each unsigned char
        for(auto i =0; i < CHUNK_SIZE; ++i)
        {
            ciphertexts_vector.push_back(ciphertext_buffer[i]);
        }

        //make new key with hashed old key
        key = hashSHA2(key_prev, key_size);
    }

    //==============================================================================
    // save data to files
    // write ciphertexts to file
    for (size_t i = 0; i < ciphertexts_vector.size(); ++i)
    {
        fprintf(ciphertexts_fd, "%02hhX", ciphertexts_vector.data()[i]);
    }

    //save hmac aggregate to file
    for (auto i = 0; i < SHA256SIZEBYTES; ++i)
    {
        fprintf(HMAC_aggregate_fd, "%02hhX", HMAC_aggregate[i]);
    }

    //==============================================================================
    // SEND DATA with ZMQ
    // connect to zmq server
    //  Prepare our context and socket
    zmq::context_t context(1);
    zmq::socket_t socket(context, zmq::socket_type::req);
    std::cout << "Connecting to server at tcp://localhost:5555..." << std::endl;
    socket.connect("tcp://localhost:5555");

    // send combined ciphertexts
    zmq::message_t request(ciphertexts_vector.data(), ciphertexts_vector.size() );
    std::cout << "Sending Message... \n";

    // use ZMQ_SNDMORE to indicate another message is following
    // socket.send(request, ZMQ_SNDMORE);   // dont use this, ZMQ_SNDMORE is depreciated
    socket.send(request, zmq::send_flags::sndmore);
    // socket.send(request, zmq::send_flags::none);

    // send the aggregate HMAC now
    // NOTE sending as unsigned char array
    zmq::message_t request2(HMAC_aggregate, SHA256SIZEBYTES);
    socket.send(request2, zmq::send_flags::none);

    // close files and free mallocs
    fclose(ciphertexts_fd);
    fclose(key_fd);
    fclose(HMACs_fd);
    fclose(HMAC_aggregate_fd);
    free(HMAC_aggregate);
    free(key);
    free(key_prev);

}