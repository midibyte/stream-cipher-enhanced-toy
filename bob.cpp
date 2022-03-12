
#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sstream>
#include <stdlib.h>
#include <tomcrypt.h>
#include <fstream>

int main(void)
{
    // Alice reads the key
    std::ifstream key_file;
    std::string key; //char buffer

    std::ofstream Bob_h;
    Bob_h.open("Bob_h.txt");

    std::ofstream BobPlaintext;
    BobPlaintext.open("BobPlaintext.txt");

    // read in the secret
    key_file.open("sharedSecret.txt");
    if (key_file.is_open())
    {
        key_file >> key;
    }
    key_file.close();

    // connect to zmq server
    // RECEIVE HERE
    // Prepare our context and socket
    zmq::context_t context(2);
    zmq::socket_t socket(context, zmq::socket_type::rep);
    socket.bind("tcp://*:5555");

    // receive message hash
    zmq::message_t request;
    zmq::recv_result_t ret = socket.recv(request, zmq::recv_flags::none);

    unsigned char *hashedMessage = (unsigned char *)malloc(ret.value());
    memcpy(hashedMessage, request.data(), ret.value());
    //  = static_cast<unsigned char *>(request.data());

    printf("Received Hash in hex: \n");
    for (size_t i = 0; i < request.size(); i++)
    {   
        // NOTE hex will be zero padded
        printf("%2.2hx", hashedMessage[i]);
    }
    printf("\n\n");

    // receive cyphertext
    zmq::message_t request2;
    ret = socket.recv(request2, zmq::recv_flags::none);

    unsigned char *cyphertext = (unsigned char *)malloc(ret.value());
    memcpy(cyphertext, request2.data(), request2.size());
    size_t cyphertextSize = ret.value();

    //CONVERT BACK TO PLAIN TEXT

    // will hold the plainText, allocate memory
    size_t plainTextSize = cyphertextSize;
    unsigned char *plainText = (unsigned char *)malloc(cyphertextSize);

    // will concat this with the hashed chunk to make the key
    char concatChar = '1';

    // split text into 32 byte chunks then XOR with each 32 byte key
    unsigned CHUNK_SIZE = 32;
    size_t currentChunk = 0;

    for (size_t i = 0; i < plainTextSize; i += CHUNK_SIZE, currentChunk++)
    {

        // Use SHA-256 to Hash
        // This part requires libtomcrypt
        unsigned char r1[256 / 8];
        hash_state c;
        // We have key||1 - || = concatenation
        sha3_256_init(&c);
        sha3_process(&c, (const unsigned char *)(key + concatChar).c_str(), (key + concatChar).size());
        concatChar++;
        // r1 contains the current key
        sha3_done(&c, r1);

        for (size_t x = 0; x < CHUNK_SIZE; ++x)
        {
            // index within the cyphertext array
            size_t cyphertextIdx = (CHUNK_SIZE * currentChunk) + x;
            plainText[cyphertextIdx] = r1[x] ^ cyphertext[cyphertextIdx];
        }
    }

    // WRITE PLAIN TEXT TO FILE

    BobPlaintext.write(reinterpret_cast<char *>(plainText), plainTextSize);

    // hash all text and print to terminal
    //holds the resulting hash
    unsigned char *hashedinput = (unsigned char *)malloc(sha3_256_desc.hashsize);
    //compute the hash
    hash_state hs1;
    sha3_256_init(&hs1);
    sha3_process(&hs1, (const unsigned char *)plainText, plainTextSize);
    sha3_done(&hs1, hashedinput); //holds the hash result

    // print each byte as hexadecimal to terminal
    // check hash match
    bool hash_match = true;
    std::cout << "Hash of plaintext in hex: \n";
    for (size_t i = 0; i < sha3_256_desc.hashsize; ++i)
    {
        printf("%2.2hx", hashedinput[i]);

        if (hashedinput[i] != hashedMessage[i])
        {
            printf("hash mismatch at %ld\n plain text hash, received hash: %2.2hx %2.2hx", i, hashedinput[i], hashedMessage[i]);
            hash_match = !hash_match;

        }
    }
    printf("\n\n");
    if (hash_match)
        printf("Hashes successfully match\n");

    std::cout << std::endl;

    //write hash to Bob_h.txt
    // print each byte as hexadecimal to filestream
    for (size_t i = 0; i < sha3_256_desc.hashsize; ++i)
    {
        Bob_h << std::hex << std::setw(2) << std::setfill('0') << int(hashedinput[i]);
    }

    key_file.close();
    Bob_h.close();
    BobPlaintext.close();
    free(cyphertext);
    free(hashedMessage);
}