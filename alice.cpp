
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

    std::ifstream text_file;
    std::stringstream text_data; //char buffer

    std::ofstream TheCiphertext;

    TheCiphertext.open("TheCiphertext.txt");

    using namespace std;

    // read in the secret
    key_file.open("sharedSecret.txt");
    if (key_file.is_open())
    {
        key_file >> key;
    }
    key_file.close();

    //read in the plain text
    text_file.open("HW1PlaintextTest.txt");
    // text_file.open("testText.txt", std::ios::binary);

    if (text_file.is_open())
    {
        text_data << text_file.rdbuf();
    }

    // hash all text and print to terminal
    //holds the resulting hash
    unsigned char *hashedinput = (unsigned char *)malloc(sha3_256_desc.hashsize);
    //compute the hash
    hash_state hs1;
    sha3_256_init(&hs1);
    sha3_process(&hs1, (const unsigned char *)text_data.str().c_str(), text_data.str().size());
    sha3_done(&hs1, hashedinput); //holds the hash result

    // print each byte as hexadecimal to terminal
    cout << "Hash of input in hex: \n";
    for (size_t i = 0; i < sha3_256_desc.hashsize; ++i)
    {
        printf("%2.2hx", hashedinput[i]);
    }
    cout << endl;

    // will hold the cyphertext, allocate memory
    size_t cyphertextSize = text_data.str().size() * sizeof(unsigned char);
    unsigned char *cyphertext = (unsigned char *)malloc(cyphertextSize);

    // will concat this with the hashed chunk to make the key
    char concatChar = '1';

    // split text into 32 byte chunks then XOR with each 32 byte key
    unsigned CHUNK_SIZE = 32;
    size_t currentChunk = 0;

    for (size_t i = 0; i < text_data.str().size(); i += CHUNK_SIZE, currentChunk++)
    {

        std::string chunk;
        chunk = text_data.str().substr(currentChunk * CHUNK_SIZE, ((currentChunk + 1) * CHUNK_SIZE) - 1);

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
            cyphertext[cyphertextIdx] = r1[x] ^ text_data.str()[cyphertextIdx];
        }
    }

    // print each byte as hexadecimal to filestream
    for (size_t i = 0; i < cyphertextSize; ++i)
    {
        TheCiphertext << hex << setw(2) << setfill('0') << int(cyphertext[i]);
    }
    printf("\n");
    TheCiphertext.close();

    // TheCiphertext.write(reinterpret_cast<const char *>(cyphertext), cyphertextSize);

    // connect to zmq server
    //  Prepare our context and socket
    zmq::context_t context(1);
    zmq::socket_t socket(context, zmq::socket_type::req);
    std::cout << "Connecting to server at tcp://localhost:5555..." << std::endl;
    socket.connect("tcp://localhost:5555");

    // send the hash first
    zmq::message_t request(hashedinput, sha3_256_desc.hashsize);
    std::cout << "Sending Message... \n";

    // use ZMQ_SNDMORE to indicate another message is following
    // socket.send(request, ZMQ_SNDMORE);
    socket.send(request, zmq::send_flags::sndmore);

    //send the cyphertext now
    zmq::message_t request2(cyphertext, cyphertextSize);
    socket.send(request2, zmq::send_flags::none);

    text_file.close();
    key_file.close();
    free(cyphertext);
}