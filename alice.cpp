
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
    unsigned char IV[32] = "bbcdefhij12345bbcdefhij12345aaa";
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

//==============================================================================
// print out a string char by char
void print_string_hex(char * str, size_t len)
{
            // prints out the chunk
        for (int i = 0; i < len; ++i)
        {
            printf("%02hhX ", str[i]);

        }
        // printf ("\n\n");
}

unsigned char * HMAC_update(unsigned char * HMAC_current, unsigned char * HMAC_aggregate)
{
    // *HMAC_aggregate = *HMAC_aggregate | *HMAC_current;
    // concat into one string
    string temp;
    for (int i =0; i < MAXBLOCKSIZE; ++i)
        temp.push_back(HMAC_current[i]);
    for (int i =0; i < MAXBLOCKSIZE; ++i)
        temp.push_back(HMAC_aggregate[i]);

    // hash and return 
    return hashSHA2(temp);

}

//==============================================================================
// BEGIN MAIN
int main(void)
{
    //==============================================================================
    // BEGIN READ FILES
    // Alice reads the key
    std::ifstream key_file;
    std::string keyString; //char buffer

    std::ifstream Messages_file;
    std::stringstream Messages; //char buffer
    FILE * ciphertexts_fd = fopen("TheCiphertexts.txt", "w");
    FILE * HMACs_fd = fopen("HMACs.txt", "w");
    FILE * plaintext_hex_fd = fopen("Plaintext_hex_alice.txt", "w");
    FILE * HMAC_aggregate_fd = fopen("AggregatedHMAC.txt", "w");
    

    // read in the secret key into "key"
    // file name is hard coded
    key_file.open("InitialKey.txt");
    if (key_file.is_open())
    {
        key_file >> keyString;
    }
    key_file.close();

    //copy key to unsigned char array
    unsigned char * key_cstr = (unsigned char*) malloc(keyString.size());
    unsigned char * key_cstr_next = (unsigned char*) malloc(keyString.size());
    memcpy(key_cstr, keyString.c_str(), keyString.size());
    memset(key_cstr_next, 0, MAXBLOCKSIZE);

    //holds aggregate HMAC
    unsigned char * HMAC_aggregate = (unsigned char *) malloc(MAXBLOCKSIZE);
    // set to zero initially
    memset(HMAC_aggregate, 0, MAXBLOCKSIZE);

    //read in the plain text
    // message data, 100 messages, 1024 bytes each
    Messages_file.open("Messages.txt", ios::binary);

    if (Messages_file.is_open())
    {
        Messages << Messages_file.rdbuf();
    }

    //==============================================================================
    // BEGIN ENCRYPTION

    // split messages file into 1024byte messages 
    unsigned CHUNK_SIZE = 1024;
    size_t CHUNK_SIZE_BYTES = CHUNK_SIZE * sizeof(char);
    // size_t currentChunk = 0;

    vector<unsigned char> ciphertexts_vector;
    vector<unsigned char> HMACs_vector;

    // unsigned 

    // for (size_t i = 0; i < Messages.str().size(); i += CHUNK_SIZE, currentChunk++)
    for (size_t currentChunk = 0; currentChunk < Messages.str().size()/CHUNK_SIZE; ++currentChunk)
    {
        // printf(" msg_len, CHUNK_SIZE_BYTES, currentChunk: %d %d %d\n\n", Messages.str().size(), CHUNK_SIZE_BYTES, currentChunk);

        std::string chunk;
        chunk = Messages.str().substr(currentChunk * CHUNK_SIZE, CHUNK_SIZE);
        
        // convert std string to unsigned char array
        unsigned char* chunk_cstr = (unsigned char *)malloc(CHUNK_SIZE_BYTES);
        // memcpy(chunk_cstr,  (chunk.c_str()), CHUNK_SIZE_BYTES );
        memcpy(chunk_cstr,  (&Messages.str().c_str()[currentChunk * CHUNK_SIZE]), CHUNK_SIZE_BYTES );
        chunk_cstr = reinterpret_cast <unsigned char*>(chunk_cstr);

        for(int i = 0; i < CHUNK_SIZE; ++i)
        {
            printf("%02hhX", chunk_cstr[i]);
            fprintf(plaintext_hex_fd, "%02hhX", chunk_cstr[i]);
        }
        printf("\n");
        fprintf(plaintext_hex_fd, "\n");


        // convert std string to unsigned char array
        // unsigned char* key_cstr = (unsigned char *)malloc(key.size());
        // memcpy(key_cstr, key.c_str(), key.size() );
        // key_cstr = reinterpret_cast <unsigned char*> (key_cstr);

        // print key in hex, char by char
        // print_string_hex(reinterpret_cast<char*>(key_cstr), key.size());
        // printf ("\n\n");

        unsigned char* ciphertext_buffer =  (unsigned char*)malloc(CHUNK_SIZE_BYTES);
        memcpy(ciphertext_buffer, chunk_cstr, CHUNK_SIZE_BYTES);

        //==============================================================================
        // ENCRYPTION STEP        
        // encrypts data in buffer then returns ciphertext
        ciphertext_buffer = AESctr_encrypt(ciphertext_buffer, key_cstr);

        // compute HMAC 
        unsigned char HMAC[MAXBLOCKSIZE];
        HMAC_Computation(ciphertext_buffer, HMAC, key_cstr);
        HMAC_aggregate = HMAC_update(HMAC, HMAC_aggregate);

        // add ciphertext to ciphertexts_vector
        // push each unsigned char
        for(int i =0; i < CHUNK_SIZE; ++i)
        {
            ciphertexts_vector.push_back(ciphertext_buffer[i]);
            // printf("%02hhX", msg[i]);
        }
        // print HMAC to file
        for (int i = 0; i < MAXBLOCKSIZE; ++i)
        {
            HMACs_vector.push_back(HMAC[i]);
        }

        
        // free any mallocs here
        free(chunk_cstr);
        // free(key_cstr);
        free(ciphertext_buffer);
        // printf("===================================================================================\n");
    }

    // send cipher text

    // send HMAC


    //==============================================================================
    // write ciphertexts to file
    // FILE * ciphertexts_fd = fopen("TheCiphertexts.txt", "w");
    for (int i = 0; i < ciphertexts_vector.size(); ++i)
    {
        fprintf(ciphertexts_fd, "%02hhX", ciphertexts_vector.data()[i]);
    }

    // write HMACs to file
    // FILE * HMACs_fd = fopen("HMACs.txt", "w");
    for (int i = 0; i < HMACs_vector.size(); ++i)
    {
        fprintf(HMACs_fd, "%02hhX", HMACs_vector.data()[i]);
    }

    for (int i = 0; i < MAXBLOCKSIZE; ++i)
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
    // socket.send(request, ZMQ_SNDMORE);
    // socket.send(request, zmq::send_flags::sndmore);
    socket.send(request, zmq::send_flags::none);

    //send the cyphertext now
    // zmq::message_t request2(cyphertext, cyphertextSize);
    // socket.send(request2, zmq::send_flags::none);

    Messages_file.close();
    key_file.close();

    fclose(ciphertexts_fd);
    fclose(HMACs_fd);
    free(HMAC_aggregate);
}