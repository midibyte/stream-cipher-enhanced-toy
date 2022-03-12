Toy stream cipher

LINUX Requirements:
    libzmq3-dev
    libtomcrypt-dev

tested on popos 20.10

NOTE: using demo code as reference

NOTE: uses hard coded file names as described in the project description.

INSTRUCTIONS:
    run make to compile the programs from source
    run bob, then alice

Project outline:
    alice:
        reads in plaintext, then shared key
        hashes the content of plain text, then prints to terminal shown in hex format.
            NOTE: the hex is padded so that each bytes is always two characters
                for example: 0x1 = 0x01
        computes the cyphertext, writes it to TheCiphertext.txt file in hex format
        sends the hash and the cyphertext to bob using zmq
    
    bob:
        reads in the shared secret from sharedSecret.txt
        receives the hash and cyphertext from alice using zmq
        computes the plaintext using the shared key and the cyphertext from bob
        writes plaintext to BobPlaintext.txt 
        hashes the plaintext, prints it to terminal, writes it to Bob_h.txt
        compares the hash received from alice with the computed hash
        prints if they match or not to the terminal



Other Notes: 
    very important to use this format when creating a zmq message
        message_t(void* data, size_t len)