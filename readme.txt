Toy stream cipher, enhanced

Uses: SHA-256, HMAC, AES-CTR, hash chains
This is a toy version of a secure, professional, side-channel resistant logging machine (Alice) and auditor (Bob) scenario.
Alice encrypts 1024byte message chunks from "Messages.txt" using AES-CTR with a 256bit key file "InitialKey.txt".
Bob receives the ciphertext from Alice along with the aggregated HMAC. 
Bob has a copy of the initial key, and uses this to verify each 1024byte message sent by Alice. 
By computing the HMACs of each ciphertext message, then the aggregated HMAC, the message can be verified even before it is decrypted.

LINUX Requirements:
    libzmq3-dev
    libtomcrypt-dev

tested on popos 20.10
not tested on Windows or MacOS

NOTE: uses hard coded file names, these files are included

INSTRUCTIONS:
    run make to compile the programs from source
    run bob, then alice
    bob will wait to receive data from alice, then print a success message if the messages are verified.
