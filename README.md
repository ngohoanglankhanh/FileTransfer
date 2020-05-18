# FileTransferArchitecture
An implementation of a file transfer application with strong focus on the security architecture over an unsecure network



This project is about security-focused design of a file transfer application. The application allows users to interact with a client via some user interface (command line) where they can enter commands related to file operations such as uploading files to and downloading files from a server, creating folders, listing the content of a folder, etc. The client then communicates with the server about the user's commands through an unsecure network and expects a response from the server if applicable. We assume that the server can only communicate with 1 logged-in user at a time. 

The project has two main phase:

Phase 1: Key establishment between client and server using RSA key pair generation and AES in CBC mode

Phase 2: Data (commands and data) communication session between client and server using AES in GCM mode


I recommend watching my demo video here:
https://drive.google.com/file/d/1nL_4J3Hw9_RF1l2zMhBMoQTH1dyetw2S/view?usp=sharing

Author: Khanh Ngo, AIT Applied Cryptography 
