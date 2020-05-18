from Crypto.Cipher import AES
from Crypto import Random

class FTAdatacipher:
    key = None
    sqn_receive = 0
    sqn_send = 0

    def __init__(self, key):
        self.key = key

    def encrypt_message(self, payload, message_type):
        # compute payload_length and set authtag_length
        payload_length = len(payload)
        authtag_length = 16 # we'd like to use a 16-byte long authentication tag 

        # compute message length...
        # header: 16 bytes
            # version: 2 bytes
            # type:    1 btye (either request or response)
            # length:  2 bytes
            # sqn:     4 bytes
            # rnd:     7 bytes
        # payload: payload_length
        # authtag: authtag_length
        msg_length = 16 + payload_length + authtag_length

        # create header
        header_version = b'\x01\x01'                            # protocol version 1.1
        header_type = message_type                              # message type 1
        header_length = msg_length.to_bytes(2, byteorder='big') # message length (encoded on 2 bytes)
        header_sqn = (self.sqn_send + 1).to_bytes(4, byteorder='big')     # next message sequence number (encoded on 4 bytes)
        header_rnd = Random.get_random_bytes(7)                 # 7-byte long random value
        header = header_version + header_type + header_length + header_sqn + header_rnd

        # encrypt the payload and compute the authentication tag over the header and the payload
        # with AES in GCM mode using nonce = header_sqn + header_rnd
        nonce = header_sqn + header_rnd
        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
        AE.update(header)
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)

        # update sqn_send
        print('Update sqn_send...')
        self.sqn_send += 1
        print('Done.')

        return header + encrypted_payload + authtag


    def decrypt_message(self, encrypted_msg):
        # parse the message msg
        header = encrypted_msg[0:16]                # header is 16 bytes long
        authtag = encrypted_msg[-16:]               # last 16 bytes is the authtag
        encrypted_payload = encrypted_msg[16:-16]   # encrypted payload is between header and authtag
        header_version = header[0:2]      # version is encoded on 2 bytes 
        header_type = header[2:3]         # type is encoded on 1 byte 
        header_length = header[3:5]       # encrypted_msg length is encoded on 2 bytes 
        header_sqn = header[5:9]          # encrypted_msg sqn is encoded on 4 bytes 
        header_rnd = header[9:16]         # random is encoded on 7 bytes 

        print("Message header:")
        print("   - protocol version: " + header_version.hex() + " (" + str(header_version[0]) + "." + str(header_version[1]) + ")")
        print("   - message type: " + header_type.hex() + " (" + str(int.from_bytes(header_type, byteorder='big')) + ")")
        print("   - message length: " + header_length.hex() + " (" + str(int.from_bytes(header_length, byteorder='big')) + ")")
        print("   - message sequence number: " + header_sqn.hex() + " (" + str(int.from_bytes(header_sqn, byteorder='big')) + ")")
        print("   - random value: " + header_rnd.hex())

        # check the encrypted_msg length
        if len(encrypted_msg) != int.from_bytes(header_length, byteorder='big'):
            print("Warning: Message length value in header is wrong!")
            print("Processing is continued nevertheless...")

        # check the sequence number
        print("Expecting sequence number " + str(self.sqn_receive + 1) + " or larger...")
        sndsqn = int.from_bytes(header_sqn, byteorder='big')
        if (sndsqn <= self.sqn_receive):
            print("Error: Message sequence number is too old!")
            print("Processing completed.")
            return None    

        print("Sequence number verification is successful.")

        # verify and decrypt the encrypted payload
        print("Decryption and authentication tag verification is attempted...")
        nonce = header_sqn + header_rnd
        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        AE.update(header)

        try:
            payload = AE.decrypt_and_verify(encrypted_payload, authtag)
        except Exception as e:
            print("Error: Operation failed!")
            print("Processing completed.")
            return None

        print("Operation was successful: message is intact, content is decrypted.")

        # udpate sqn_receive 
        print('Updating sqn_receive...')
        self.sqn_receive = sndsqn
        print('Done.')

        return payload





