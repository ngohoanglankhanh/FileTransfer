import sys, os
import getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random


class FTAkeyexchange:
    pubkeyfileName = 'my_pubkeyfile.pem'
    privkeyfileName = 'my_privkeyfile.pem'
    pubkeyfile = ''
    privkeyfile = ''
    location = None

    def __init__(self, location):
        if (location[-1] != '/') and (location[-1] != '\\'): location += '/'
        self.location = location
        self.pubkeyfile = self.location + self.pubkeyfileName
        self.privkeyfile = self.location + self.privkeyfileName

    def _save_publickey(self, pubkey):
        with open(self.pubkeyfile, 'wb') as f:
            f.write(pubkey.export_key(format='PEM'))
        print('pubkey is saved at ' + self.pubkeyfile)

    def _load_publickey(self, pubkeyfile):
        with open(pubkeyfile, 'rb') as f:
            pubkeystr = f.read()
        try:
            return RSA.import_key(pubkeystr)
        except ValueError:
            print('Error: Cannot import public key from file ' + self.pubkeyfile)
            sys.exit(1)

    def _save_keypair(self, keypair):
        # The key pair contains the private key, so we want to save it protected with a passphrase
        # We use the getpass() function of the getpass class to input the passphrase from the user
        passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')

        # Export the key pair in PEM format protected with the passphrase and
        # save the result in the file privkeyfile
        with open(self.privkeyfile, 'wb') as f:
            f.write(keypair.export_key(format='PEM', passphrase=passphrase))
        print('keypair is saved at ' + self.privkeyfile)

    def _load_keypair(self):
        # We will need the passphrase to get access to the private key
        passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')

        with open(self.privkeyfile, 'rb') as f:
            keypairstr = f.read()
        try:
            # Import the key pair and return it
            return RSA.import_key(keypairstr, passphrase=passphrase)
        except ValueError:
            print('Error: Cannot import private key from file ' + self.privkeyfile)
            sys.exit(1)

    def _newline(self, s):
        return s + b'\n'

    def generateKeyPair(self):
        print('Generating a new 2048-bit RSA key pair...')
        keypair = RSA.generate(2048)
        self._save_publickey(keypair.publickey())
        self._save_keypair(keypair)
        print('Done')

    def encrypt_keyexchange(self, plaintext, des, outputfile):
        print('Encrypting...')

        # obtain pubkey of destination
        des_pubkey = self._load_publickey(des + self.pubkeyfileName)

        # create an RSA cipher object
        RSAcipher = PKCS1_OAEP.new(des_pubkey)

        # Apply PKCS7 padding on the plaintext (we want to use AES)
        padded_plaintext = Padding.pad(plaintext, AES.block_size, style='pkcs7')
        
        # Generate a random symmetric key and create an AES cipher object in CBC mode
        symkey = Random.get_random_bytes(32) # we need a 256-bit (32-byte) AES key
        AEScipher = AES.new(symkey, AES.MODE_CBC)

        # Store the IV of the AES cipher object in a variable
        iv = AEScipher.iv

        # Encrypt the padded plaintext with the AES cipher
        ciphertext = AEScipher.encrypt(padded_plaintext)

        # Encrypt the AES key with the RSA cipher
        encsymkey = RSAcipher.encrypt(symkey)

        # Compute signature 
        keypair = self._load_keypair()
        signer = pss.new(keypair)
        hashfn = SHA256.new()
        hashfn.update(encsymkey+iv+ciphertext)
        signature = signer.sign(hashfn)

        # Write out the encrypted AES key, the IV, the ciphertext, 
        # and the signature in base64 encoding
        with open(outputfile, 'wb') as f:
            f.write(self._newline(b'--- ENCRYPTED AES KEY ---'))
            f.write(self._newline(b64encode(encsymkey)))
            f.write(self._newline(b'--- IV FOR CBC MODE ---'))
            f.write(self._newline(b64encode(iv)))
            f.write(self._newline(b'--- CIPHERTEXT ---'))
            f.write(self._newline(b64encode(ciphertext)))
            f.write(self._newline(b'--- SIGNATURE ---'))
            f.write(self._newline(b64encode(signature)))

        print('Encryption done.')

    def decrypt_keyexchange(self, sender, inputfile):
        print('Decrypting...')

        #Read and parse the input...
        encsymkey = b''
        iv = b''
        ciphertext = b''

        with open(inputfile, 'rb') as f:        
            sep = f.readline()
            while sep:
                data = f.readline()
                data = data[:-1]   # removing \n from the end
                sep = sep[:-1]     # removing \n from the end

                if sep == b'--- ENCRYPTED AES KEY ---':
                    encsymkey = b64decode(data)
                elif sep == b'--- IV FOR CBC MODE ---':
                    iv = b64decode(data)
                elif sep == b'--- CIPHERTEXT ---':
                    ciphertext = b64decode(data)
                elif sep == b'--- SIGNATURE ---':
                    signature = b64decode(data)

                sep = f.readline()

        if (not encsymkey) or (not iv) or (not ciphertext):
            print('Error: Could not parse content of input file ' + inputfile)
            return None

        # Verify signature...
        # obtain pubkey of sender 
        sender_pubkey = self._load_publickey(sender + self.pubkeyfileName)

        # create an RSA PSS verifier object 
        verifier = pss.new(sender_pubkey)

        # create a SHA256 object
        hashfn = SHA256.new()

        # hash encsymkey+iv+ciphertext with SHA256
        hashfn.update(encsymkey+iv+ciphertext)

        #verifying signature
        try:
            verifier.verify(hashfn, signature)
            print('Signature verification is successful.')
        except (ValueError, TypeError):
            print('Signature verification is failed.') 
            return None

        # Load the private key (key pair) from privkeyfile and 
        #     create the RSA cipher object
        keypair = self._load_keypair()
        RSAcipher = PKCS1_OAEP.new(keypair)

        # Decrypt the AES key and create the AES cipher object (CBC mode is used)
        symkey = RSAcipher.decrypt(encsymkey)
        AEScipher = AES.new(symkey, AES.MODE_CBC, iv)
        
        # Decrypt the ciphertext and remove padding
        padded_plaintext = AEScipher.decrypt(ciphertext)
        plaintext = Padding.unpad(padded_plaintext, AES.block_size, style='pkcs7')
        
        print('Decryption done.')
        # return the decrypted key 
        return plaintext




