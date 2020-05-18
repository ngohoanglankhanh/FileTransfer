import os, sys, getopt, ntpath
from netinterface import network_interface
from FTAkeyexchange import FTAkeyexchange
from FTAdatacipher import FTAdatacipher
from FTApayload import FTApayload
from Crypto import Random


own_addr = './client/'
server_addr = './server/'
network_path = './NETWORK/'
network_own_identifier = 'C'
network_server_identifier = 'S'
encrypted_keyfile = own_addr + 'encrypt_key'
user_workspace = 'HOME'
key = None

cmds_list = ['mkd', 'rmd', 'gwd', 'cwd', 'lst', 'upl', 'dnl', 'rmf']
request_code = b'\001'
response_code = b'\002'


def show_command_usage():
    print('\n--------------')
    print('COMMAND USAGE:')
    print('--------------')
    print('Create a folder: mkd <folder-path>')
    print('Remove a folder: rmd <folder-path>')
    print('Ask for the name of the current folder (working directory): gwd')
    print('Change the current folder (working directory): cwd <folder-path>')
    print('List the content of a folder: lst [<folder-path>]')
    print('Upload a file to a folder: upl [<destination-path>] <inputfile>')
    print('Download a file from a folder: dnl <inputfile> [<destination-path>]')
    print('Remove a file from a folder: rmf <file-path>\n')


def check_upl_cmd(cmd_args):
    # check if the inputfile path is valid and return its content in byte string
    inputfile = cmd_args[1] if len(cmd_args) == 2 else cmd_args[2]
    inputfile = own_addr + user_workspace + '/' + inputfile
    try:
        with open(inputfile, 'rb') as f:
            return f.read()
    except IOError:
        print('Error: Inputfile ' + inputfile + ' not found.')
        return None


def process_and_generate_payload(cmd_args, payload_factory):
    cmd = cmd_args[0]
    if cmd == 'upl': 
        extra = check_upl_cmd(cmd_args)
        if extra == None: 
            return None
        return payload_factory.generate_payload(cmd_args, extra=extra)

    if cmd == 'dnl' and len(cmd_args) == 3 and not os.path.exists(cmd_args[2]):
        print(cmd_args[2] + ' not found.')
        return None

    return payload_factory.generate_payload(cmd_args)


def process_server_command_response(serv_res, cmd_args):
    if serv_res[0] == 'ERROR':
        print(serv_res[0] + ': ' + serv_res[1])
    else:
        if cmd_args[0] != 'dnl':
            print(serv_res[0] + '... ' + serv_res[1])
        else:
            dnl_des = cmd_args[2] if len(cmd_args) == 3 else own_addr + user_workspace
            if (dnl_des[-1] != '/') and (dnl_des[-1] != '\\'): dnl_des += '/'

            with open(dnl_des + ntpath.basename(cmd_args[1]), 'wb') as f:
                f.write(serv_res[1].encode('utf-8'))

            print('OK... Downloaded file successfully, stored at ' + dnl_des + ntpath.basename(cmd_args[1]))


# ------------------------
# client environment setup
# ------------------------

# create client folder
if not os.path.exists(own_addr):
    print('Client environment at ' + own_addr + ' does not exist. Trying to create it... ', end='')
    os.mkdir(own_addr)
    print('Done.')

# create user workspace 
if not os.path.exists(own_addr + user_workspace):
    print('Client HOME workspace at ' + own_addr + user_workspace + ' does not exist. Trying to create it... ', end='')
    os.mkdir(own_addr + user_workspace)
    print('Done.')

# start network 
if not os.path.exists(network_path):
    print('Network path at ' + network_path + ' does not exist. Trying to create it... ', end='')
    os.mkdir(network_path)
    print('Done.')

netif = network_interface(network_path, network_own_identifier)

# -----------------
# key establishment 
# -----------------

# start a key exchange session
keyexchange = FTAkeyexchange(own_addr)
# generate a keypair for client
keyexchange.generateKeyPair()

# we need 256-bit key for data communication session 
key = Random.get_random_bytes(32) 

print('Encrypting new communication session key...')
keyexchange.encrypt_keyexchange(plaintext=key, des=server_addr, outputfile=encrypted_keyfile)

# read the encrypted session key and send to server 
with open(encrypted_keyfile, 'rb') as f:
    encrypted_key = f.read()

netif.send_msg(network_server_identifier, encrypted_key)

# waiting for server response about key establishment 
print('Waiting for server response about key establishment...')
status, msg = netif.receive_msg(blocking=True)   

# save encrypted server response to client workspace
print('Saving encrypted server response to client workspace...')
with open(encrypted_keyfile + '_reponse', 'wb') as f:
    f.write(msg)

# decrypt server response 
print('Decrypting server response on key establishment...')    
response = keyexchange.decrypt_keyexchange(sender=server_addr, inputfile=encrypted_keyfile + '_reponse')

# key establishment failed, exit the program 
if not response or response.decode('utf-8') == 'FAILED':
    print('Error: cannot establish communication session key with server')
    print('Please try again')
    sys.exit(1)

print('Server response: ' + response.decode('utf-8'))
print('Key establishment successful.')

# ---------------------------
# data communication exchange
# ---------------------------

datacipher = FTAdatacipher(key=key)
payload_factory = FTApayload()

for i in range(80):
    print('*', end='')

print('\nYou are now logged in and can start using the file transfer application.')

proceed = 'y'
while proceed == 'y':
    cmd = input('Enter a command or type -h for help: ').strip()

    if cmd == '-h':
        show_command_usage()
    else:
        # check if user command is valid. If not, show error and usage 
        args = cmd.split()
        if len(args) < 1 or args[0] not in cmds_list:
            print('Error: you entered an invalid command.')
            show_command_usage()

        # check if user command has a correct number of parameters
        elif(payload_factory.check_command_parameters(args)):
            payload = process_and_generate_payload(args, payload_factory)
            if payload != None:
                print('Sending command to server...')
                encrypted_cmd = datacipher.encrypt_message(payload, request_code)
                netif.send_msg(network_server_identifier, encrypted_cmd)
                print('Command sent.')

                print('Waiting for server response...')
                status, res = netif.receive_msg(blocking=True)
                decrypted_res = payload_factory.get_cmd_from_payload(datacipher.decrypt_message(res))
                process_server_command_response(decrypted_res, args)


    # ask to proceed?
    proceed = input('Do you want to continue? (y/n): ').strip()
    while proceed != 'y' and proceed != 'n':
        proceed = input('Do you want to continue? (y/n): ')


# End of a communication session between client and server 
print('Communication session terminated.')





