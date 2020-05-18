import os, sys, time, shutil, ntpath
from netinterface import network_interface
from FTAkeyexchange import FTAkeyexchange
from FTAdatacipher import FTAdatacipher
from FTApayload import FTApayload
from pathlib import Path

own_addr = './server/'
client_addr = './client/'
network_path = './NETWORK/'
network_own_identifier = 'S'
network_client_identifier = 'C'
encrypted_keyfile = own_addr + 'encrypt_key'
default_client_wd = own_addr + 'client_HOME/'
current_client_wd = default_client_wd

request_code = b'\001'
response_code = b'\002'

cmds_list = ['mkd', 'rmd', 'gwd', 'cwd', 'lst', 'upl', 'dnl', 'rmf']

datacipher = None
netif = None
payload_factory = None


def send_error_response_to_client(error_mes):
    print('Sending command result (ERROR) to client...')
    cmd_args = ['ERROR', error_mes]
    encrypted_res = datacipher.encrypt_message(payload_factory.generate_payload(cmd_args), response_code)
    netif.send_msg(network_client_identifier, encrypted_res)
    print('Command result sent.')

def send_OK_response_to_client(extra=None):
    print('Sending command result (OK) to client...')
    cmd_args = ['OK']
    if extra != None: extra = extra.encode('utf-8')
    encrypted_res = datacipher.encrypt_message(payload_factory.generate_payload(cmd_args, extra), response_code)
    netif.send_msg(network_client_identifier, encrypted_res)
    print('Command result sent.')


def get_exact_path(path):
    global current_client_wd
    if (current_client_wd[-1] != '/') and (current_client_wd[-1] != '\\'): current_client_wd += '/'
    return current_client_wd + path if current_client_wd not in path else path

# ------------------------
# server environment setup
# ------------------------

if not os.path.exists(own_addr):
    print('Server environment ' + own_addr + ' does not exist. Trying to create it... ', end='')
    os.mkdir(own_addr)
    print('Done.')

# start connecting to network
if not os.path.exists(network_path):
    print('Network path at ' + network_path + ' does not exist. Trying to create it... ', end='')
    os.mkdir(network_path)
    print('Done.')    

netif = network_interface(network_path, network_own_identifier)

# create user workspace 
if not os.path.exists(default_client_wd):
    print('Client workspace at ' + default_client_wd + ' does not exist. Trying to create it... ', end='')
    os.mkdir(default_client_wd)
    print('Done.')

# -----------------
# key establishment 
# -----------------
keyexchange = FTAkeyexchange(own_addr)
keyexchange.generateKeyPair()

key = None

while not key:
    # waiting for encrypted key message from client
    print('Waiting for client\'s initiation of session key establishment...')
    status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message 

    # save encrypted key message to server database
    print('Saving encrypted keyfile to server database...')
    with open(encrypted_keyfile, 'wb') as f:
        f.write(msg)

    # decrypt session key file
    print('Decrypting session key established by client...')    
    key = keyexchange.decrypt_keyexchange(sender=client_addr, inputfile=encrypted_keyfile)

    # send key establishment result back to client
    print('Sending establishment result back to client...')
    feedback = 'OK'
    if not key: 
        print('Error: key establishment failed')
        feedback = 'FAILED'

    keyexchange.encrypt_keyexchange(plaintext=feedback.encode('utf-8'), des=client_addr, outputfile=encrypted_keyfile + '_response')

    # read encrypted response and send to client 
    with open(encrypted_keyfile + '_response', 'rb') as f:
        encrypted_key_response = f.read()

    netif.send_msg(network_client_identifier, encrypted_key_response)

print('Key establishment successful.')

# ---------------------------
# data communication exchange
# ---------------------------
datacipher = FTAdatacipher(key=key)
payload_factory = FTApayload()

for i in range(80):
    print('*', end='')

print('\nData communication exchange begins...')

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

while True:
    print('Waiting for user command from client...')
    status, msg = netif.receive_msg(blocking=True)
    payload = datacipher.decrypt_message(msg)

    if not payload:
        send_error_response_to_client('Message decryption failed.')
        continue

    cmd_args = payload_factory.get_cmd_from_payload(payload)
    cmd = cmd_args[0]
    print(cmd_args)

    # check if the command is valid 
    if cmd not in cmds_list:
        send_error_response_to_client('Command not found in the supported command list.')
        continue

    # check if the number of command arguments is correct 
    if False == payload_factory.check_command_parameters(cmd_args, server=True):
        send_error_response_to_client('Command argument check failed.')
        continue

    # start executing command 
    if cmd == 'mkd':
        path = get_exact_path(cmd_args[1])
        if not os.path.exists(path):
            Path(path).mkdir(parents=True, exist_ok=False)
            send_OK_response_to_client('new folder is stored at ' + path + '.')
        else:
            send_error_response_to_client('folder already exists.')

    elif cmd == 'rmd':
        path = get_exact_path(cmd_args[1])
        if path == default_client_wd:
            send_error_response_to_client('you cannot delete the default home directory at' + path + '.')
        elif os.path.exists(path):
            shutil.rmtree(path)
            send_OK_response_to_client('directory at ' + path + ' and all subfiles and subfolders were removed.')
        else:
            send_error_response_to_client('directory at ' + path + ' not found.')


    elif cmd == 'gwd':
        send_OK_response_to_client('current working directory: ' + current_client_wd + '.')

    elif cmd == 'cwd':
        new_wd = cmd_args[-1]
        if (new_wd[-1] != '/') and (new_wd[-1] != '\\'): new_wd += '/'
        if current_client_wd == new_wd:
            send_OK_response_to_client('working directory already set to ' + current_client_wd)
            continue

        path = get_exact_path(new_wd)
        if os.path.exists(new_wd) and default_client_wd in new_wd:
            path = new_wd

        if not os.path.exists(path):
            send_error_response_to_client('path ' + path + ' does not exist.')
        else:
            if (current_client_wd[-1] != '/') and (current_client_wd[-1] != '\\'): current_client_wd += '/'
            if (os.path.exists(new_wd) and default_client_wd in path) or current_client_wd in path:
                current_client_wd = path
            send_OK_response_to_client('changed working directory to ' + current_client_wd + '.')

    elif cmd == 'lst':
        if len(cmd_args) < 2:
            path = current_client_wd
        else:
            path = get_exact_path(cmd_args[1])

        if not os.path.exists(path):
            send_error_response_to_client('path ' + path + ' does not exist.')
        else:
            ls = os.listdir(path)
            if len(ls) == 0:
                send_OK_response_to_client('directory ' + path + ' is empty.')
            else:
                send_OK_response_to_client('here is the list: \n' + ', '.join(ls))


    elif cmd == 'upl':
        path = current_client_wd
        file_name = ntpath.basename(cmd_args[1])
        content = cmd_args[2]

        if len(cmd_args) > 3: 
            path = get_exact_path(cmd_args[1])
            file_name = ntpath.basename(cmd_args[2])
            content = cmd_args[3]

        if not os.path.exists(path):
            send_error_response_to_client('path ' + path + ' does not exist.')
        else:
            if (path[-1] != '/') and (path[-1] != '\\'): path += '/'
            with open(path + file_name, 'wb') as f:
                f.write(content.encode('utf-8'))

            send_OK_response_to_client('uploaded file ' + file_name + ' at ' + path)

    elif cmd == 'dnl':
        if not os.path.isfile(cmd_args[1]):
            send_error_response_to_client('file ' + cmd_args[1] + ' not found.')
        else:
            with open(cmd_args[1], 'rb') as f:
                content = f.read()

            send_OK_response_to_client(content.decode('utf-8'))


    elif cmd == 'rmf':
        path = get_exact_path(cmd_args[1])
        if os.path.isfile(path):
            os.remove(path)
            send_OK_response_to_client('file ' + path + ' was removed.')
        else:
            send_error_response_to_client('file ' + path + ' not found.')





