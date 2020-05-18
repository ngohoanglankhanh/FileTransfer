
class FTApayload:
    cmd_codes = {'mkd':0, 'rmd':1, 'gwd':2, 'cwd':3, 'lst':4, 'upl':5, 'dnl':6, 'rmf':7, 'OK':8, 'ERROR': 9}
    cmd_codes_id = {0:'mkd', 1:'rmd', 2:'gwd', 3:'cwd', 4:'lst', 5:'upl', 6:'dnl', 7:'rmf', 8:'OK', 9:'ERROR'}

    def __init__(self):
        pass

    def check_command_parameters(self, cmd_args, server=False):
        cmd = cmd_args[0]
        if cmd == 'gwd' and len(cmd_args) > 1:
            print('Error: too many arguments for command ' + cmd)
            return False

        if cmd == 'lst' and len(cmd_args) > 2:
            print('Error: too many arguments for command ' + cmd)
            return False

        # case: commands with at least 1 argument
        if cmd != 'gwd' and cmd != 'lst' and len(cmd_args) < 2:
            print('Error: command ' + cmd + ' is missing an argument')
            return False

        # case: commands with at most 1 argument
        if (cmd == 'mkd' or cmd == 'rmd' or cmd == 'cwd' or cmd == 'rmf') and len(cmd_args) > 2:
            print('Error: too many arguments for command ' + cmd)
            return False

        # case: commands with at most 2 arguments
        if (cmd == 'upl' or cmd == 'dnl') and len(cmd_args) > 3:
            if not server:
                print('Error: too many arguments for command ' + cmd)
                return False

        return True

    def generate_payload(self, cmd_args, extra=None):
        # cmd type: 1 byte
        # number of parameters: 1 byte
        # parameter length: 4 bytes
        cmd = cmd_args[0]
        cmd_type = self.cmd_codes[cmd].to_bytes(1, byteorder='big')

        if extra != None:
            para_num = len(cmd_args).to_bytes(1, byteorder='big')
        else:
            para_num = (len(cmd_args) - 1).to_bytes(1, byteorder='big')
        payload = cmd_type + para_num

        # for each parameter, append its length and value to the payload
        for i in range(1, len(cmd_args)):
            payload += len(cmd_args[i]).to_bytes(4, byteorder='big')
            payload += cmd_args[i].encode('utf-8')

        if extra != None: 
            payload += len(extra).to_bytes(4, byteorder='big')
            payload += extra

        return payload

    def get_cmd_from_payload(self, payload):
        # cmd type: 1 byte
        # number of parameters: 1 byte
        # parameter length: 4 bytes
        cmd_type = int.from_bytes(payload[0:1], byteorder='big')
        cmd_type = self.cmd_codes_id[cmd_type]
        para_num = int.from_bytes(payload[1:2], byteorder='big')

        cmd_args = [None] * (para_num + 1)
        cmd_args[0] = cmd_type

        ptr = 2
        for i in range(1, len(cmd_args)):
            para_len = int.from_bytes(payload[ptr:ptr+4], byteorder='big')
            ptr += 4
            cmd_args[i] = payload[ptr:ptr+para_len].decode('utf-8')
            ptr += para_len

        return cmd_args






