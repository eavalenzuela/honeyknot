import socket
import os
import configparser

class ThreadKill(Exception):
    print("we're dunzo")

def hk_handler(port_config, args):
    cfp = configparser.ConfigParser()
    try:
        cfp.read(args.handler_dir+port_config)
    except configparser.ParsingError as cppe:
        print(cppe)
        print('Error parsing '+str(port_config)+'file. Exiting.')
        raise ThreadKill
    port = cfp['port']
    port_type = cfp['service_type']
    resp_dict = []
    for value in cfp['responses']:
        resp_dict.append([value, cfp['responses'][value]])
    if args.v:
        print(resp_dict)

    return
