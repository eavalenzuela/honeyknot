import socket
import os
import configparser
import re

def hk_handler(port_config, data, client_connection, args):
    print('hk_handler')
    port_type, resp_dict, resp_headers = get_port_config_settings(port_config, args)
    # Check request data against responses
    for pair in resp_dict:
        if re.match(bytes(pair[0], encoding='utf-8'), data, re.IGNORECASE):
            if args.v:
                print(pair[0] + ' match found! Sending response.')

            # Construct full response
            response_data = ''
            for line in resp_headers:
                response_data += (line + '\n')
            response_data += '\n'
            response_data += pair[1]
            response_data += '\r\n'

            # Send response to client
            client_connection.sendall(bytes(response_data, encoding='utf-8'), 0)
            client_connection.close()
            return
    client_connection.close()
    return
    
def get_port_config_settings(port_config, args):
    try:
        cfp = configparser.ConfigParser()
        path = args.handler_dir+str(port_config)
        cfp.read(path)
    except configparser.ParsingError as cppe:
        print(cppe)
        print('Error parsing '+str(port_config)+' file. Exiting.')
    except TypeError as te:
        print(te)
    port = cfp['main']['port']
    port_type = cfp['main']['service_type']
    resp_dict = []
    for value in cfp['responses']:
        resp_dict.append([value, cfp['responses'][value]])
    if args.v:
        print(resp_dict)
    resp_headers = []
    for value in cfp['response_headers']:
        resp_headers.append(cfp['response_headers'][value])
    if args.v:
        print(resp_headers)
    return port_type, resp_dict, resp_headers

