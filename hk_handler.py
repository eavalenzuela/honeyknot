import socket
import os
import configparser
import re
import json

def write_error(error_mssg, port_config, args):
    if error_mssg != None:
        with open(args.log_dir+str(port_config)+'_errors.log', 'a') as logfile:
            logfile.write(error_mssg+'\n')
    return

def hk_handler(port_config, data, client_connection, args):
    error_mssg = None
    port_type, resp_dict, resp_headers, error_mssg = get_port_config_settings(port_config, args)
    # Check request data against responses
    if len(resp_dict) > 0:
        for pair in resp_dict:
            if re.match(bytes(pair[0], encoding='utf-8'), data, re.IGNORECASE):
                if args.v:
                    print(pair[0] + ' match found! Sending response.')

                # Construct full response
                response_data = ''
                if len(resp_headers) > 0:
                    for line in resp_headers:
                        response_data += (line + '\n')
                response_data += '\n'
                response_data += pair[1]
                response_data += '\r\n'

                # Send response to client
                client_connection.sendall(bytes(response_data, encoding='utf-8'), 0)
                client_connection.close()
    else:
        error_mssg = 'hk.hk_handler: '+'No responses detected. Closing connection and returning to parent.'
    client_connection.close()
    write_error(error_mssg, port_config, args)
    return error_mssg

def json_definition_parser(json_data, args):
    return [['*', 'bebebe']], ['huehueh']

def get_port_config_settings(port_config, args):
    error_mssg = None
    try:
        cfp = configparser.ConfigParser()
        path = args.handler_dir+str(port_config)
        cfp.read(path)
    except configparser.ParsingError as cppe:
        error_mssg = 'hk.get_port_config_settings: '+str(cppe)
        return '', '', '', error_mssg
    except TypeError as te:
        error_mssg = 'hk.get_port_config_settings: '+str(te)
        return '', '', '', error_mssg
    except Exception as ge:
        error_mssg = 'hk.get_port_config_settings: '+str(ge)
        return '', '', '', error_mssg
    port = cfp['main']['port']
    port_type = cfp['main']['service_type']
    if cfp.has_option('main', 'definition_file'):
        try:
            with open(args.definition_dir+cfp['main']['definition_file'], 'r') as def_file:
                raw_json = json.loads(def_file.readlines())
                resp_dict, resp_headers = json_definition_parser(raw_json, args)
                return port_type, resp_dict, resp_headers, error_mssg
        except Exception as ge:
            error_mssg = 'hk.get_port_config_settings: '+str(ge)
            return '', '', '', error_mssg
    elif cfp['main']['service_type'] == 'http':
        resp_dict = []
        if cfp.has_section('responses'):
            for value in cfp['responses']:
                resp_dict.append([value, cfp['responses'][value]])
            if args.v:
                print(resp_dict)
            resp_headers = []
            for value in cfp['response_headers']:
                resp_headers.append(cfp['response_headers'][value])
            if args.v:
                print(resp_headers)
    else:
        error_mssg = 'hk.get_port_config_settings: '+'No definition file present, and not an HTTP service with a "responses" section. Exiting.'
        return '', '', '', error_mssg
    return port_type, resp_dict, resp_headers, error_mssg

