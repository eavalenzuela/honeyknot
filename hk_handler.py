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
    port_type, resp_dict, resp_headers, response_type, error_mssg = get_port_config_settings(port_config, args)
    # Check request data against responses
    if len(resp_dict) > 0:
        for pair in resp_dict:
            pattern = pair[0] if isinstance(pair[0], (bytes, bytearray)) else bytes(pair[0], encoding='utf-8')
            if re.match(pattern, data, re.IGNORECASE):
                if args.v:
                    print(str(pair[0]) + ' match found! Sending response.')

                if response_type == 'bytes':
                    response_data = pair[1] if isinstance(pair[1], (bytes, bytearray)) else bytes(pair[1], encoding='utf-8')
                    client_connection.sendall(response_data, 0)
                else:
                    response_body = pair[1] if isinstance(pair[1], str) else pair[1].decode('utf-8')

                    # Construct full response
                    response_data = ''
                    if len(resp_headers) > 0:
                        for line in resp_headers:
                            response_data += (line + '\n')
                    response_data += '\n'
                    response_data += response_body
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
    """Parse a service definition file into regex/response pairs.

    The function expects a dictionary with at least the following keys:
    - service
    - service_type
    - communication_dicts: a list of dictionaries containing a 'regex'
      pattern and a 'return' payload.

    The optional 'response_type' key controls how payloads are encoded.
    When set to 'bytes' both regex patterns and return payloads will be
    converted to bytes to allow binary comparisons.
    """

    required_keys = ['service', 'service_type', 'communication_dicts']
    for key in required_keys:
        if key not in json_data:
            raise ValueError(f"Missing required key '{key}' in definition file")

    response_type = json_data.get('response_type', 'text')
    comms = json_data.get('communication_dicts', [])
    if not isinstance(comms, list) or len(comms) == 0:
        raise ValueError('communication_dicts must be a non-empty list')

    resp_dict = []
    for comm in comms:
        if 'regex' not in comm or 'return' not in comm:
            raise ValueError('Each communication_dict must contain regex and return keys')

        regex_pattern = comm['regex']
        return_payload = comm['return']
        if isinstance(return_payload, dict) and 'value' in return_payload:
            return_payload = return_payload['value']

        if response_type == 'bytes':
            regex_pattern = regex_pattern if isinstance(regex_pattern, (bytes, bytearray)) else bytes(regex_pattern, encoding='utf-8')
            if isinstance(return_payload, (bytes, bytearray)):
                encoded_payload = return_payload
            else:
                encoded_payload = bytes(str(return_payload), encoding='utf-8')
            resp_dict.append([regex_pattern, encoded_payload])
        else:
            resp_dict.append([str(regex_pattern), str(return_payload)])

    resp_headers = json_data.get('response_headers', [])
    return resp_dict, resp_headers, response_type

def get_port_config_settings(port_config, args):
    error_mssg = None
    try:
        cfp = configparser.ConfigParser()
        path = args.handler_dir+str(port_config)
        cfp.read(path)
    except configparser.ParsingError as cppe:
        error_mssg = 'hk.get_port_config_settings: '+str(cppe)
        return '', '', '', '', error_mssg
    except TypeError as te:
        error_mssg = 'hk.get_port_config_settings: '+str(te)
        return '', '', '', '', error_mssg
    except Exception as ge:
        error_mssg = 'hk.get_port_config_settings: '+str(ge)
        return '', '', '', '', error_mssg
    port = cfp['main']['port']
    port_type = cfp['main']['service_type']
    response_type = 'text'
    resp_dict = []
    resp_headers = []
    if cfp.has_option('main', 'definition_file'):
        try:
            with open(args.definition_dir+cfp['main']['definition_file'], 'r') as def_file:
                raw_json = json.load(def_file)
                resp_dict, resp_headers, response_type = json_definition_parser(raw_json, args)
                return port_type, resp_dict, resp_headers, response_type, error_mssg
        except Exception as ge:
            error_mssg = 'hk.get_port_config_settings: '+str(ge)
            return '', '', '', '', error_mssg
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
        return '', '', '', '', error_mssg
    return port_type, resp_dict, resp_headers, response_type, error_mssg

