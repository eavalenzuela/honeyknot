from typing import Optional

import service_loader

def write_error(error_mssg, port_config, args, error_logger=None):
    if error_mssg != None:
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'port': port_config,
            'error': error_mssg,
        }
        if error_logger:
            error_logger.error(json.dumps(log_entry))
        else:
            error_path = os.path.join(args.log_dir, f"{port_config}_errors.log")
            with open(error_path, 'a') as logfile:
                logfile.write(json.dumps(log_entry)+'\n')
    return

def hk_handler(port_config, data, client_connection, args, port_settings=None, error_logger=None):
    error_mssg = None

    if port_settings:
        port_type, resp_dict, resp_headers, response_type = port_settings
    else:
        port_type, resp_dict, resp_headers, response_type, error_mssg = get_port_config_settings(port_config, args)
    
    # Check request data against responses
    matched_rule = None
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
        error_mssg = 'hk.hk_handler: No responses detected. Closing connection and returning to parent.'
    client_connection.close()
    write_error(error_mssg, service.port, args)
    return error_mssg


def get_port_config_settings(port_config, args):
    """Legacy shim for existing callers relying on handler files.

    When given a port identifier, this function loads matching services from
    the handler directory and returns a tuple similar to the old API. It is
    deprecated in favor of using the new consolidated service schema.
    """

    services = service_loader.load_handler_directory(args.handler_dir, args.definition_dir)
    for service in services:
        if str(service.port) == str(port_config) or service.name == str(port_config):
            resp_dict = [[resp.match, resp.body] for resp in service.responses]
            return service.protocol, resp_dict, service.headers, None
    return '', '', '', f'hk.get_port_config_settings: No matching service for port {port_config}'
