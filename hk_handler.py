from typing import Optional

import service_loader


def write_error(error_mssg, port_config, args):
    if error_mssg is not None:
        with open(args.log_dir + str(port_config) + '_errors.log', 'a') as logfile:
            logfile.write(error_mssg + '\n')
    return


def hk_handler(service, data, client_connection, args):
    error_mssg: Optional[str] = None
    matched_response = service.find_response(data)
    if matched_response:
        headers = matched_response.headers or service.headers
        if service.protocol == 'http':
            response_data = ''
            for line in headers:
                response_data += (line + '\n')
            response_data += '\n'
            response_data += matched_response.body
            response_data += '\r\n'
            client_connection.sendall(bytes(response_data, encoding=service.encoding), 0)
        else:
            response_bytes = matched_response.body.encode(service.encoding)
            client_connection.sendall(response_bytes, 0)
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
