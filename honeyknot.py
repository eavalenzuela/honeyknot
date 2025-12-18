import argparse
import hk_handler

import service_loader

"""
Honeyknot: The Highly-Configurable Honeypot
"""

def run_from_interactive_shell(ip, use_custom_args, c_args):
    if use_custom_args:
        args = c_args
    else:
        class argContainer(object):
            pass

        args = argContainer()
        args.bind_ip = ip
        args.handler_dir = "handlers/"
        args.definition_dir = "definition_files/"
        args.thread_count = 5
        args.log_dir = 'logs/'
        args.log_max_bytes = 1048576
        args.log_backup_count = 5
        args.capture_limit = 4096
        args.v = False
        args.tv = False
        args.service_schema = None
        args.export_schema = None
    main_loop(args)


def main_loop(args):


def _load_services(args):
    services = service_loader.load_service_definitions(
        args.service_schema, args.handler_dir, args.definition_dir, args.v
    )
    # Allow a CLI bind_ip override
    for service in services:
        if args.bind_ip:
            service.bind_ip = args.bind_ip
        elif not service.bind_ip:
            service.bind_ip = '0.0.0.0'
    return services


def server_port_process_pool(args):
    # Optionally perform a one-off migration from handler files to a schema
    if args.export_schema:
        service_loader.write_schema_from_handlers(args.handler_dir, args.definition_dir, args.export_schema)
        print(f"Legacy handler files exported to {args.export_schema}")
        return []

    services = _load_services(args)
    if not services:
        print('No configuration files found in target directory or schema. Exiting.')
        sys.exit(1)

    # Create process pools
    error_mssg = None
    futures = []
    with ProcessPoolExecutor(len(services)) as sppe:
        for service in services:
            try:
                futures.append(sppe.submit(server_port_process, service, args))
            except TypeError as te:
                print(te)
                print('TypeError encountered in server_port_process call(s)')
            except Exception as e:
                print(e)
                print('Generic Exception encoutnered in server_port_process call(s)')
        for future in as_completed(futures):
            if args.tv:
                port_hnd_res = future.result()
                if future.exception():
                    print('|--- port handler '+str(port_hnd_res)+' exited abnormally.')
                    error_mssg = future.result()[2]
                    if error_mssg != None:
                        print('|--- port handler '+str(port_hnd_res)+' error_mssg:')
                        print('|--- '+port_hnd_res[1])
                else:
                    print('|--- port handler closed: '+str(port_hnd_res))
    return futures


def server_port_process(service, args):
    rsp, error_mssg = server_port_thread_pool(service, args)
    hk_handler.write_error(error_mssg, service.port, args)
    return service.port


def server_port_thread_pool(service, args):
    error_mssg = None
    socket_port = service.port

    # Create thread pool
    with ThreadPoolExecutor(int(args.thread_count)) as spte:
        # Create socket
        print('standing-up socket on '+str(socket_port)+'...')
        try:
            conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            conn_sock.bind((service.bind_ip, int(socket_port)))
        except Exception as se:
            print('socket construction error: ')
            print(se)
            sys.exit(1)
        futures = []
        for thread_num in range(int(args.thread_count)):
            if args.tv:
                print('|- running port handler '+str(socket_port)+', thread '+str(thread_num))
            futures.append(spte.submit(server_port_thread, service, thread_num, None, args))
        while True:
            # Move socket to listening
            while True:
                try:
                    conn_sock.listen(1)
                    break
                except Exception as e:
                    print('socket listen_state exception')
                    time.sleep(5)
                    continue

            # Grab idle thread
            if args.v:
                print('Grabbing idle thread for connection processing...')
            for future in as_completed(futures):
                if future.exception():
                    print(future.result())
                else:
                    thread_num = future.result()[0]
                    error_mssg = future.result()[1]
                    if args.tv:
                        print('|- spawning replacement port handler for '+str(socket_port)+', thread '+str(thread_num))

                    # Feed incoming request to idle thread
                    while True:
                        try:
                            client_sock, client_address = conn_sock.accept()
                            break
                        except Exception as e:
                            time.sleep(5)
                            continue
                    print('connection from '+str(client_address)+' on port '+str(socket_port))

                    client_info = [client_address, client_sock]
                    futures.append(spte.submit(server_port_thread, service, thread_num, client_info, args))
    hk_handler.write_error(error_mssg, service.port, args)
    return futures, error_mssg


def server_port_thread(service, thread_num, client_info, args):
    error_mssg = None
    print('|-- port handler: '+str(service.port)+', thread: '+str(thread_num))

    # If first run, return
    if client_info == None:
        hk_handler.write_error(error_mssg, service.port, args)
        return thread_num, error_mssg
    else:
        client_address = client_info[0]
        client_connection = client_info[1]
        data = client_connection.recv(2048)
        if args.v:
            print(data)

    # Log raw request data
    logpath = args.log_dir+str(service.port)+'.log'
    try:
        with open(logpath, 'a') as rl:
            rl.write(str(client_address)+': '+str(data)+'\n')
    except TypeError as te:
        error_mssg = 'server-port_thread(): '+str(te)

    # Execute hk_handler
    matched_rule = None
    try:
        error_mssg = hk_handler.hk_handler(service, data, client_connection, args)
        if args.v:
            print(error_mssg)
    except Exception as tk:
        tk = str(tk)
        error_mssg = 'server_port_thread(): '+tk
    hk_handler.write_error(error_mssg, service.port, args)
    return thread_num, error_mssg


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--bind_ip', dest='bind_ip', help='IP address of interface to bind sockets to')
    parser.add_argument('--handler_directory', '-hd', dest='handler_dir', default='handlers/', help='path to folder containing files that define port handlers. See documentation for how to format handlers.')
    parser.add_argument('--definitions_directory', '-dd', dest='definition_dir', default='definition_files', help='path to folder containing service definiton json files')
    parser.add_argument('--service_schema', '-ss', dest='service_schema', default=None, help='path to a consolidated service schema (JSON or YAML)')
    parser.add_argument('--export_schema', '-es', dest='export_schema', default=None, help='write a consolidated schema (JSON) from legacy handler files then exit')
    parser.add_argument('--log_directory', '-ld', dest='log_dir', default='logs/', help='path to folder to output log files to. Each service port will have its own logfile.')
    parser.add_argument('--log_max_bytes', dest='log_max_bytes', type=int, default=1048576, help='maximum size in bytes for a log file before rotation occurs (default 1MB).')
    parser.add_argument('--log_backup_count', dest='log_backup_count', type=int, default=5, help='number of rotated log files to retain (default 5).')
    parser.add_argument('--capture_limit', dest='capture_limit', type=int, default=4096, help='maximum number of bytes to capture per request for hex dumps (default 4096).')
    parser.add_argument('-v', action='store_true', default=False, help='enable verbose output')
    parser.add_argument('-tv', action='store_true', default=False, help='enable thread verbosity')
    parser.add_argument('-tc', '--thread_count', dest='thread_count', default=5, help='number of threads for each port process to manage (default 5)')
    args = parser.parse_args()

    # Ensure log directory exists
    os.makedirs(args.log_dir, exist_ok=True)

    # Call main loop-handler
    main_loop(args)


def get_port_config_files(args):
    try:
        files = []
        for (_, _, filenames) in os.walk(args.handler_dir):
            files.extend(filenames)
        if len(files) > 0:
            return files
        else:
            print("No configuration files found in target directory. Exiting.")
            sys.exit(1)
    except Exception as e:
        print(e)
        print("Configuration file enumeration failed. Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    __spec__ = "ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>)"
    run()
