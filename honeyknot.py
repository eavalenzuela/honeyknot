from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import argparse
import configparser
import hk_handler
import os, sys, time
import socket
import pdb

"""
Honeyknot: The Highly-Configurable Honeypot

honeyknot takes a response-definition file for each port you wish to run a honeypot on, which tells the service how to present itself.
Ports can be either HTTP, HTTPS or raw TCP. Responses are defined per-service, based on regex patterns.
All incoming data is saved raw(hex blob), ASCII-only, and in pcap formats.
"""

def run_from_interactive_shell(ip, use_custom_args, c_args):
    if use_custom_args:
        args = c_args
    else:
        # Empty object class mimicks argparse.Namespace
        class argContainer(object):
            pass
        # Instantiate and assign values
        args = argContainer()
        args.bind_ip = ip
        args.handler_dir = 'handlers/'
        args.definition_dir = 'definition_files/'
        args.thread_count = 5
        args.log_dir = 'logs/'
        args.v = False
        args.tv = False
    main_loop(args)

def main_loop(args):
    proc_pool_futures = server_port_process_pool(args)
    return proc_pool_futures

def server_port_process_pool(args):
    # Get port config files in handler_dir
    config_files = get_port_config_files(args)

    # Create process pools
    error_mssg = None
    futures = []
    with ProcessPoolExecutor(len(config_files)) as sppe:
        for pc_file in config_files:
            try:
                futures.append(sppe.submit(server_port_process, pc_file, args))
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
                    print('|--- port handler '+str(pc_file)+' exited abnormally.')
                    error_mssg = future.result()[2]
                    if error_mssg != None:
                        print('|--- port handler '+str(pc_file)+' error_mssg:')
                        print('|--- '+port_hnd_res[1])
                else:
                    print('|--- port handler closed: '+port_hnd_res[0])
    return futures

def server_port_process(port_config_file, args):
    rsp, error_mssg = server_port_thread_pool(port_config_file, args)
    hk_handler.write_error(error_mssg, port_config_file, args)
    return port_config_file

def server_port_thread_pool(port_config, args):
    error_mssg = None
    # Get port number from port_config file
    cfg = configparser.ConfigParser()
    try:
        cfg.read(args.handler_dir+str(port_config))
        socket_port = cfg['main']['port']
    except Exception as e:
        print('Error retrieving port number from config file: '+str(port_config))
        print(e)
        sys.exit(1)

    #####
    # hk_handler module thread-internal functions testing
    #####
    # hk_handler() function testing
    """
    dummy_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dummy_conn.bind((args.bind_ip, 9999))
    dummy_conn.listen(1)
    dummy_conn, addr = dummy_conn.accept()
    dc_data = dummy_conn.recv(2048)
    print(hk_handler.hk_handler(port_config, 'GET /huehuehue.php', dc_data, args))
    """
    # get_port_config_settings() function testing
    """
    print(hk_handler.get_port_config_settings(port_config, args))
    """
    #####

    # Create thread pool
    with ThreadPoolExecutor(int(args.thread_count)) as spte:
        # Create socket
        print('standing-up socket on '+str(socket_port)+'...')
        try:
            conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            conn_sock.bind((args.bind_ip, int(socket_port)))
        except Exception as se:
            print('socket construction error: ')
            print(se)
            sys.exit(1)
        futures = []
        for thread_num in range(int(args.thread_count)):
            if args.tv:
                print('|- running port handler '+str(port_config)+', thread '+str(thread_num))
            futures.append(spte.submit(server_port_thread, port_config, thread_num, None, args))
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
                        print('|- spawning replacement port handler for '\
                                'str(port_config)'\
                                ', thread '+str(thread_num))
                    
                    # Feed incoming request to idle thread
                    while True:
                        try:
                            client_sock, client_address = conn_sock.accept()
                            break
                        except Exception as e:
                            time.sleep(5)
                            continue
                    print('connection from '+str(client_address)+' on port '+str(port_config))

                    client_info = [client_address, client_sock]
                    futures.append(spte.submit(server_port_thread, port_config, thread_num, client_info, args))
    hk_handler.write_error(error_mssg, port_config, args)
    return futures, error_mssg

def server_port_thread(port_config, thread_num, client_info, args):
    error_mssg = None
    print('|-- port handler: '+str(port_config)+', thread: '+str(thread_num))
    
    # If first run, return
    if client_info == None:
        hk_handler.write_error(error_mssg, port_config, args)
        return thread_num, error_mssg
    else:
        client_address = client_info[0]
        client_connection = client_info[1]
        data = client_connection.recv(2048)
        if args.v:
            print(data)

    # Log raw request data
    logpath = args.log_dir+str(port_config)+'.log'
    try:
        with open(logpath, 'a') as rl:
            rl.write(str(client_address)+': '+str(data)+'\n')
    except TypeError as te:
        error_mssg = 'server-port_thread(): '+str(te)

    # Execute hk_handler
    try:
        error_mssg = hk_handler.hk_handler(port_config, data, client_connection, args)
        if args.v:
            print(error_mssg)
    except Exception as tk:
        tk = str(tk)
        error_mssg = 'server_port_thread(): '+tk
    hk_handler.write_error(error_mssg, port_config, args)
    return thread_num, error_mssg

def run():
    # Argument Processing
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--bind_ip', dest='bind_ip', help='IP address of interface to bind sockets to')
    parser.add_argument('--handler_directory', '-hd', dest='handler_dir', default='handlers/', help='path to folder containing files that define port handlers. See documentation for how to format handlers.')
    parser.add_argument('--definitions_directory', '-dd', dest='definition_dir', default='definition_files', help='path to folder containing service definiton json files')
    parser.add_argument('--log_directory', '-ld', dest='log_dir', default='logs/', help='path to folder to output log files to. Each service port will have its own logfile.')
    parser.add_argument('-v', action='store_true', default=False, help='enable verbose output')
    parser.add_argument('-tv', action='store_true', default=False, help='enable thread verbosity')
    parser.add_argument('-tc', '--thread_count', dest='thread_count', default=5, help='number of threads for each port process to manage (default 5)')
    args = parser.parse_args()

    # Call main loop-handler
    main_loop(args)
    return

def get_port_config_files(args):
    try:
        files = []
        for (_, _, filenames) in os.walk(args.handler_dir):
            files.extend(filenames)
        if args.v:
            print(files)
        if len(files) > 0:
            return files
        else:
            print('No configuration files found in target directory. Exiting.')
            sys.exit(1)
    except Exception as e:
        print(e)
        print('Configuration file enumeration failed. Exiting.')
        sys.exit(1)

if __name__ == "__main__":
    __spec__ = "ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>)"
    run()
