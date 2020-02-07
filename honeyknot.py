from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import argparse
import configparser
import hk_handler
import os, sys, time
import socket

"""
Honeyknot: The Highly-Configurable Honeypot

honeyknot takes a response-definition file for each port you wish to run a honeypot on, which tells the service how to present itself.
Ports can be either HTTP, HTTPS or raw TCP. Responses are defined per-service, based on regex patterns.
All incoming data is saved raw(hex blob), ASCII-only, and in pcap formats.
"""

def main_loop(args):
    proc_pool_futures = server_port_process_pool(args)
    return proc_pool_futures

def server_port_process_pool(args):
    # Get port config files in handler_dir
    config_files = get_port_config_files(args)

    # Create process pools
    with ProcessPoolExecutor(len(config_files)) as sppe:
        futures = []
        for pc_file in config_files:
            futures.append(sppe.submit(server_port_process, pc_file, args))
        for future in as_completed(futures):
            if args.tv:
                if future.exception():
                    print('|--- port handler '+str(pc_file)+' exited abnormally.')
                else:
                    print('|--- port handler closed: '+str(future.result()))
    return futures

def server_port_process(port_config_file, args):
    rsp = server_port_thread_pool(port_config_file, args)
    return port_config_file

def server_port_thread_pool(port_config, args):
    # Create thread pool
    with ThreadPoolExecutor(5) as spte:
        # Create socket
        print('standing-up socket on '+str(port_config)+'...')
        try:
            conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            conn_sock.bind((args.bind_ip, 8080))
        except Exception as se:
            print('socket construction error: ')
            print(se)
            sys.exit(1)
        futures = []
        for i in range(5):
            if args.tv:
                print('|- running port handler '+str(port_config)+', thread '+str(i))
            futures.append(spte.submit(server_port_thread, [port_config, i], None, args))
        while True:
            # Move socket to listening
            conn_sock.listen(1)

            # Grab idle thread
            for future in as_completed(futures):
                if future.exception():
                    print(future.result())
                else:
                    thread_num = future.result()
                    if args.tv:
                        print('|- spawning replacement port handler for '\
                                'str(port_config)'\
                                ', thread '+str(thread_num))
                    
                    # Feed incoming request to idle thread
                    client_sock, client_address = conn_sock.accept()
                    print('connection from '+str(client_address)+' on port '+str(port_config))

                    futures.append(spte.submit(server_port_thread, [port_config, thread_num], client_sock, args))
    return futures

def server_port_thread(counters, client_connection, args):
    print('|-- port handler: '+str(counters[0])+', thread: '+str(counters[1]))
    
    # If first run, return
    if client_connection == None:
        return counters[1]
    else:
        data = client_connection.recv(2048)
        print(data)
    # Execute hk_handler
    try:
        hk_handler.hk_handler(counters[0], data, client_connection, args)
    except Exception as tk:
        print(tk)
    return counters[1]

def run():
    # Argument Processing
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', '--bind_ip', dest='bind_ip', help='IP address of interface to bind sockets to')
    parser.add_argument('--handler_directory', '-hd', dest='handler_dir', default='handlers/', help='path to folder containing files that define port handlers. See documentation for how to format handlers.')
    parser.add_argument('--log_directory', '-ld', dest='log_dir', default='logs/', help='path to directory to output log files to. Each service port will have its own logfile.')
    parser.add_argument('-v', action='store_true', default=False, help='enable verbose output')
    parser.add_argument('-tv', action='store_true', default=False, help='enable thread verbosity')
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
    run()
