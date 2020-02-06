from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import argparse
import configparser
import hk_handler
import os, sys

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
            if args.v:
                print('|--- port handler closed: '+str(future.result()))
    return futures

def server_port_process(port_config_file, args):
    rsp = server_port_thread_pool(port_config_file, args)
    return port_config_file

def server_port_thread_pool(port_config, args):
    # Create thread pool
    with ThreadPoolExecutor(5) as spte:
        futures = []
        for i in range(5):
            if args.v:
                print('|- running port handler '+str(port_config)+', thread '+str(i))
            futures.append(spte.submit(server_port_thread, [port_config, i], args))
        for future in as_completed(futures):
            if future.exception():
                print(future.result())
    return futures

def server_port_thread(counters, args):
    print('|-- port handler: '+str(counters[0])+', thread: '+str(counters[1]))
    return 0

def run():
    # Argument Processing
    parser = argparse.ArgumentParser()
    parser.add_argument('--handler_directory', '-hd', dest='handler_dir', default='handlers/', help='path to folder containing files that define port handlers. See documentation for how to format handlers.')
    parser.add_argument('--log_directory', '-ld', dest='log_dir', default='logs/', help='path to directory to output log files to. Each service port will have its own logfile.')
    parser.add_argument('-v', action='store_true', default=False, help='enable verbose output')
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