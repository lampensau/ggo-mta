# Copyright (c) 2023 Timo Toups
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
# copies of the Software, and to permit persons to whom the Software is 
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Author(s): 
# - Timo Toups <github@timotoups.de>
#
# Description: 
# This program is a multicast traffic analyzer built to monitor and analyze the 
# network traffic in a multicast group. It provides statistics about the traffic,
# like the amount of data received, bandwidth, lost packets, and jitter.

import argparse
import binascii
from collections import deque
import curses
import ipaddress
import json
import os
import socket
import sys
import threading
from threading import Event
import time

class Config:
    CONFIG_NAME = 'ggo_mta-default.config'
    SOCK_BUFFER_SIZE = 1024 * 2048
    DEQUE_SIZE = 1000
    PACKET_TYPES = {
        '5f8': '5f8',
        '600': '600',
        '608': '608',
        '688': '688',
        '068': '068',
        '060': '060'
    }
    PACKET_TYPE_688 = '688'
    MAX_PACKET_COUNTER = 255
    MAX_INTERVALS = {"updates": 2, "vox": 0.09}
    DEFAULT_DEVICE_TYPE = "Unknown"
    COLUMN_POSITIONS = [0, 17, 27, 32, 40, 47, 55, 71, 88, 96, 112]

class MulticastTrafficAnalyzer:
    def __init__(self, multicast_address, interface_address):
        # States
        self.running = False
        self.dialog_active = False
        # Multicast Socket
        self.multicast_address = multicast_address
        self.interface_address = interface_address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('', 5810))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(self.multicast_address) + socket.inet_aton(self.interface_address))
        self.subscribers = {}
        # UI
        self.update_event = Event()
        self.last_ui_update = 0
        self.ui_update_interval = 0.25
        # Logging        
        self.log_filename = self.generate_log_filename()

    def start(self):
        # Set flag
        self.running = True

        # Start curses
        self.stdscr = curses.initscr()

        # Initialize colors
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)

        # Setup curses
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)
        self.stdscr.nodelay(True)
        curses.curs_set(0)
        self.pad = curses.newpad(200, 200)
        

        # Start the UI update and process threads
        ui_thread = threading.Thread(target=self.update_ui)
        processing_thread = threading.Thread(target=self.process_packets)
        bandwidth_thread = threading.Thread(target=self.log_bandwidth)
        ui_thread.start()
        processing_thread.start()
        bandwidth_thread.start()

    def stop(self):
        # Set flag
        self.running = False
        self.update_event.set()
        # Reset curses
        curses.nocbreak()
        curses.curs_set(1)
        self.stdscr.keypad(False)
        curses.echo()
        curses.endwin()

    def update_ui(self):
        column_positions = Config.COLUMN_POSITIONS
        default_device_type = Config.DEFAULT_DEVICE_TYPE
        while self.running:
            # Get latest terminal size
            height, width = self.stdscr.getmaxyx()

            # Adjust pad size before performing any operations
            self.adjust_pad_size(height, width)
            self.refresh_screen()

            self.add_app_title()
            self.add_column_headers(column_positions)
            
            self.update_event.wait()
            self.update_event.clear()
            now = time.time()
            if now - self.last_ui_update > self.ui_update_interval:
                self.last_ui_update = now
                
            self.add_subscriber_stats(column_positions, default_device_type)
            self.refresh_screen()

    def adjust_pad_size(self, height, width):
        # Use the minimum of the terminal size and height/width to resize pad
        self.height = height
        self.width = width
        self.pad.resize(max(3, height), max(3, width))

    def refresh_screen(self):
        try:
            # Get the size of the terminal
            term_height, term_width = self.stdscr.getmaxyx()

            # Refresh only the visible part of the pad
            self.pad.refresh(0, 0, 0, 0, min(term_height - 1, self.height - 1), min(term_width - 1, self.width - 1))
        except Exception:
            pass

    def add_app_title(self):
        # Add application title
        title = "Green-GO"
        sub_title = f" Multicast Traffic Analyzer for '{self.multicast_address}'"
        self.addstr_to_pad(0, 0, title[:self.width], curses.color_pair(1) | curses.A_BOLD)
        if len(title) < self.width:
            self.addstr_to_pad(0, len(title), sub_title[:(self.width - len(title))], curses.A_BOLD)

    def add_column_headers(self, column_positions):
        # Add column headers
        headers = ["Source IP", "Device", "ENG", "Kbps", "Lost", "Updates", "Delta (s)", "Jitter (ms)", "Voice", "Delta (ms)", "Jitter (ms)"]

        for position, header in [(pos, head) for pos, head in zip(column_positions, headers) if pos < self.width]:
            self.addstr_to_pad(2, position, header[:(self.width - position)], curses.A_BOLD)

    def add_subscriber_stats(self, column_positions, default_device_type):

        # For each subscriber, print their stats
        row = 3
        for src_ip, engines in self.subscribers.items():
            for engine_id, stats in engines.items():
                # Clear the line before writing
                self.addstr_to_pad(row, 0, " " * self.width)
                self.add_engine_stats(column_positions, row, src_ip, engine_id, stats, default_device_type)
                row += 1

    def add_engine_stats(self, column_positions, row, src_ip, engine_id, stats, default_device_type):
        # Skip this engine if no packet of the wanted types has been received
        if not stats["packet_received"]:
            return

        self.addstr_to_pad(row, column_positions[0], src_ip)
        device_type = stats["device_type"] or default_device_type
        self.addstr_to_pad(row, column_positions[1], device_type)
        self.addstr_to_pad(row, column_positions[2], str(engine_id))
                    
        for packet_type in ("updates", "vox"):
            self.add_packet_type_stats(column_positions, row, stats, packet_type)
        self.addstr_to_pad(row, column_positions[3], self.format_bandwidth(stats["bandwidth_per_second"]))
        self.addstr_to_pad(row, column_positions[4], str(stats["lost_counter"]))

    def add_packet_type_stats(self, column_positions, row, stats, packet_type):
        packet_count = len(stats["packet_timestamps"][packet_type])
        deltas = stats["deltas"][packet_type]
        jitters = stats["jitters"][packet_type]
                        
        # If the packet type is 'vox', convert the time to milliseconds
        time_multiplier = 1000 if packet_type == "vox" else 1

        current_delta = self.format_time(deltas[-1] * time_multiplier) if deltas else self.format_time(0)
        avg_delta = self.format_time(sum(deltas) / len(deltas) * time_multiplier) if deltas else self.format_time(0)
        max_delta = self.format_time(max(deltas) * time_multiplier) if deltas else self.format_time(0)

        current_jitter = self.format_time(jitters[-1] * 1000) if jitters else self.format_time(0)
        avg_jitter = self.format_time(sum(jitters) / len(jitters) * 1000) if jitters else self.format_time(0)
        max_jitter = self.format_time(max(jitters) * 1000) if jitters else self.format_time(0)

        self.addstr_to_pad(row, column_positions[5 if packet_type == "updates" else 8], str(packet_count))
        self.addstr_to_pad(row, column_positions[6 if packet_type == "updates" else 9], f"{current_delta}/{avg_delta}/{max_delta}")
        self.addstr_to_pad(row, column_positions[7 if packet_type == "updates" else 10], f"{current_jitter}/{avg_jitter}/{max_jitter}")

    def reset_confirmation(self):
        self.dialog_active = True
        # Save the current state of the screen
        self.stdscr.refresh()
        y, x = self.stdscr.getmaxyx()
        
        # Create a new window for the popup
        popup = curses.newwin(6, 40, y//2-4, x//2-20)

        # Draw a box around the popup
        popup.border(0)
        popup.addstr(1, 6, "Reset all recorded counters?", curses.color_pair(2) | curses.A_BOLD)
        popup.addstr(3, 4, "Press Y to confirm, C to cancel.")

        # Set getch() to non-blocking mode
        popup.nodelay(True)

        start_time = time.time()
        countdown = 9
        while True:
            # Display a countdown bar at the bottom of the popup
            time_left = countdown - int(time.time() - start_time)
            bar_length = int((time_left / countdown) * 36)  # Scale the bar length to fit the popup
            popup.addstr(5, 1, f"[{'='*bar_length}{' '*(36-bar_length)}]")
            popup.refresh()

            # Wait for a key press
            key = popup.getch()

            # Check if the key is 'Y', 'C', or Enter
            if key in [ord('y'), ord('Y'), 10]:
                self.reset_counters()
                break
            elif key in [ord('c'), ord('C')]:
                break

            # Close the popup after 5 seconds
            if time.time() - start_time > countdown:
                break

            popup.refresh()  # Move this after refresh_pad() call

        # Clear the popup and refresh the screen
        popup.clear()
        self.stdscr.refresh()
        self.dialog_active = False

    def log_bandwidth(self):
        while self.running:
            time.sleep(1)
            now = time.time()
            
            for src_ip, engines in self.subscribers.items():
                for engine_id, subscriber in engines.items():
                    # Get the bytes received since the last update
                    bytes_received_last_second = subscriber["bytes_received"] - subscriber.get("bytes_received_last_update", 0)
                    
                    # Calculate bandwidth in Kbps
                    bandwidth_per_second_mbps = (bytes_received_last_second * 8) / (1 << 10)
                    
                    # Update bandwidth_per_second
                    subscriber["bandwidth_per_second"] = bandwidth_per_second_mbps
                    
                    # Update bytes_received_last_update
                    subscriber["bytes_received_last_update"] = subscriber["bytes_received"]

    def addstr_to_pad(self, y, x, str, attr=0):
        try:
            # Get the size of the terminal
            term_height, term_width = self.pad.getmaxyx()

            # Check if the coordinates are within the terminal size
            if y < term_height and x < term_width:
                # Truncate the string if it's wider than the remaining terminal width
                str = str[:max(0, term_width - x)]
                # Add the string to the pad
                self.pad.addstr(y, x, str, attr)
        except Exception:
            pass

    def process_packets(self):
        while self.running:
            data, (src_ip, src_port) = self.socket.recvfrom(Config.SOCK_BUFFER_SIZE)

            # Get variables from packet data
            packet_type, packet_counter, mac_address, engine_id = self.parse_packet(data)

            # Ignore packet if packet_type is 688
            if packet_type == Config.PACKET_TYPE_688:
                continue

            # Determine the device type based on the MAC address
            device_type = self.get_device_type(mac_address)

            # Add the packet to the subscriber's queue
            subscriber = self.initialize_subscriber(src_ip, engine_id, device_type, data)

            # Check for wanted packet types
            if packet_type in ('5f8', '600', '608', '060', '068'):
                subscriber["packet_received"] = True
                self.process_packet_timings(subscriber, packet_type, packet_counter)

            # Check and update packet counter
            self.update_lost_counter(src_ip, subscriber, engine_id, packet_type, packet_counter)

            # Update last_counter after checking the current packet_counter
            subscriber["last_counter"] = packet_counter
            
            if not self.dialog_active:
                self.update_event.set()

    def get_device_type(self, mac_address):
        if mac_address.startswith("000"):
            return "BridgeX"
        if mac_address.startswith("20"):
            return "BPX(SP)"
        elif mac_address.startswith("22"):
            return "MCX(D)"
        elif mac_address.startswith("213"):
            return "WPX"
        elif mac_address.startswith("211"):
            return "INTX/Q4WR"
        elif mac_address.startswith("216"):
            return "WAA"
        elif mac_address.startswith("217"):
            return "SiWR/RDX"
        return None

    def initialize_subscriber(self, src_ip, engine_id, device_type, data):
        if src_ip not in self.subscribers:
            self.subscribers[src_ip] = {}
        if engine_id not in self.subscribers[src_ip]:
            self.subscribers[src_ip][engine_id] = {
                "packet_received": False,
                "queue": deque(maxlen=Config.DEQUE_SIZE),
                "last_received": {"updates": time.time(), "vox": time.time()},
                "packet_timestamps": {"updates": [], "vox": []},
                "device_type": device_type,
                "deltas": {"updates": [], "vox": []},
                "jitters": {"updates": [], "vox": []},
                "bytes_received": 0,
                "bandwidth_per_second": 0,
                "last_counter": None,
                "lost_counter": 0
            }
        subscriber = self.subscribers[src_ip][engine_id]
        subscriber["queue"].append(data)
        subscriber["bytes_received"] += len(data)
        return subscriber

    def process_packet_timings(self, subscriber, packet_type, packet_counter):
        category = "updates" if packet_type in ('600', '608') else "vox"
        current_time = time.time()
        subscriber["packet_timestamps"][category].append(current_time)

        # Check and initialize definitions for keeping time
        timestamps = subscriber["packet_timestamps"][category]
        if "last_processed" not in subscriber:
            subscriber["last_processed"] = {}
        if category not in subscriber["last_processed"]:
            subscriber["last_processed"][category] = None
        last_processed = subscriber["last_processed"][category]

        # Check if we are outside the expected timing window
        if not timestamps or last_processed is None or timestamps[-1] - last_processed > Config.MAX_INTERVALS[category]:
            subscriber["last_processed"][category] = timestamps[-1] if timestamps else None
            return

        # Calculate and add latest delta time
        delta = timestamps[-1] - last_processed
        subscriber["deltas"][category].append(delta)

        # Calculation of jitter following the MEF 10 specification
        if len(subscriber["deltas"][category]) >= 2:
            jitter = abs(subscriber["deltas"][category][-1] - subscriber["deltas"][category][-2])
            subscriber["jitters"][category].append(jitter)

        # Update time record for next calculation
        subscriber["last_processed"][category] = timestamps[-1]

    def update_lost_counter(self, src_ip, subscriber, engine_id, packet_type, packet_counter):
        if subscriber["last_counter"] is not None:
            if packet_type == '5f8':
                expected_next_counter = (subscriber["last_counter"] + 2) % (Config.MAX_PACKET_COUNTER + 1)
            else:
                expected_next_counter = (subscriber["last_counter"] + 1) % (Config.MAX_PACKET_COUNTER + 1)

            # Calculate the difference in the counters taking into account the wrap around
            counter_difference = packet_counter - expected_next_counter
            if counter_difference < 0:
                counter_difference += (Config.MAX_PACKET_COUNTER + 1)

            if counter_difference != 0:
                self.log_missed_packets(src_ip, engine_id, packet_type, packet_counter, expected_next_counter, subscriber["lost_counter"])
                subscriber["lost_counter"] += counter_difference

    def parse_packet(self, packet):
        # Third byte for packet type
        third_byte = binascii.hexlify(packet[2:3]).decode()

        # Fourth byte half (first 4 bits) for packet type
        fourth_byte = binascii.hexlify(packet[3:4]).decode()
        fourth_byte_first_half = fourth_byte[0]

        # Concatenating the third byte and half of the fourth to form the key for packet type
        packet_type_key = third_byte + fourth_byte_first_half

        # Defining the packet types
        packet_types = Config.PACKET_TYPES

        # Determine packet type based on the third byte and half of the fourth byte
        packet_type = packet_types.get(packet_type_key, 'Unknown')

        # Fifth byte for packet counter
        packet_counter = int.from_bytes(packet[4:5], byteorder='big')
        
        # Extract the MAC address and reverse it
        mac_address = binascii.hexlify(packet[14:17]).decode()
        mac_address = "".join(reversed([mac_address[i:i+2] for i in range(0, len(mac_address), 2)]))

        # Byte 18 for engine ID
        engine_id = packet[17]

        return packet_type, packet_counter, mac_address, engine_id

    def reset_counters(self):
        # Reset the deltas and jitters for each subscriber
        for ip, engines in self.subscribers.items():
            for engine_id, stats in engines.items():
                stats["deltas"] = {"updates": [], "vox": []}
                stats["jitters"] = {"updates": [], "vox": []}
                stats["packet_timestamps"] = {"updates": [], "vox": []}
                stats["lost_counter"] = 0

    def format_time(self, delta):
        if delta >= 100:
            return "{:3.0f}".format(delta)
        elif delta > 9.9999999:
            return "{:2.1f}".format(delta)
        else:
            return "{:1.2f}".format(delta)

    def format_bandwidth(self, delta):
        if delta >= 1000:
            return "{:4.0f}".format(delta)
        if delta >= 100:
            return "{:3.1f}".format(delta)
        elif delta > 10:
            return "{:2.2f}".format(delta)
        else:
            return "{:1.3f}".format(delta)

    def generate_log_filename(self):
        # Get the current time and format it as a string to use in the filename
        now = time.strftime("%Y%m%d%H%M%S")
        filename = f'missed_packets-{now}.log'
        return filename

    def log_missed_packets(self, src_ip, engine_id, packet_type, packet_counter, expected_counter, lost_counter):
        # Define the data structure
        t = time.time()
        millisec = round((t - int(t)) * 1000)
        data = {
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + f".{millisec:03}",
            'src_ip': src_ip,
            'engine_id': engine_id,
            'packet_type': packet_type,
            'packet_counter': packet_counter,
            'expected_counter': expected_counter,
            'lost_counter': lost_counter,
        }

        # Open the file in append mode
        with open(self.log_filename, 'a') as f:
            # Convert the data to JSON and write to file
            f.write(json.dumps(data) + '\n')

def save_config(multicast_address, interface_address, filename=None):
    config = {"multicast_address": multicast_address, "interface_address": interface_address}
    filename = filename if filename else Config.CONFIG_NAME
    with open(filename, 'w') as configfile:
        json.dump(config, configfile)
    print(f"Saved configuration to {filename}")

def get_local_ip_addresses():
    local_ips = set()
    for info in socket.getaddrinfo(socket.gethostname(), None):
        ip = info[4][0]
        # Filter out IPv6 addresses
        if ipaddress.ip_address(ip).version == 4:
            local_ips.add(ip)
    return local_ips

def get_config_filename(multicast_address):
    # Replace dots with underscores and prepend with "ggo_mta-"
    filename = "ggo_mta-" + multicast_address.replace('.', '_') + ".config"
    return filename

def validate_args():
    local_ips = get_local_ip_addresses()

    # Create the parser
    parser = argparse.ArgumentParser(prog=os.path.basename(__file__), description='''Green-GO Multicast Traffic Analyzer
This program is a multicast traffic analyzer built to monitor and analyze the 
network traffic in a multicast group. It provides statistics about the traffic,
like the amount of data received, bandwidth, lost packets, and jitter.

key commands:
q: Quit the program
r: Reset all counters
s: Save to default configuration''',
                                     formatter_class=argparse.RawTextHelpFormatter)

    # Add the arguments
    parser.add_argument('multicast_address',
                        metavar='multicast_address',
                        type=str,
                        nargs='?',
                        help='Multicast IPv4 address to join and listen to. The multicast address for your Green-GO system can be found in the global configuration settings.')

    parser.add_argument('interface_address',
                        metavar='interface_address',
                        type=str,
                        choices=local_ips,
                        nargs='?',
                        help='Local interface IP address')

    parser.add_argument('-c', '--config',
                        metavar='config_file',
                        type=str,
                        help='The path to your custom configuration file. Default is ./ggo_mta-default.json.',
                        default=Config.CONFIG_NAME)

    # Parse the arguments
    args = parser.parse_args()

    # If no arguments are passed, try to load them from config.json
    if args.multicast_address is None or args.interface_address is None:
        try:
            with open(args.config, 'r') as configfile:
                config = json.load(configfile)
            args.multicast_address = config["multicast_address"]
            args.interface_address = config["interface_address"]
            print(f"Loaded configuration ({args.config}): Multicast: {args.multicast_address}, interface: {args.interface_address}")
        except (FileNotFoundError):
            print("Error: Configuration file not found or missing entries ({config})")
            sys.exit(1)
        except (KeyError):
            print("Error: Configuration file is missing entries.")
            sys.exit(1)

    # Check if the first argument is a valid multicast IPv4 address
    try:
        addr = ipaddress.IPv4Address(args.multicast_address)
        if not addr.is_multicast:
            print("Error: The first argument must be a valid multicast IPv4 address.")
            sys.exit(1)
    except ipaddress.AddressValueError:
        print("Error: The first argument is not a valid IPv4 address.")
        sys.exit(1)

    # Save the config for future runs
    save_config(args.multicast_address, args.interface_address, get_config_filename(args.multicast_address))

    return args

if __name__ == "__main__":
    try:
        args = validate_args()
        mta = MulticastTrafficAnalyzer(args.multicast_address, args.interface_address)
        mta.start()

        try:
            while mta.running:
                key = mta.stdscr.getch()
                if key == ord('q'):
                    mta.running = False
                elif key == ord('r'):
                    mta.reset_confirmation()
                elif key == ord('s'):
                    save_config(args.multicast_address, args.interface_address)
                    print("Default configuration saved.")
        finally:
            mta.stop()
    except KeyboardInterrupt:
        print("\nUser has closed the application.")
