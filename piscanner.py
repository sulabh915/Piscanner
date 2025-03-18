from argparse import ArgumentParser
import socket
import threading
from datetime import datetime
from time import time
from queue import Queue
import ipaddress
import sys
import os
import subprocess
from tabulate import tabulate



class Documentation_options:
                """options and Documentation of program"""

                def prepare_arg():
                        parser = ArgumentParser(
                        description="Python Advance Port Scanner",
                        usage="python3 %(prog)s 192.168.1.1",
                        epilog="Example Usage: python3 %(prog)s -tT -sp 22 -th 300 -sd -b -v scanme.nmap.org"
                        )

                        # Required positional argument: Target (IP, CIDR range, or domain)
                        parser.add_argument(
                        dest="ip", 
                        metavar="IPv4",
                        help="Target IP (e.g., 192.168.1.1), CIDR range (e.g., 192.168.1.0/24), or domain (e.g., scanme.nmap.org)"
                        )

                        # Mutually exclusive group for scan type (TCP or UDP)
                        scan_type = parser.add_mutually_exclusive_group(required=True)
                        scan_type.add_argument("-tT", "--tcp",dest='tcp', action="store_true", help="Perform a TCP scan")
                        scan_type.add_argument("-tU", "--udp",dest='udp', action="store_true", help="Perform a UDP scan")

                        # Port range and single port options
                        port_group = parser.add_mutually_exclusive_group()

                        # Single port scan (`-sp`)
                        port_group.add_argument("-sp", "--single-port", dest="single",metavar='', type=str, help="Scan a single port")

                        # Port range scan (`-rp range to scah`)
                        port_group.add_argument("-rp", "--range-port", dest="range",metavar='', type=str, help="range port e.g.,1-1000")
                        
                        # Number of threads
                        parser.add_argument("-th", "--threads",dest='thread',metavar='', type=int, default=200, help="Number of threads to use (default: 200)")

                        # Additional scan options
                        parser.add_argument("-sd", "--service",dest="service",action="store_true", help="Enable service detection")
                        parser.add_argument("-b", "--banner", dest="banner",action="store_true", help="Enable banner grabbing")

                        # Output file
                        parser.add_argument("-o", "--output",dest='output',type=str,metavar='', help="Save scan results to a file")

                        # Verbose mode
                        parser.add_argument("-V", "--verbose", dest='verbose',action="store_true", help="Enable verbose output")

                        # Version info
                        parser.add_argument("-v","--version", action="version", version="%(prog)s 1.0", help="Display scanner version")

                        args = parser.parse_args()

                        
                     

                        return args


class Port_Scanner(Documentation_options):
        """class for port scanner related tasks."""

        



        def prepare_target(target):
                """Resolve target (IP, CIDR, or hostname) and return only live hosts."""
                
                live_hosts = []  # ✅ Store only alive hosts
                threads = []  # ✅ Store threads for parallel execution

                def ping_host(ip):
                        """Pings an IP and adds it to live_hosts if reachable."""
                        param = "-n" if sys.platform.startswith("win") else "-c"
                        result = subprocess.run(["ping", param, "1", str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                        if result.returncode == 0 and "unreachable" not in result.stdout.decode().lower():
                                live_hosts.append(str(ip))  # ✅ Add to live hosts list

                try:
                        # ✅ If target is a CIDR range (e.g., "192.168.1.0/24")
                        if '/' in target:
                                try:
                                        network = ipaddress.ip_network(target, strict=False)
                                        for ip in network.hosts():  # Exclude network & broadcast IPs
                                        # ✅ Start a thread for each IP in the range
                                                for ip in network.hosts():
                                                        thread = threading.Thread(target=ping_host, args=(str(ip),))
                                                        threads.append(thread)
                                                        thread.start()

                                                # ✅ Wait for all threads to finish
                                                for thread in threads:
                                                        thread.join()

                                                return live_hosts if live_hosts else None  # ✅ Return None if no hosts are alive

                                except ValueError:
                                        print("❌ Invalid CIDR notation or IP")
                                        sys.exit()
                                        return None  

                        # ✅ If target is already an IP, check if it's alive
                        elif target.replace('.', '').isdigit():  # IPv4 Address
                                try:
                                        ipaddress.ip_address(target)  # ✅ Validate IP Address Format
                                except ValueError:
                                        print(f"❌ Error: {target} is not a valid IP address.")
                                        sys.exit(1)  # ✅ Exit for invalid IP format
                                param = "-n" if sys.platform.startswith("win") else "-c"
                                result = subprocess.run(["ping", param, "1", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                
                                return [target] if result.returncode == 0 and "unreachable" not in result.stdout.decode().lower() else None  # ✅ Return None if host is down

                        # ✅ Otherwise, resolve hostname to an IP and check if it's alive
                        else:
                                target_ip = socket.gethostbyname(target)

                                param = "-n" if sys.platform.startswith("win") else "-c"
                                result = subprocess.run(["ping", param, "1", target_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                                return [target] if result.returncode == 0 and "unreachable" not in result.stdout.decode().lower() else None
  # ✅ Return None if resolved host is down

                except socket.gaierror:
                        print("❌ Invalid hostname")
                        sys.exit()
                        return None  # ✅ Return None if resolution fails

                                        


        def prepare_ports(single_port:str,range_port:str):
                """takes single port and range port in argument return the list 
                also return default 1-1000 ports if not specify
                """

                if single_port is not None:
                       ports = []
                       try:
                                for port in single_port.split(','):
                                        port = int(port.strip())

                                        if not (1 <= port <= 65535):  # Ensure within valid range
                                                print(f"❌ Error: Invalid port: {port}. Port must be between 1 and 65535.")
                                                sys.exit()
                                        ports.append(port)
                                return ports  # ✅ Return single port or list of ports as a list
                       except ValueError:
                                        print("❌ Error: Invalid format for `-sp`. Use format: 22,21,80")
                                        sys.exit()
                               

                if range_port is not None:
                        try:
                                start, end = map(int, range_port.split('-'))  # Convert "1-1000" → (1, 1000)
                        except ValueError:
                                print("❌ Error: Invalid format for `-rp`. Use format: 1-1000")
                                sys.exit()

                        # ✅ Ensure valid port numbers (1-65535)
                        if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                                print(f"❌ Error: Invalid range: Ports must be between 1-65535. You entered: {start}-{end}")
                                sys.exit()

                        # ✅ Ensure `start` is not greater than `end`
                        if start > end:
                                print(f"❌ Error: Start port {start} cannot be greater than end port {end}.")
                                sys.exit()
                        
                        return list(range(start, end + 1))  # ✅ Return list of ports

                if single_port is None and range_port is None:
                       
                        return list(range(1,1000+1))

        global queue
        queue = Queue()
        def fill_queue(port_list):
                for port in port_list:
                        queue.put(port)
        def new_port():
                ports = []
                while not queue.empty():
                        port = queue.get()
                        ports.append(port)

                return ports
                        
                

                
        
        def scan_ports(target,ports,service,banner,scan_type,verbose,output,num_threads=10):
                """Scans for open ports, retrieves banners & services if enabled.
        
                        - `target`: IP or hostname to scan
                        - `ports`: List of ports to scan
                        - `service`: Boolean, fetch service if True
                        - `banner`: Boolean, grab banner if True
                        - `scan_type`: Tuple of scan types (e.g., ('tcp', 'udp'))

                        Returns:
                                List of tuples [(port, protocol, status, banner/service)]
               """

                results = []
                queue = Queue()

                def getbanner(sock):
                        """Attempts to retrieve the banner from an open port."""
                        try:
                                sock.settimeout(2)
                                return sock.recv(1024).decode().strip()
                        except:
                                return "Unknown Banner"
                
                def getservice(port):
                         """Returns the service name for a given port using well-known services."""
                         try:
                                return socket.getservbyport(port)
                         except:
                                return "Unknown Service"


                def tcp_scan(t,p):
                        """Performs a TCP port scan."""
                        try:
                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                        sock.settimeout(1)
                                        result = sock.connect_ex((t, p))
                                        if result == 0:
                                                serv = getservice(p) if service else "N/A"
                                                ban = getbanner(sock) if banner else "N/A"
                                                if verbose:
                                                        print(f"✅ [{t}][TCP {p}] {serv} | {ban}")
                                                if verbose and output:
                                                        f = open(output,'a',encoding="utf-8")
                                                        f.write(f"\n✅ [{t}][TCP {p}] {serv} | {ban}")
                                                        f.close()

                                                results.append((t, p, "TCP", "Open", serv, ban))
                                        else:
                                                results.append((t,p,"TCP","Closed","N/A","N/A"))
                                        
                        except Exception as e:
                                        print(f"❌ Error TCP {p}: {e}")
                        finally:
                                sock.close()

                def udp_scan(t,p):
                        
                                                """Performs a UDP port scan."""
                                
                                                try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock.settimeout(10)  # UDP has no connection, so we wait for a response

                                                        sock.sendto(b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00 \x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x00\x00\x20\x00\x01", (t, p))  # ✅ Send dummy data

                                                        try:
                                                                        data, _ = sock.recvfrom(1024)  # ✅ Try receiving response
                                                                        response = "Open"
                                                                        ban = data.decode(errors="ignore").strip() if banner else "N/A"


                                                        except socket.timeout:
                                                                        response = "No Response (Possibly Open/Filtered)"
                                                                        ban = "Unknown Banner"

                                                        except ConnectionResetError:
                                                                        response = "Closed (ICMP Port Unreachable)"  # ✅ Some OSes send ICMP "port unreachable"
                                                                        ban = "N/A"

                                                        serv = getservice(p) if service else "N/A"

                                                        if response == "Open":
                                                                if verbose:     
                                                                        print(f"✅ [{t}][UDP] {p}: {serv} | {ban} | {response}")
                                                                if verbose and output:
                                                                        f = open(output,'a',encoding="utf-8")
                                                                        f.write(f"\n✅ [{t}][UDP] {p}] {serv} | {ban} | {response}")
                                                                        f.close()
                                                                results.append((t, p, "UDP","Open",serv, ban))  # ✅ Fix order of values
                                                        else:
                                                                results.append((t,p,"UDP","Closed","N/A","N/A"))

                                                              
                                                        

                                                except Exception as e:
                                                        print(f"❌ Error scanning UDP port {p}: {e}")
                                                
                                                finally:
                                                        sock.close()

                def worker():
                        """Thread worker function"""
                        while not queue.empty():
                                t, p, protocol = queue.get()
                                if protocol == "tcp":
                                        tcp_scan(t,p)
                                elif protocol == "udp":
                                        udp_scan(t,p)
                                queue.task_done()

                for t in target:
                        for p in ports:
                                if scan_type[0]:
                                        queue.put((t,p,"tcp"))
                                if scan_type[1]:
                                        queue.put((t,p,"udp"))
                num_threads = min(num_threads, queue.qsize())


                thread_list = []
                for _ in range(num_threads):
                        thread = threading.Thread(target=worker)
                        thread_list.append(thread)
                        thread.start()

                for thread in thread_list:
                        thread.join()

                return results

        
        

        
class Output_formatting:
    """Formats and displays scan results per target."""

    @staticmethod
    def result_output(result,start_time,output):
        """Prints formatted scan results separately for each target."""



        closed_count = {}  # ✅ Track closed ports per target
        open_ports = {}  # ✅ Track open ports per target
        target_data = {}  # ✅ Store results per target
        live_hosts = 0  # ✅ Count of hosts that responded


        # ✅ Process Results & Group by Target
        for entry in result:
            target = entry[0]  # Extract target IP/host

            if target not in closed_count:
                closed_count[target] = 0
                open_ports[target] = 0
                target_data[target] = []  # ✅ Create entry for this target

            if entry[3] == 'Closed':
                closed_count[target] += 1
            else:
                open_ports[target] += 1
                service = entry[4] if entry[4] != "N/A" else "-"
                banner = entry[5] if entry[5] != "N/A" else "-"
                target_data[target].append([entry[1], entry[2], entry[3], service, banner])

        # ✅ Display Results per Target
        for target in target_data:
            print(f"\n🔍 **Results for Target: {target}**")
            if output:
                f = open(output,'a',encoding="utf-8")
                f.write(f"\n🔍 **Results for Target: {target}**")
                f.close()

            if open_ports[target] == 0 and closed_count[target] > 0:
                print("❌ No open ports found....")
                

            print(f"🔴 {closed_count[target]} closed TCP/UDP ports.")
            if output:
                f = open(output,'a',encoding="utf-8")
                f.write(f"🔴 {closed_count[target]} closed TCP/UDP ports.")
                f.close()

            if target_data[target]:  # ✅ Only print if there are open ports
                headers = ["Port", "Protocol", "State", "Service", "Banner"]
                print(tabulate(target_data[target], headers=headers, tablefmt="grid"))

                if output:
                        table = tabulate(target_data[target], headers=headers, tablefmt="grid")
                        with open(output, "a", encoding="utf-8") as f:  # ✅ Open file in append mode
                                f.write("\n" + table + "\n\n")  # ✅ Ensure line breaks before & after the table
                live_hosts += 1  # ✅ Count this as a live host            
                

        elapsed_time = round(time() - start_time,3)
        total_hosts = len(set(entry[0] for entry in result))  # Unique target IPs
        print(f"\nDone: {total_hosts} IP address{'es' if total_hosts > 1 else ''} "
              f"({live_hosts} host{'s' if live_hosts != 1 else ''} up) scanned in {elapsed_time} seconds.")
        
        if output:
              
              with open(output, "a", encoding="utf-8") as f: 
                                f.write(f"\nDone: {total_hosts} IP address{'es' if total_hosts > 1 else ''} "
                                        f"({live_hosts} host{'s' if live_hosts != 1 else ''} up) scanned in {elapsed_time} seconds.")




def main():
        argument = Documentation_options.prepare_arg()
        target = Port_Scanner.prepare_target(argument.ip)

        if target is None:
                print(f'{argument.ip} is not alive')
                sys.exit()
                  
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M %p %Z")
        script_name = os.path.basename(__file__)  # Gets the filename
        print(f"\nStarting {script_name} 1.0 at {current_time}")
        if argument.output:
                f = open(argument.output,'a',encoding="utf-8")
                f.write(f"\nStarting {os.path.basename(__file__)} 1.0 at {datetime.now().strftime("%Y-%m-%d %H:%M %p %Z")}")
                f.write(f'\n{len(target)} alive host found')
                f.close()
        
        print(f'\n{len(target)} alive host found')
        if target is not None and argument.verbose:
                    for t in target:
                         if argument.output:
                             f = open(argument.output,'a',encoding="utf-8")
                             f.write(f"\n{t}")
                             f.close()
                         
                         print(t)

        
                
                
        
        ports_list = Port_Scanner.prepare_ports(argument.single,argument.range)
        Port_Scanner.fill_queue(ports_list)
        ports = Port_Scanner.new_port()
        
        
        result = Port_Scanner.scan_ports(target,ports,argument.service,argument.banner,[argument.tcp,argument.udp],argument.verbose,argument.output,argument.thread)
       
        start_time  = time()
        Output_formatting.result_output(result,start_time,argument.output)
       
        
        




if __name__ == "__main__":
        main()
