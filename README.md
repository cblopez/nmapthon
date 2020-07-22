# Nmapthon
A complete, high level Nmap module for Python.  
&nbsp;
  
- ## [**Home**](https://github.com/cblopez/nmapthon/blob/master/README.md#welcome-to-the-nmapthon-wiki-a-high-level-nmap-module-for-python)
- ## [**Changelog**](https://github.com/cblopez/nmapthon/blob/master/README.md#changelog-1)
- ## [**Classes**](https://github.com/cblopez/nmapthon/blob/master/README.md#classes-1)  
  - ### [**NmapScanner**](https://github.com/cblopez/nmapthon/blob/master/README.md#nmapscanner-1)
    - #### [**Run the scanner**](https://github.com/cblopez/nmapthon/blob/master/README.md#running-the-scan)
    - #### [**Simple scan information**](https://github.com/cblopez/nmapthon/blob/master/README.md#getting-simple-scan-information)
    - #### [**Hosts, protocols and ports**](https://github.com/cblopez/nmapthon/blob/master/README.md#get-hosts-information)
    - #### [**Services**](https://github.com/cblopez/nmapthon/blob/master/README.md#service-information)
    - #### [**OS Detection**](https://github.com/cblopez/nmapthon/blob/master/README.md#os-detection-1)  
    - #### [**Host scripts and Traceroute**](https://github.com/cblopez/nmapthon/blob/master/README.md#host-scripts)  
    - #### [**Merging NmapScanner objects**](https://github.com/cblopez/nmapthon/blob/master/README.md#merging-nmapscanner-objects-1)
  - ### [**AsyncNmapScanner**](https://github.com/cblopez/nmapthon/blob/master/README.md#asyncnmapscanner-1)  
    - #### [**Run the scanner**](https://github.com/cblopez/nmapthon/blob/master/README.md#run-the-scan)  
    - #### [**Properties and methods**](https://github.com/cblopez/nmapthon/blob/master/README.md#properties-and-methods-1)  
- ## [**List of properties and methods**](https://github.com/cblopez/nmapthon/blob/master/README.md#list-of-properties-setters-and-methods)  
  

---
# Welcome to the Nmapthon Wiki! A high level Nmap module for Python.  

## Installation (with pip)  
Update your `pip` utility with `pip install pip --upgrade` and then `pip install nmapthon`.

## Installation (Manual)  
Downloading the file from the 'src' folder and pasting it directly into your proyect and import it. **No aditional modules are needed to run this library, everything is achieved by vanilla Python modules.**  

---  
# Changelog
- Version 1.1.X: Added `merge()` function, `script_name` for script related functions and minor error correction.
  
---  

# Classes  

There are **two available classes** to use right now with this module:  
- **NmapScanner**: Used to execute custom nmap scans, providing a large list of methods and customization to gather all the resulting information. Docs [here](https://github.com/cblopez/nmapthon/wiki/NmapScanner)  
- **AsyncNmapScanner**: Inherits NmapScanner and as you could guess by the name, it runs nmap scans asynchronously allowing the program to execute other actions meanwhile.  
  
---
# NmapScanner  
Class for executing and parsing nmap scans.
  
## Instantiation  
The NmapScanner class takes one positional parameter and `**kwargs` parameters for instantiation. The positional parameter is the target IP or target's IP range to scan: 

Specify the targets to scan in two different accepted formats: In str format, those targets can be a network/netmask like `'192.168.1.0/24'`, a range like `'192.168.1.1-192.168.1.10'`, a number of individual targets separated by a comma like `'192.168.1.1,192.168.1.2'`, a single target like `'192.168.1.1'` or any combination between these options like `'192.168.1.1-192.168.1.10, 192.168.1.22'`. In list format, with every IP Address specified separately: `['192.168.1.1', '192.168.1.2', .... ]`.  
**You can re-assign them later with the target setter:**  
`scanner_instance.targets = # String or list of targets`.  

On the other hand, `kwargs` are:
   
- `ports`: Specify the ports to scan in two different accepted formats. In str format, sepecify a port range like `'20-100'`, a number of individual ports separated by a comma like `'22,53'`, a single port like `'22'` or any combination between these options like `'22,53,100-300'`. In list format, built by single int or str port values: `[22, 53, 100]` or `['22', '53', '100']`. 
**If no ports are specified, nmap will scan the default ports. As well as `targets`, this attribute has a setter:**  
`scanner_instance.ports = range(1, 1025) # Yeah, you can use range()!`  
- `arguments`: String containing every nmap parameter that we want to execute. For example `'-sV -Pn'`.  
**Note: No `-d` or `-v` options allowed (That means no debugging or verbosity). The `-p` parameter is not allowed either, ports must be specified on instantiation or by the `ports` setter as explained above. No IP addresses will be allowed, targets must be specified on instantiation or by the `targets` setter as explained above.**`arguments` **has also a setter:**  
`scanner_instance.arguments = '-sS -T2'`  
- `name`: Specify a particular name for the scanner.
  
### Example  
```python  
import nmapthon as nm  

# This instantiates a scanner for localhost and Service Detection on default ports
scanner = nm.NmapScanner('127.0.0.1', arguments='-sV')

# This one scans 3 hosts at maximum speed and with script launching, OS detection and Service Detection  
scanner = nm.NmapScanner(['192.168.1.1', '192.168.1.11', '192.168.1.34'], arguments='-A -T4')

# This one scans localhost, SYN scan for the first 200 ports. His name is 'Mapy'  
scanner = nm.NmapScanner('127.0.0.1', name='Mapy', ports=range(1,201))
```
### Errors  
During instantiation, some errors can be raised:  
- `InvalidArgumentError`: For example, if `arguments` contains the `-p` parameter, this will be raised.  
- `MalformedIPAddressError`: If a target is not well written (it is not a valid IP address), this will be raised.  
- `InvalidPortError`: If string port cannot be converted to integer, it is a non valid port. If a port is smaller than 1 or greater than 65535. Will be raised in any of these cases.  
  
## Running the scan  
After [instantiating](https://github.com/cblopez/nmapthon/wiki/NmapScanner#Instantiation) the scanner, the `run()` method will execute it. The program will block until the nmap process finishes, and after that, the `NmapScanner` instance will contain all the information from the scan. 

## Example  
```python  
import nmapthon as nm

example_scanner = nm.NmapScanner(target='127.0.0.1', arguments='-sS')  

# Execute the scan
example.scanner.run()

# Now the 'example_scanner' object contains all the information from the scan.
```  
Please head to the next sections to know how to manage all the information gathered from the scan.  

## Errors  
When executing the `run()` method, several type of errors can pop, but all of them are raised by the same Exception: `NmapScannerError`. The situations when this Exception could come out are: 
- No targets to scan are specified.  
- When nmapthon cannot parse the nmap output, due to any type of nmap error that interrupted the execution. In this case, the `NmapScannerError` will print the nmap error.  
- When no output from nmap is given. Should never happen but if it does, the `NmapScannerError` will print the nmap error.  

**Any other type of error when calling the** `run()` **method could be some type of non permitted operation (execute with `sudo` or as admin), or the fact that the machine does not have nmap installed.**

## Getting simple scan information  
After calling the `run()` method, the `NmapScanner` instance will have several properties to access scan information, only if no errors occur. These properties are:  
- `start_timestamp`: Get the timestamp from when the scan started.  
- `start_time`: Get the human-readable date and hour from when the scan started.  
- `exit_status`: Nmap application exit status.  
- `args`: All arguments used in the scan, **but this args are printed by nmap**.  
- `summary`: Scan summary.  
- `version`: Nmap's version.  
- `end_timestamp`: Get the timestamp from when the scan finished.  
- `end_time`: Get the human-readable date and hour from when the scan finished.  
- `finished`: Boolean flag that tells if the scan has finished.  

**In addition, there is a very important property called the `tolerant_errors` property. That returns a string with nmap errors that happened but let the scan finish.**  

**Important: If any of this properties is accessed before calling the `run()` method, they will return `None`.**  

## Example  
```python  
import nmapthon as nm

scanner = nm.NmapScanner('192.168.1.0/24', ports='1-1024', arguments='-sS')  
scanner.run()  

# If program reaches this point, we can get the properties.  
print("Started at: {}".format(scanner.start_time))  
print("Used {} nmap version.".format(scanner.version))  
print("The tolerant errors were:\n{}".format(scanner.tolerant_errors)) 
# You can keep calling any of this properties 
```  
  
#### **Every method must be called after** `run()` **or an** `NmapScanError` **will be raised.**
## Get hosts information  
After running the scan, we can execute two primary methods to obtain the hosts from the scan:  
- `scanned_hosts()`: Returns a list of scanned hosts.  
- `non_scanned_hosts()`: Returns a list with all the hosts that where specified on `targets` but did not appear on the nmap output, which means that they were not scanned.  
  
To get the **hostnames** associated with a particular host:  
- `hostnames(host:str)`: Returns a list with all the hostnames from a host.

Having the scanned hosts, we can get their state, reason and scanned protocols:  
- `state(host:str)`: Returns the state of a given host.  
- `reason(host:str)`: Returns the reason why the host has a certain state.  
- `all_protocols(host:str)`: **Yields** every protocol scanned for a given host.  

For a given host and protocol, we can also get the scanned and non scanned ports, plus their state:  
- `scanned_ports(host:str, protocol:str)`: Return a list of scanned ports for a given host and protocol.  
- `non_scanned_ports(host:str, protocol:str`: Return a list of non scanned ports for a given host and protocol.  
- `port_state(host:str, protocol:str, port:str,int)`: Return the state and reason from a port.  

**These host, protocol and port related methods are just to enumerate. Head to the next sections to see more complex ones.**  

### Host information example  
```python
import nmapthon as nm

scanner = nm.NmapScanner(['127.0.0.1', '192.168.1.99'], ports=[1,101], arguments='-sT')  
scanner.run()

# Get hosts that responded the scan
host_that_responded = scanner.scanned_hosts()

# Loop through protocols, for every scanned host and get other information
for host in host_that_responded:
    # Get state, reason and hostnames
    print("Host: {}\tState: {}\tReason: {}".format(host, scanner.state(host), scanner.reason(host))    
    for hostname in scanner.hostnames(host):
        print("Hostname: {}".format(hostname))
        # Get scanned protocols
    for proto in scanner.all_protocols(host):
        # Get scanned ports
        for port in scanner.scanned_ports(host, proto): 
            state, reason = scanner.port_state(host, proto, port)
            print("Port: {0:<7}State:{1:<9}Reason:{2}'.format(port, state, reason))
```  
  

## Service information
If service detection was performed (for example with `'-sV'` or `'-A'`), we can gather the service information for a given host, protocol and port:  
- `service(host:str, protocol:str, port:str,int)`: Get a Service instance representing the gathered information from the service, if no service information was found it returns `None`.  
- `standard_service_info(host:str, protocol:str, port:str,int)`: Returns the service name and service information. The service information is a string formed by the service product, version and extarinfo. If there is no info about a particular service, two `None` values will be returned. If nmap has found the name of the service, but it doesnt know anything about the service information itself, this method will return the name and an empty string (`''`).  

## Service class  
Executing the function `service(host:str, protocol:str, port:int,str)` will return `None` if there is no known service, or it will return a `Service` in any other case. A `Service` object has 4 simple properties:  
- `name`: Return the name of the service.  
- `product`: Return the product running on that service.  
- `version`: Return the version of the product.  
- `extrainfo`: Return extra information about the product.  
  
We can also get all CPEs associated with that service:  
- `all_cpes()`: Return a list containing all the CPEs from a service.  
  
Last but not least, we can get all the scripts information that were launched against that particular service:  
- `all_scripts()`: **Yields** every script name and output from every script that was launched agaisnt that service.  
  
Service instances can be used as list objects, which allows scripts management, for example:  
- `service_instance[script_name]`: Return the output from a given script name.  
- `service_instance[script_name] = script_output`: Add a script name with an associated output.  
- `del service_instance[script_name]`: Delete every script related information for a given script name.  
  
Script instance also have a custom `__str__` method:  
- `print(str(service_instance))`: Prints all the service info in a specific way.  
  
## Service object example  
```python  
import nmapthon as nm  

scanner = nm.NmapScanner('192.168.1.0/24', ports='22,53,443', arguments='-A -T4')
scanner.run()  

# for every host scanned  
for host in scanner.scanned_hosts():  
    # for every protocol scanned for each host  
    for proto in scanner.all_protocols(host):  
        # for each scanned port  
        for port in scanner.scanned_ports(host, proto):
            # Get service object  
            service = scanner.service(host, proto, port)  
            if service is not None:  
                print("Service name: {}".format(service.name))  
                print("Service product: {}".format(service.product))  
                for cpe in service.all_cpes():
                    print("CPE: {}".format(cpe))
                for name, output in service.all_scripts():  
                    print("Script: {}\nOutput: {}".format(name, output))
                # You could also do print(str(service))
                # You could also know if 'ssh-keys' script was launched and print the output
                if 'ssh-keys' in service:  
                    print("{}".format(service['ssh-keys']))


```  
  
## Service standard info example  
```python  
import nmapthon as nm  

scanner = nm.NmapScanner('192.168.1.0/24', ports='22,53,443', arguments='-sV -T4')
scanner.run()  

# for every host scanned  
for host in scanner.scanned_hosts():  
    # for every protocol scanned for each host  
    for proto in scanner.all_protocols(host):  
        # for each scanned port  
        for port in scanner.scanned_ports(host, proto):
            # Get service information  
            service, service_info = scanner.standard_service_info(host, proto, port)
            if service is not None:  
                print("Service: {}\tInfo: {}".format(service, service_info))

```  

  
## OS Detection  
If OS detection was performed (for example, by using `'-O'` or `'-A'`), you can get the OS matches with their accuracy and the OS fingerprint:  
- `os_matches(host:str)`: **Yields** every OS name with it's corresponding accuracy for a given host.  
- `os_fingerprint(host:str)`: Returns the OS fingerprint for a given host. If no fingerprint was found or performed, it will return `None`.  
- `most_accurate_os(host:str)`: Returns a list with the most accurate OSs. **The list is needed because there might not be only one OS match with the highest accuracy, but several.**  

## OS Detection example  
```python  
import nmapthon as nm  

scanner = nm.NmapScanner('127.0.0.1', arguments='-O --osscan-guess')
scanner.run()

# Notice that '127.0.0.1' can be used without expecting an NmapScanError  
# localhost should always responde.
for os_match, acc in scanner.os_matches('127.0.0.1'):
    print('OS Match: {}\tAccuracy:{}%'.format(os_match, acc))

fingerprint = scanner.os_fingerprint('127.0.0.1')
if fingerprint is not None:
    print('Fingerprint: {}'.format(fingerprint))

for most_acc_os in scanner.most_accurate_os('127.0.0.1'):
    print('Most accurate OS: {}'.format(most_acc_os))
```  
  
  
## Host Scripts  
We can gather the information from the scripts that are host oriented. If looking for service oriented scripts, you can find  how to get them [here](https://github.com/cblopez/nmapthon/blob/master/README.md#service-information):  
- `host_scripts(host:str, script_name=None)`: **Yield** every name and output for every script launched against the host. If `script_name` is set to a string, 
only the scripts containing that string will be yielded, i.e. `sc.host_scripts('127.0.0.1'), script_anme='smtp'`) 
  
## Traceroute information  
Get every hop information from executing a traceroute to a particular host:  
- `trace_info(host:str)`: **Yields** one `TraceHop` instance per traceroute hop.  
  
## TraceHop class  
A `TraceHop` instance has four basic properties to access its information:  
- `ttl`: Time-To-Live. IP layer field.  
- `ip_addr`: IP Address of the node.  
- `rtt`: Round Trip Time.  
- `domain_name`: Domain name of the node.  
  
`TraceHop` instances have a custom `__str__` method to print their information in a specific way.  
**If any of the traceroute hop information is unknown, the corresponding property will return** `None`.  
**If a** `TraceHop` **instance has no information (blocked by firewall, for example) the** `__str__` **method will print** `'Somehow blocked Hop.'`.  

## Host scripts example  
```python  
import nmapthon as nm  

scanner = nm.NmapScanner('192.168.1.1-192.168.1.112', arguments='-A')  
scanner.run()

for host in scanner.scanned_hosts():  
    print("Host: {}".format(host))
    for name, output in scanner.host_scripts(host):  
        print("Script: {}\nOutput: {}".format(name, output))  
```  
  
## Traceroute example  
```python  
import nmapthon as nm  

scanner = nm.NmapScanner('85.65.234.12', arguments='--traceroute')  
scanner.run()  
  
if '85.65.234.12' in scanner.scanned_hosts():  
    for tracehop_instance in scanner.trace_info('85.65.234.12'):  
        print('TTL: {}\tIP address: {}'.format(tracehop_instance.ttl, tracehop_instance.ip_addr))
```  

---  

# Merging NmapScanner objects  

There may be situations where several `NmapScanner` instances may be instantiated separately, so a `merge()` is available to 
merge scans. It must be called after the instance finishes the scan, and it accepts any number of other `NmapScanner` instances 
plus additional `**kwargs`
- `merge_tcp=True`: Flag to allow TCP merging
- `merge_udp=True`: Flag to allow UDP merging 
- `merge_scripts=True`: Flag to merge host scripts. TCP/UDP port scripts are merged if their respective flag is `True`.
- `merge_trace=True`: Merge Traceroute information. 
- `merge_os`: Merge OS information.  
- `merge_non_scanned`: Merge IPs that could not be scanned.

### `merge()` deep inspect  
The `merge()` method acts differently depending on a main condition, which is: "Does the instance that's calling the method have the target X?". Depending on the answer: 
- If the target is not in the caller scanner, all the information from the target is copied depending on the `**kwargs` flags values.
- If the target is on the caller scanner, the information is copied depending on the flags, particularly:
  - TCP/UDP ports are copied if they where not scanned on the caller scan, but if the caller already has information 
  about them, it's not overwritten.
  - OS information, as well as Host scripts are checked one by one, only adding them if the caller does not have information of a particular OS/script.
  - Traceroute is only added while no Traceroute information is in the caller scanner.  

## Example 1: Dividing TCP and UDP scans  
```python
import nmapthon as nm

# Run a TCP scan synchronously and a UDP async to the same target
main_scanner = nm.NmapScanner('10.10.10.2', ports=[22, 80, 443], arguments='-sV -sS -n')
udp_scanner = nm.AsyncNmapScanner('10.10.10.2', ports=[21, 53], arguments='-sU -n', mute_error=True)

# Launch the UDP first
udp_scanner.run()

# Launch the TCP
try:
    main_scanner.run()
except nm.NmapScanError as e:
    print('Error while scanning TCP ports:\n{}'.format(e))

# Wait until UDP ends
udp_scanner.wait()

if udp_scanner.finished_successfully():
    # Merge the scans (Do not need to set all flags to False since there is no information on the UDP scanner,
    # but just to show the usage thay are set to False here
    main_scanner.merge(udp_scanner, merge_os=False, merge_scripts=False, merge_tcp=False, merge_trace=False)
```  

## Example 2: Multi-threading/processing scans
```python
import nmapthon as nm
import multiprocessing

def read_ips(ips_file):
    with open(ips_file) as f:
        return [x.strip() for x in f.readlines()]

def worker(n, ip, return_dict):
    sc = nm.NmapScanner(ip, ports=[1-1000], arguments='-sT -sV -T4 -n')
    try:
        sc.run()
    except nm.NmapScanner as e:
        raise e
    return_dict[n] = sc


if __name__ == '__main__':
    # Create share dict to store scans
    manager = multiprocessing.Manager()
    return_dict = manager.dict()
    jobs = []
    # Read IPS from file
    ips = read_ips('my_ips_file.txt')
    for i in range(len(ips)):
        p = multiprocessing.Process(target=worker, args=(i, ips[i], return_dict))
        jobs.append(p)
        p.start()
    
    # Freeze application until all apps finish
    for proc in jobs:
        proc.join()
    
    # Take the first scanner as caller
    main_scan = return_dict[0]
    # Pass the rest of the scans as arguments for merging
    main_scan.merge(*return_dict[1:])
    
    # Now you can use the main_scan as a single scanner with all the information
    for host in main_scan:
        ......
```
---  

# AsyncNmapScanner  
Class for executing background nmap scans.  
  
## Instantiation  
Instantiating `AsyncNmapScanner` has the same `kwargs` as the `NmapScanner` class, you can find them [here](https://github.com/cblopez/nmapthon/blob/master/README.md#nmapscanner-1). But this one has an optional extra `kwargs` parameter:  
- `mute_errors`: A boolean type parameter, `False` by default. If set to `True`, the AsyncNmapScanner wont show fatal errors when executing. **It is not recommended to set it to** `True` **because it hides scan errors, but in case you need it, you can use it.**  
  
## Example  
```python  
import nmapthon as nm  
  
async_scanner = nm.AsyncNmapScanner('10.126.65.0/23', ports='21,22,100-200', arguments='-sV -n -T4')  
  
# Async Scanner with error muting  
async_scanner = nm.AsyncNmapScanner(targets='192.168.1.30', arguments='-A -T4', mute_errors=True)
```
  
# AsyncNmapScanner  
  
## Run the scan  
`AsyncNmapScanner` also has the `run()` method, which will start executing the scan in background. You can use several methods to get the scan state and block the application.  
- `is_running()`: Returns `True` if the scanner is running. `False` if not.  
- `wait()`: Blocks the program execution until the scan finishes.  
- `finished_succesfully`: Returns `True` if the scan finished with no fatal errors. `False` if not.  
  
If `mute_errors=True` is used, you can get the Exception raised when muted:  
- `fatal_error()`: Returns an `NmapScanError` with the information from the Exception raised that was muted. If no `mute_errors=True` was set, it will return None, but you will have anyways an `NmapScanError` raised on your program.
  
## Example 1  
```python  
import nmapthon as nm  
import time  
  
scanner = nm.AsyncNmapScanner('192.168.1.2', ports=range(1,10001), arguments='-sS -sU')  
scanner.run()  
  
# Do something while it executes  
while scanner.is_running():  
    print("I print because I can :)")  
    time.sleep(1)  
  
# Check if it was not successful  
if not scanner.finished_succesfully():  
    print("Uh oh! Something went wrong!")  
```  
  
## Example 2  
```python  
import nmapthon as nm  
  
scanner = nm.AsyncNmapScanner('192.168.1.2', ports=range(1,10001), arguments='-sS -sU')  
scanner.run()  
  
# Do something and block execution until finishes
for i in range(1, 1000000):  
    print("Im printing a lot of lines!")  
scanner.wait()  
  
# Check if it was not successful  
if not scanner.finished_succesfully():  
    print("Uh oh! Something went wrong!\nPopped error:\n{}".format(scanner.fatal_error()))  
```  
  
## Properties and Methods  
Apart from the additional methods mentioned in the [previous section](https://github.com/cblopez/nmapthon/blob/master/README.md#run-the-scan), all the properties and methods from the `NmapScanner` class are inherited, please [read the documentation](https://github.com/cblopez/nmapthon/blob/master/README.md#nmapscanner-1) from this class to know what to use.  
  
---
# List of properties, setters and methods  
  
## NmapScanner  
Here is a complete list of attributes and methods from the ´NmapScanner´ class.  
  
### NmapScanner: Properties  
  
  
| Property  | Return type | Description |  
| --------- | ----------- | ----------- |  
| `name` | `str`, `None` | Name of the scanner, `None` if no name was set on instantiation. |    
| `targets` | `str`, `list`, `None`  | Targets specified to scan, depending on the type used to specify them. |  
| `ports` | `str`, `None`  | Ports in string format, even if they were set using a `list`. |  
| `scan_arguments` | `str`, `None` | Arguments set on instantiation (`arguments=#whatever`) or by `arguments(args)` setter. |  
| `start_timestamp`* | `str`, `None` | Timestamp from the time when the scan started. |  
| `start_time`* | `str`, `None` | Human readable time and hour when the scan started. |  
| `end_timestamp`* | `str`, `None` | Timestamp from the time when scan finished. |  
| `end_time`* | `str`, `None` | Human readable time and hour when the scan finished. |  
| `exit_status`* | `str`, `None` | Nmap's exit status. |  
| `args`* | `str`, `None` | Nmap scanning sentence. (From nmap, not explicitly the arguments of the user. |  
| `summary`* | `str`, `None` | Scan summary. |  
| `version`* | `str`, `None` | Nmap version used. |  
| `tolerant_errors`* | `str`, `None` | Errors that happened during the scan, but let it finish. |  
| `scanned_protocols_info`* | `dict`, `None` | Dictionary containing simple information about services scanned. |  
| `finished` | `bool` | Flag set to `True` if scanner was executed and done, `False` if not |  
  
  
__*Need to execute the__ `run()` __method before using this property, otherwise it will return__ `None` __.__ 
  
### NmapScanner: Setters  
  
  
| Setter  | Value type | Description |  
| ------- | ---------- | ----------- |  
| `name` | `str` | Set the name of the scanner | 
| `ports` | `str`, `list` | Set the ports to scan |  
| `targets` | `str`, `list` | Set the targets` IPs to scan |  
| `arguments` | `str` | Set the arguments to use by the scan. No `-p`, `-v` or `-d` allowed |  
  
  
### NmapScanner: Methods  
  
  
| Method | Return type | Description |  
| ------ | ----------- | ----------- |  
| `run()` | - | Start scanning. |  
| `raw_data()`* | `dict` | Return a complex dictionary containing all the output information. |  
| `scanned_hosts()`* | `list` | Return a list of all hosts that responded to the scan. |  
| `non_scanned_hosts()`* | `list` | Return a list of all hosts that did not respond to the scan. |  
| `state(host:str)`* | `str` | Return the state of a given host. |  
| `reason(host:str)`* | `str` | Return the reason of why a given host has such state. | 
| `all_protocols(host:str)`* | `generator` | **Yield** all the protocols scaned for a given host. |  
| `scanned_ports(host:str, protocol:str)`* | `list` | Return a list of all scanned ports for a given host and protocol. |  
| `non_scanned_ports(host:str, protocol:str)`* | `list` | Return a list of all scanned ports for a given host and protocol. |  
| `hostnames(host:str)`* | `list` | Return a list of all hostnames from a given host. |  
| `os_matches(host:str)`* | `generator` | **Yield** every `(os_match, accuracy)` for a given host. |  
| `os_fingerprint(host:str)`* | `str`, `None` | Return the OS Fingerprint for a given host, `None` if not scanned or was not found. |  
| `most_accurate_os(host:str)`* | `list` | Return a list of all OS matches with maximum accuracy. |  
| `service(host:str, protocol:str, port:str,int)`* | `Service`, `None` | Return a `Service` instance representing the service running on a port, for a given host and protocol. `None` if no service was found. |  
| `standard_service_info(host:str, protocol:str, port:str,int)`* | `tuple` | Return a tuple containing the service name and service version information. Returns `(None, None)` if none of them were found. | 
| `port_scripts(host:str, protocol:str, port:str,int, script_name=None)`* | `generator` | **Yield** every `(script_name, script_output)` for every script launched against a port, for a given host and protocol. Specify a `script_name` to return only those scripts that contain the given word on their name.  |  
| `host_scripts(host:str, script_name=None)`* | `generator` | **Yield** every `(script_name, script_output)` for every script launched against a given host. Specify a `script_name` to return only those scripts that contain the given word on their name. |  
| `trace_info(host:str)`* | `generator` | **Yield** one `TraceHop` instance, representing a Traceroute hop, for every hop gathered. |  
| `merge(*scanners:NmapScanner, merge_tcp=True, merge_udp=True, merge_os=True, merge_scripts=True, merge_trace=True, merge_non_scanned=True)`* | - | Merge the caller scan with any number of other `NmapScanner` instances. |  
  
  
__*Need to execute the__ `run()` __method before using this method, otherwise it will raise `NmapScanError`__.  
  
## AsyncNmapScanner  
Here is a complete list of attributes and methods from the ´AsyncNmapScanner´ class.  
  
### AsyncNmapScanner: Properties
The `AsyncNmapScanner` class has the same properties as the `NmapScanner` class.  
  
### AsyncNmapScanner: Methods  
The `AsyncNmapScanner` class has the same methods as the `NmapScanner` class, plus the following:  
  
| Method  | Return type | Description |  
| ------ | ----------- | ----------- |  
| `is_running()`* | `bool` | Returns `True` if the scan is running, `False` if not. |  
| `wait()`* | - | Freezes the application execution until the scan finishes. |  
| `finished_successfully()` | `bool` | Returns `True` if the scan was launched and it has finished successfully, `False` if not. |  
| `fatal_error()`* | `NmapScanError` | Returns the `Exception` raised on the scan execution, in case `finished_successfully()` is `False` and the `mute_errors=True` `kwarg` was used. |  
  
__*Need to execute the__ `run()` __method before using this method.__    
  
