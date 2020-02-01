# Nmapthon
A complete, high level Nmap module for Python.  
&nbsp;
  
- ## [**Home**](https://github.com/cblopez/nmapthon/wiki/Home)
- ## [**Classes**](https://github.com/cblopez/nmapthon/wiki/Classes)  
  - ### [**NmapScanner**](https://github.com/cblopez/nmapthon/wiki/NmapScanner)
    - #### [**Run the scanner**](https://github.com/cblopez/nmapthon/wiki/NmapScanner:-Run)
    - #### [**Simple scan information**](https://github.com/cblopez/nmapthon/wiki/NmapScanner:-Simple-scan-information)
    - #### [**Hosts, protocols and ports**](https://github.com/cblopez/nmapthon/wiki/NmapScanner:-Hosts,-protocols-and-ports)
    - #### [**Services**](http://github.com/cblopez/nmapthon/wiki/NmapScanner:-Services)
    - #### [**OS Detection**](http://github.com/cblopez/nmapthon/wiki/NmapScanner:-OS-Detection)  
    - #### [**Host scripts and Traceroute**](https://github.com/cblopez/nmapthon/wiki/NmapScanner:-Host-Scripts-and-Traceroute)  
  - ### [**AsyncNmapScanner**](https://github.com/cblopez/nmapthon/wiki/AsyncNmapScanner)  
    - #### [**Run the scanner**](https://github.com/cblopez/nmapthon/wiki/AsyncNmapScanner:-Run-the-scan)  
    - #### [**Properties and methods**](https://github.com/cblopez/nmapthon/wiki/AsyncNmapScanner:-Properties-and-Methods)  
- ## [**List of properties and methods**](https://github.com/cblopez/nmapthon/wiki/List-of-properties-and-methods)

# Welcome to the Nmapthon Wiki! A high level Nmap module for Python.  

## Installation (with pip)  
Update your `pip` utility with `pip install pip --upgrade` and then `pip install nmapthon`.

## Installation (Manual)  
Downloading the file from the 'src' folder and pasting it directly into your proyect and import it. **No aditional modules are needed to run this library, everything is achieved by vanilla Python modules.**  

# Classes  

There are **two available classes** to use right now with this module:  
- **NmapScanner**: Used to execute custom nmap scans, providing a large list of methods and customization to gather all the resulting information. Docs [here](https://github.com/cblopez/nmapthon/wiki/NmapScanner)  
- AsyncNmapScanner: Inherits NmapScanner and as you could guess by the name, it runs nmap scans asynchronously allowing the program to execute other actions meanwhile.  
  
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

