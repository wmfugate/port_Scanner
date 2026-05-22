# Project Title: Port Scanner

## Purpose
This project was made for learning purposes. The main goals were:

 - learn Python sockets and concurrency
 - recreate the scanner in Go to gain experience with the language and goroutines
 - explore TCP and UDP scanning techniques

## Dependencies
Built-in modules for Python:

    - socket
    - threading
    - time
    - datetime

Built-in modules for Go:

	- fmt
	- net
	- time
	- strconv
	- syscall
	- errors
	- os
	- math
	- sync
	- encoding/hex
	- bytes

## How to run
### Python scanner

```bash
sudo python3 portScan.py
```

### Go scanner

```bash
go run portScan.go
```

## Takeaways

### TCP vs. UDP
TCP, being connection-oriented, made drawing conclusions a lot easier than with UDP. With TCP, the state can be determined by responses during the three-way handshake. Since there is no handshake in UDP, the state has to be drawn from responses to the connection.

For example, if there is no response from the port:

	- the packet may have been received, but no response sent
 	- the packet may have been dropped by a firewall
  	- the port may have been closed and not sent a response.

Nmap suggested using service/version detection (-sV) and TTL analysis to better the accuracy of UDP results. The specific packets based on port number are meant to partially replicate -sV. TTL was not implemented in the Python scanner as the socket approach did not return TTL values.

### Normal TCP scan vs. SYN scan
TCP forms connections through a three-way handshake process. A normal TCP scan goes through the full handshake when scanning ports. A SYN scan, on the other hand, only goes through the first part (SYN and SYN/ACK) before cutting off the connection (with RST). A SYN scan tends to be stealthier as it makes less noise and is less likely to get logged by detection systems. However, this is less true against modern systems as they are now designed to detect SYN scanning.

This has only been implemented on the Python scanner and uses raw sockets to craft the SYN packets manually. The SYN scan may take longer than the regular TCP scan because creating and handling raw packets introduces additional overhead compared to the operating system's built-in and optimized socket handling. In addition, because the SYN scan uses raw sockets and manually crafted packets, it typically requires elevated privileges (such as running with sudo/root permissions) on most operating systems.

### Python vs. Go
The Python version of the scanner was coded first, then the Go version was coded based on it. There are some differences as there are things that are in Python that are not in Go, such as:

 - Go's slices rather than Python's lists
 - Go does not have tuples
 - Go mainly uses for loops
 - must specify type(s) of parameters and return in Go functions
 - Go uses curly brackets rather than Python's indents 
 - error handling in Go is normally immediately after a function call rather than try/except (Python)

The Go version tended to be faster than the Python version though both were potentially limited by the scanner timeout entered and latency in the connections. Of course, some the differences could be from how the code was written (analysed afterwards and discovered that the sockets were opened and closed for each scanned port in the Python version). Still, goroutines tend to be more lightweight than Python's threads when it comes to concurrency as their creation takes less memory and Python can be limited by the Global Interpreter Lock (GIL).

## Author: William Fugate

## Acknowledgements/Sources
### general

 - For testing:
   - http://scanme.nmap.org/
- More on UDP responses + how to better:
	- https://nmap.org/book/scan-methods-udp-scan.html
### Python scanner

- sockets, TCP, UDP:
	- https://www.geeksforgeeks.org/python/socket-programming-python/
    - https://www.w3tutorials.net/blog/python-socket-connection-timeout/
    - https://docs.python.org/3/library/socket.html#socket.socket.connect
    - https://pythontic.com/modules/socket/sendto

- threading in Python:
	- https://www.geeksforgeeks.org/python/multithreading-python-set-1/

- raw sockets, SYN scan basics:
	- https://nmap.org/book/synscan.html
	- https://www.cyberly.org/en/what-is-a-syn-scan-and-how-does-it-work/index.html
	- https://github.com/LordEvron/PythonRawSocketSniffers/tree/master
    - https://www.binarytides.com/raw-socket-programming-in-python-linux/
    - https://pyquesthub.com/exploring-raw-sockets-in-python-a-practical-example
    - https://jumpcloud.com/it-index/what-is-an-ephemeral-port
### Go scanner

- general:
	- https://www.geeksforgeeks.org/go-language/go/
- slices:
	- https://go.dev/blog/slices-intro
	- https://stackoverflow.com/questions/21326109/why-are-lists-used-infrequently-in-go
- error handling:
	- https://www.reddit.com/r/golang/comments/j7c8ut/why_is_there_no_trycatch/
	- https://medium.com/@caring_smitten_gerbil_914/gos-errors-is-and-errors-as-unwrapping-the-right-way-cff69b374a1f
- Go sockets:
	- https://zetcode.com/golang/socket/
	- https://stackoverflow.com/questions/47117850/how-to-set-timeout-while-doing-a-net-dialtcp-in-golang
	- https://oneuptime.com/blog/post/2026-03-20-resolve-dns-ipv4-addresses-go/view
- concurrency/parallelism:
	- https://www.geeksforgeeks.org/go-language/go-concurrency-and-parallelism/
	- https://www.geeksforgeeks.org/go-language/using-waitgroup-in-golang/
	- https://gobyexample.com/waitgroups
- channels:
	- https://www.geeksforgeeks.org/go-language/channel-in-golang/
- time:
	- https://stackoverflow.com/questions/45766572/is-there-an-efficient-way-to-calculate-execution-time-in-golang
	- https://gobyexample.com/time
- files:
	- https://useful.codes/opening-files-with-go/
- ellipsis, variadic functions:
	- https://www.geeksforgeeks.org/go-language/how-to-use-ellipsis-in-golang/
- UDP:
	- https://dev.to/jones_charles_ad50858dbc0/go-udp-programming-a-beginner-friendly-guide-to-building-fast-real-time-apps-4ik

## AI Use
ChatGPT was used to help with debugging (more with Go as learning the language) and to craft specific packets for UDP.
