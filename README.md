# Project Title: Port Scanner

## Purpose
This project was made for learning purposes. It focused on python sockets and concurrency. Also programmed the scanner in go to better learn the language and gain experience with goroutines.

## Dependencies
Built-in modules for python:
    - socket
    - threading
    - time
    - datetime

Built-in modules for go:
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
python scanner: python3 portScan.py
go scanner: go run portScan.go

## Author: William Fugate

## Acknowledgements/Sources
python scanner:
    For more on sockets, TCP, UDP:
        https://www.geeksforgeeks.org/python/socket-programming-python/
        https://www.w3tutorials.net/blog/python-socket-connection-timeout/
        https://docs.python.org/3/library/socket.html#socket.socket.connect
        https://pythontic.com/modules/socket/sendto
    More on UDP responses + how to better:
        https://nmap.org/book/scan-methods-udp-scan.html
    For threading in python:
        https://www.geeksforgeeks.org/python/multithreading-python-set-1/
    For testing:
        http://scanme.nmap.org/
go scanner:
    general:
		https://www.geeksforgeeks.org/go-language/go/
	slices:
		https://go.dev/blog/slices-intro
		https://stackoverflow.com/questions/21326109/why-are-lists-used-infrequently-in-go
	error handling:
		https://www.reddit.com/r/golang/comments/j7c8ut/why_is_there_no_trycatch/
		https://medium.com/@caring_smitten_gerbil_914/gos-errors-is-and-errors-as-unwrapping-the-right-way-cff69b374a1f
	Go sockets:
		https://zetcode.com/golang/socket/
		https://stackoverflow.com/questions/47117850/how-to-set-timeout-while-doing-a-net-dialtcp-in-golang
		https://oneuptime.com/blog/post/2026-03-20-resolve-dns-ipv4-addresses-go/view
	concurrency/parallelism:
		https://www.geeksforgeeks.org/go-language/go-concurrency-and-parallelism/
		https://www.geeksforgeeks.org/go-language/using-waitgroup-in-golang/
		https://gobyexample.com/waitgroups
	channels:
		https://www.geeksforgeeks.org/go-language/channel-in-golang/
	time:
		https://stackoverflow.com/questions/45766572/is-there-an-efficient-way-to-calculate-execution-time-in-golang
		https://gobyexample.com/time
	files:
		https://useful.codes/opening-files-with-go/
	ellipsis, variadic functions:
		https://www.geeksforgeeks.org/go-language/how-to-use-ellipsis-in-golang/
	UDP:
		https://dev.to/jones_charles_ad50858dbc0/go-udp-programming-a-beginner-friendly-guide-to-building-fast-real-time-apps-4ik

AI Use
Used ChatGPT to help with debugging (more with go as new to the language) and to craft specific packets for UDP.