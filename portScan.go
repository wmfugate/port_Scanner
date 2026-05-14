package main
import (
	"fmt"
	"net"
	"time"
	"strconv"
	"syscall"
	"errors"
	"os"
	"math"
	"sync"
	"encoding/hex"
	"bytes"
)

/*
no tuples natively in Go
will use list of integers with i as port number and i + 1 as state
0 = closed
1 = open
2 = filtered|slow
3 = unknown
4 = filtered|open
must iterate by +2 then
*/

//lists not used often in Go? See suggestions of slice instead online

func getInp(typ string) any{
	//any return type since sometimes str return, other times int (dep on typ parameter)
	var err error
	if typ == "str"{
		var inp string
		for{	//only for loops; "infinite for" = while
			_, err = fmt.Scanln(&inp)
			if err != nil{
				fmt.Println("Input must be a string\n")
			}else{
				return inp
			}
		}
	}else if typ == "int"{
		var inp int
		for{	//only for loops; "infinite for" = while
			_, err = fmt.Scanln(&inp)
			if err != nil{
				fmt.Println("Input must be an integer\n")
			}else{
				return inp
			}
		}
	}else{
		fmt.Println("Type is currently not implemented\n")
		return -1
	}
}

func conn(minport int, maxport int, timeout int, protocol int, returnType int, resultStore []int, retries int, target string) []int{
	if protocol == 1{
		//TCP
		d := net.Dialer{Timeout: time.Duration(timeout)*time.Millisecond}
		for i := minport; i < maxport + 1; i++{
			_, err := d.Dial("tcp", target + ":" + strconv.Itoa(i))
			if err == nil{	//no error with connecting
				if returnType >= 2 && returnType <= 4 || returnType == 6{
					fmt.Println("Port", i, "is open.\n")
				}
				if returnType == 1 || returnType == 3 || returnType == 5 || returnType == 6{
					resultStore = append(resultStore, i, 1)
				}
			}else{
				if errors.Is(err, syscall.ECONNREFUSED){	//reached host, but connection refused
					if returnType == 2 || returnType == 3{
						fmt.Println("Port", i, "is closed.\n")
					}
					if returnType == 1 || returnType == 3{
						resultStore = append(resultStore, i, 0)
					}
				}else if errors.Is(err, syscall.ETIMEDOUT){	//packet dropped (Fw) or timed out
					if returnType == 2 || returnType == 3{
						fmt.Println("Port", i, "is filtered or slow.\n")
					}
					if returnType == 1 || returnType == 3{
						resultStore = append(resultStore, i, 2)
					}
				}else{
					if returnType == 2 || returnType == 3{
						fmt.Println("Port", i, "is unknown.\n")
					}
					if returnType == 1 || returnType == 3{
						resultStore = append(resultStore, i, 3)
					}
				}
			}
		}
	}else{
		//UDP
		for i := minport; i < maxport + 1; i++{
			for j := 0; j < retries; j++{
				address, error := net.ResolveUDPAddr("udp", target + ":" + strconv.Itoa(i))
				if error != nil{
					fmt.Println("Could not resolve UDP address\n")
					}else{
					connection, err := net.DialUDP("udp", nil, address)
					//net.DialUDP(network string (protocol + IPv), laddr (local/src addr; nil autos to local IP), raddr (target:port))
				
					if err == nil{
						if i == 37{    //Time Protocol
							_, err = connection.Write([]byte("\x00"))
						}else if i == 53{        //DNS, dns query
							_, err = connection.Write([]byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"))
						}else if i == 66 || i == 67{   //DHCP, discover message
							_, err = connection.Write([]byte{0x01, 0x01, 0x06, 0x00, 0x39, 0x03, 0xf3, 0x26})
						}else if i == 69{      //TFTP, read request
							_, err = connection.Write([]byte("\x00\x01test\x00octet\x00"))
						}else if i == 88{  //Kerberos
							_, err = connection.Write([]byte("\x6a\x81\x30\x30\x81\x2d\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a"))
						}else if i == 123{     //NTP, ntp packet
							_, err = connection.Write([]byte{0x1b})
						}else if i == 137{     //NetBIOS-ns, name query
							_, err = connection.Write(append([]byte("\x12\x34\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00"), []byte("\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")...))
						}else if i == 161{     //SNMP, snmp public
							decoded, errora := hex.DecodeString("302602010104067075626c6963a019020471b4b568020100020100300b300906052b060102010500")
							if errora != nil{
								fmt.Println("Error with decoding hex string\n")
							}else{
								_, err = connection.Write([]byte(decoded))
							}
						}else if i == 500{     //ISAKMP, IKE handshake mimic
							payload := append(bytes.Repeat([]byte("\x00"), 16), []byte("\x01\x10\x02\x00")...)
							payload = append(payload, bytes.Repeat([]byte("\x00"), 8)...)	//have to name slice to append to not slice declaration
							payload = append(payload, bytes.Repeat([]byte("\x00"), 16)...)
							_, err = connection.Write(payload)
							//_, err = connection.Write(append(bytes.Repeat([]byte("\x00"), 16), []byte("\x01\x10\x02\x00"), bytes.Repeat([]byte("\x00"), 8), bytes.Repeat([]byte("\x00"), 16)))
						}else if i == 520{ //RIP (routing info)
							_, err = connection.Write(append([]byte("\x01\x01\x00\x00"), bytes.Repeat([]byte("\x00"), 20)...))
						}else if i == 554{ //RTSP (real time streaming)
							_, err = connection.Write([]byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"))
						}else if i == 631{ //IPP, printing
							_, err = connection.Write([]byte("POST / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
						}else if i == 1434{    //mssql
							_, err = connection.Write([]byte("\x02"))
						}else if i == 1900{    //SSDP, M-Search discovery request
							_, err = connection.Write([]byte("M-SEARCH * HTTP/1.1\r\nST:ssdp:all\r\nMX:1\r\nMAN:\"ssdp:discover\"\r\n\r\n"))
						}else if i == 5355{    //LLMNR, name resolution
							_, err = connection.Write(append([]byte("\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"), []byte("\x07example\x00\x00\x01\x00\x01")...))
						}else if i == 11211{   //Memcached
							_, err = connection.Write([]byte("stats\r\n"))
						}else if i == 33434{   //traceroute, UDP
							_, err = connection.Write([]byte("\x00"))
						}else{	//default to empty packet if not specific port
							_, err = connection.Write([]byte{0x00})
						}
						if err != nil{	//error with sending packet
							fmt.Println("Error writing packet\n")
						}else{
							connection.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
							buffer := make([]byte, 1024)
							_, err = connection.Read(buffer)
							connection.Close()
							if err != nil {
								if errors.Is(err, syscall.ECONNREFUSED){	//reached host, but connection refused
									if returnType == 2 || returnType == 3{
										fmt.Println("Port", i, "is closed.\n")
									}
									if returnType == 1 || returnType == 3{
										resultStore = append(resultStore, i, 0)
									}
									break
								}else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {	//packet dropped (Fw) or simply no response (but open)
									//if checking if err is using net.Error (type) and if so, if that error is a timeout error
									if j == retries - 1{	//will only write/print if still happens on final try
										if returnType == 2 || returnType == 3{
											fmt.Println("Port", i, "is filtered or open.\n")
										}
										if returnType == 1 || returnType == 3{
											resultStore = append(resultStore, i, 2)
										}
									}
								}else{
									if returnType == 2 || returnType == 3{
										fmt.Println("Port", i, "is unknown.\n")
									}
									if returnType == 1 || returnType == 3{
										resultStore = append(resultStore, i, 3)
									}
									break
								}
							}else{	//no error, open?
								if returnType >= 2 && returnType <= 4 || returnType == 6{
									fmt.Println("Port", i, "is open.\n")
								}
								if returnType == 1 || returnType == 3 || returnType == 5 || returnType == 6{
									resultStore = append(resultStore, i, 1)
								}
								break	//break retry loop if success
							}
						}
					}else{	//error with dial
						fmt.Println("Dial failed\n")
					}
				}
			}
		}
	}
	return resultStore
}


func main(){
	fmt.Println("Welcome to the port scanner.\n")

	var targetc, portc, protocol, scanm, returnType, retries, routineCount int
	var target, outFile string
	var minport, maxport, timeout int = 1, 1024, 500
	resultStore := []int{}
	var err error
	var ip []net.IP
	//1) Getting Inputs + Setup Phase
	//finding target

	for targetc < 1 || targetc > 2{
		fmt.Println("Target format:\n(1) IP Address\n(2) Domain Name\n")
		targetc = getInp("int").(int)
	}
	if targetc == 1{
		fmt.Println("Enter IP Address in ###.###.###.### form.")
    	target = getInp("str").(string)
	}else{
		for{
			fmt.Println("Enter Domain Name.")
			target = getInp("str").(string)

			ip, err = net.LookupIP(target)
			target = ip[0].String()
			if err != nil{
				fmt.Println("Invalid Domain Name or DNS failure\n")
			}else{
				fmt.Println("Found IP Address", target, "for entered Domain Name.\n")
				break
			}
		}
	}

	//ports to scan
	for portc < 1 || portc > 4{
		fmt.Println("Ports to scan:\n(1) Top ~1000 ports\n(2) All ports\n(3) Range of ports\n(4) Specific port\n")
		portc = getInp("int").(int)
	if portc == 1{
		minport = 1
		maxport = 1024
	}else if portc == 2{
		minport = 1
		maxport = 65535
	}else if portc == 3{
		maxport = -1
		for minport > maxport || minport < 1 || minport > 65535{
			fmt.Println("Ports range between 1 and 65535.\nEnter starting port.\n")
			minport = getInp("int").(int)
			fmt.Println("Enter ending port.\n")
			maxport = getInp("int").(int)
		}
	}else{
		minport = 0
		maxport = 65536
		for minport < 1 || minport > 65535{
			fmt.Println("Ports range between 1 and 65535.\nEnter specific port")
			minport = getInp("int").(int)
		}
		maxport = minport	//to prevent loop continuing after specific port
		}
	}

	//timeout
	fmt.Println("Please enter how long to wait for response when scanning (between 1 and 100,000 ms).\n")
	timeout = getInp("int").(int)
	if timeout < 1 || timeout > 100000{
		fmt.Println("Timeout value must be > 0 and < 100,001.")
		timeout = getInp("int").(int)
	}

	//protocol choose
	for protocol < 1 || protocol > 2{
		fmt.Println("Choose protocol to scan with:\n(1) TCP\n(2) UDP\n(Keep in mind that UDP is generally less accurate and revealing than TCP)\n")
		protocol = getInp("int").(int)
	}
	if protocol == 2{
		fmt.Println("UDP is lossy. How many retries per port (> 0)?\n")
		for retries <= 0{
			retries = getInp("int").(int)
		}
	}

	//scanning method >> seq or concurrent
	for scanm < 1 || scanm > 2{
		fmt.Println("Choose scanning method:\n(1) Scan ports one-by-one (possibly slow)\n(2) Attempt to scan multiple at once\n")
		scanm = getInp("int").(int)
	}

	//getting return type:
	//returnType breakdown:
	// 1 = write everything to file
	// 2 = print everything locally
	// 3 = write and print everything
	// 4 = print only opens
	// 5 = write only opens
	// 6 = write and print only opens
    for returnType < 1 || returnType > 3{
        fmt.Println("Choose return method:\n(1) Write to File\n(2) Print locally\n(3) Do both\n")
        returnType = getInp("int").(int)
	}
    if returnType == 2{    //specifics on print >> only likely opens or all results
        returnType = 0
        for returnType < 1 || returnType > 2{
            fmt.Println("Choose what is printed:\n(1) Print only opens\n(2) Print everything\n")
            returnType = getInp("int").(int)
		}
        if returnType == 1{
            returnType = 4
		}else{ returnType = 2 }
	}else if returnType == 1{    //same with what is saved to file; also gets filename
        returnType = 0
        for returnType < 1 || returnType > 2{
            fmt.Println("Choose what is saved:\n(1) Save only opens\n(2) Save everything\n")
            returnType = getInp("int").(int)
		}
        if returnType == 1{
            returnType = 5
		}else{ returnType = 1 }
        fmt.Println("Please enter file name to save under (with no extension):\n")
        outFile = getInp("str").(string) + ".txt"
	}else if returnType == 3{
        for returnType < 1 || returnType > 2{
            fmt.Println("Choose what is printed and saved:\n(1) Only opens\n(2) Everything\n")
            returnType = getInp("int").(int)
		}
        if returnType == 1{
            returnType = 6
		}else{ returnType = 3 }
        fmt.Println("Please enter file name to save under (with no extension):\n")
        outFile = getInp("str").(string) + ".txt"
	}


	//2) Scanning Phase
	//create socket
	//attempt to connect
	//interpret result
	//close
	if scanm == 2 && maxport == minport{
		fmt.Println("You only want to scan 1 port. Use sequential.")
		scanm = 1
	}
	if scanm == 2{
		//concurrent or parallel
		for routineCount < 2 || routineCount > 10{
			fmt.Println("How many routines do you want to work? (Suggested: 2-4)\n")
			routineCount = getInp("int").(int)
		}
		for math.Round(float64((maxport - minport + 1)/ routineCount)) < 1{	//if more routines than ports to scan
			routineCount = routineCount - 1
		}

		start := time.Now()
		var wg sync.WaitGroup
		if returnType == 1 || returnType == 3 || returnType == 5 || returnType == 6{
			resChannel := make(chan []int, routineCount)	//channel to collect returns if writing to file, must initialize or doesn't work
			for i:=0; i<routineCount; i++{
				wg.Add(1)
				if i == routineCount - 1{
					fmt.Println("Routine", i+1, "has", minport + i * ((maxport - minport +1)/ routineCount), "through", maxport, "\n")
					go func(i int){
						defer wg.Done()
						res := conn(minport + i * ((maxport - minport +1)/ routineCount), maxport, timeout, protocol, returnType, resultStore, retries, target)
						if returnType == 1 || returnType == 3 || returnType == 5 || returnType == 6{
							resChannel <- res	//send routine's results to channel
						} 
					}(i)	//add at end to run function
				}else{
					fmt.Println("Routine", i+1, "has", minport + i * ((maxport - minport +1)/ routineCount), "through", minport + (i+1)*((maxport - minport +1)/ routineCount) - 1, "\n")
					go func(i int){
						defer wg.Done()
						res := conn(minport + i * ((maxport - minport +1)/ routineCount), minport + (i+1)*((maxport - minport +1)/ routineCount) - 1, timeout, protocol, returnType, resultStore, retries, target)
						if returnType == 1 || returnType == 3 || returnType == 5 || returnType == 6{
							resChannel <- res	//send routine's results to channel
						} 
					}(i)	//add at end to run function
				}
			} 
			wg.Wait()
			fmt.Println("Scan completed in", time.Since(start), "\n")
			close(resChannel)
			for i := range resChannel{
				resultStore = append(resultStore, i...)	//"..." expands slice to add elements within i (as cannot append slice to slice of ints)
			}
		}else{	//have 2 because of declared and not used, undefined errors with resChannel
			for i:=0; i<routineCount; i++{
				wg.Add(1)
				if i == routineCount - 1{
					fmt.Println("Routine", i+1, "has", minport + i * ((maxport - minport +1)/ routineCount), "through", maxport, "\n")
					go func(i int){
						defer wg.Done()
						conn(minport + i * ((maxport - minport +1)/ routineCount), maxport, timeout, protocol, returnType, resultStore, retries, target) 
					}(i)	//add at end to run function
				}else{
					fmt.Println("Routine", i+1, "has", minport + i * ((maxport - minport +1)/ routineCount), "through", minport + (i+1)*((maxport - minport +1)/ routineCount) - 1, "\n")
					go func(i int){
						defer wg.Done()
						conn(minport + i * ((maxport - minport +1)/ routineCount), minport + (i+1)*((maxport - minport +1)/ routineCount) - 1, timeout, protocol, returnType, resultStore, retries, target)
					}(i)	//add at end to run function
				}
			} 
			wg.Wait()
			fmt.Println("Scan completed in", time.Since(start), "\n")
		}
		
	}
	if scanm == 1{
		//sequential
		start := time.Now()
		resultStore = conn(minport, maxport, timeout, protocol, returnType, resultStore, retries, target)
		fmt.Println("Scan completed in", time.Since(start), "\n")
	}


	//3) Results + Output Phase
	//print output happens in conn
	//for file output
	if returnType == 1 || returnType == 3 || returnType == 5 || returnType == 6{
		file, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil{
			fmt.Println(err)
			return
		}
		defer file.Close()

		_, err = file.WriteString("Scan of " + target + " on " + time.Now().String() + "\n")
		if err != nil{
			fmt.Println(err)
			return
		}
		for i := 0; i < len(resultStore); i = i + 2{
			if resultStore[i+1] == 0{
			_, err = file.WriteString("Port " + strconv.Itoa(resultStore[i]) + " | closed\n")
			if err != nil{
				fmt.Println(err)
				return
			}
			}else if resultStore[i+1] == 1{
				_, err = file.WriteString("Port " + strconv.Itoa(resultStore[i]) + " | open\n")
				if err != nil{
					fmt.Println(err)
					return
				}
			}else if resultStore[i+1] == 2{
				_, err = file.WriteString("Port " + strconv.Itoa(resultStore[i]) + " | filtered/slow\n")
				if err != nil{
					fmt.Println(err)
					return
				}
			}else if resultStore[i+1] == 3{
				_, err = file.WriteString("Port " + strconv.Itoa(resultStore[i]) + " | unknown\n")
				if err != nil{
					fmt.Println(err)
					return
				}
			}else if resultStore[i+1] == 4{
				_, err = file.WriteString("Port " + strconv.Itoa(resultStore[i]) + " | filtered/open\n")
				if err != nil{
					fmt.Println(err)
					return
				}
			}
		}
	}

	return
}
/*
Sources:
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
*/