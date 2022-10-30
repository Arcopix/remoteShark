## TODO

2. Fully test (and bugfix) for Mac
5. Fully test and bugfix
8. Split remoteShark.py into a library and have basic scripts which execute the behavior _(?)_
9. Support for display filter in local Wireshark
11. Update project dir tree (remove win/linux dirs, move sources to src)
12. Build system for compiling via pyinstaller
13. Implement compression of the stream

## DONE

1. Rewrite the utility in Python(?) for improved capabilities
2. Implement capability to list remote interfaces
3. Implement (optional) timeout for capturing traffic
4. Implement (optional) maximum count of packets to be captured
5. Implement -i|--interface options to select correct interface
6. Check if the remote host key is in _known_hosts_  
7. Detection of *HOST* between *FQDN* and *IP* address
8. Detached Wireshark in Linux _(?)_
9. Work with remote pcap files
10. Support for non standard SSH port
