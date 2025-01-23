## TODO

1. Fully test (and bugfix) for Mac
1. Split remoteShark.py into a library and have basic scripts which execute the behavior _(?)_
1. Support for display filter in local Wireshark
1. Update project dir tree (remove win/linux dirs, move sources to src)
2. Build system for compiling via pyinstaller

## DONE

1. Rewrite the utility in Python(?) for improved capabilities
2. Implement capability to list remote interfaces
3. Implement (optional) timeout for capturing traffic
4. Implement (optional) maximum count of packets to be captured
5. Implement -i|--interface options to select correct interface
6. Fully test and bugfix
7. Check if the remote host key is in _known_hosts_  
8. Detection of *HOST* between *FQDN* and *IP* address
9. Detached Wireshark in Linux _(?)_
10. Work with remote pcap files
11. Support for non-standard SSH port
12. Implement compression of the data stream
