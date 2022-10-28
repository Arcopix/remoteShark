# CHANGELOG

## Alpha 3

* Implemented a check if the remote host key is in _known_hosts_
* Brackets in packet capture filter are now automatically escaped
* PCAP filter is now softly validated for potentially dangerous characters
* Interface name is now validated
* Implemented detection of -dd, -ddd, etc for setting the debug level to higher values
* Implemented verification of the remote host (provided by hostname or IP address)
* Fixed Wireshark to be run as detached process for Linux/Windows

## Alpha 2

* Fixed  issues with detection of Wireshark with MacOS/Darwin
* Implemented interface (-i|--interface) argument
* Actual help message (-h|--help) was added

## Alpha 1

* Initial release of the Python version
* Implemented capability to list remote interfaces
* Implemented optional timeout for capturing traffic
* Implemented optional maximum count of packets to be captured
