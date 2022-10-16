# remoteShark
A set of utilities allowing the user to capture traffic in real-time from remote system which supports SSH and tcpdump (basically most Unix/Linux systems) into local Wireshark.

## Versions

* Python - Full implementation of the utility in Python 3 with multi OS support.
* Window - Initial/proof of concept version implemented in a simple BAT file.
  * **Version is obsolete**
* Linux - Initial/proof of concept version implemented in a simple BASH file
  * **Version is obsolete.**

## HOWTO

Listing interfaces on remote system `10.20.30.40`:
> `remoteShark.py 10.20.30.40 --list-interfaces`

Capture any traffic on remote system `10.20.30.40`:
> `remoteShark.py 10.20.30.40`

Capture any traffic coming from host `10.10.10.10` on remote system `10.20.30.40`:
> `remoteShark.py 10.20.30.40 -f "host 10.10.10.10"`

Capture HTTP traffic (`port 80`) on interface `eth0` on remote system `10.20.30.40`:
> `remoteShark.py 10.20.30.40 -f "port 80" -i eth0`

Capture SIP traffic (`port 5060 or 5061`) for 100 packets on any interface on remote system `10.20.30.40`:
> `remoteShark.py 10.20.30.40 -f "port 5060 or 5061" -c 100`

Capture SMTP traffic (`port 25`) for 5 minutes (300 seconds) on eth0.44 interface on remote system `10.20.30.40`:
> `remoteShark.py 10.20.30.40 -f "port 25" -t 300 -i eth0.44`

## TODO

Current TODO/DONE list is available in [TODO](TODO.md)

## CHANGELOG

The CHANGELOG is available [here](CHANGELOG.md)
