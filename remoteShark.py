#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
  RemoteShark is a utility allowing the user to capture traffic in real-time
  from remote system which supports SSH and tcpdump into local Wireshark.
  
  The utility supports Linux/MacOS/Windows local workstations and most if not
  all Unix/Linux systems.
"""
__author__ = "Stefan Lekov"
__copyright__ = "Copyright 2022, Devhex Ltd"
__credits__ = ["Stefan Lekov", "Theo Belder", "Atanas Angelov", "Linda Aleksandrova" ]
__license__ = "GPLv3"
__version__ = "1.0.0-alpha3"
__maintainer__ = "Stefan Lekov"
__email__ = "stefan.lekov@devhex.org"
__status__ = "Testing"

import sys
import os
import os.path
import re
import inspect
from ipaddress import ip_address
import time
import subprocess
import platform
import signal
from socket import gethostbyname

# Use Devhex' Python common for printf/sprintf
try:
    from devhex.common import *
except:
    # Fallback to local definitions if not available
    from local import sprintf
    from local import printf

# Default locations for Windows
WIN_WIRESHARK_PATH="\\Wireshark\\Wireshark.exe"
WIN_PLINK_PATH="\\PuTTY\\plink.exe"

MAC_WIRESHARK_PATH="/Applications/Wireshark.app/Contents/MacOS/Wireshark"

class AppConfig:
    # Path of binaries
    wiresharkPath = None
    plinkPath = None
    packetCount = None
    runTimeout = None
    listInterfaces = False
    interface = 'any'
    sshUser = 'root'
    sshHost = None
    dumpFilter = 'not port 22'

    debug = 0

    def __init__(self, argv):
        """ Construct the application's configuration """
        argc = len(argv)
        if argc == 1:
            RemoteShark.printHelp(None)
            sys.exit(0)

        # Skip argv[0] since that should hold the application name
        i = 1
        while i < argc:

            if argv[i] == '--help' or argv[i] == '-h':
                RemoteShark.printHelp(None)
                sys.exit(0)

            if argv[i] == '--debug':
                self.debug = self.debug + 1
                i = i + 1
                continue

            if re.match('^-d[d]*$', argv[i]):
                self.debug = self.debug + len(re.findall('d', argv[i]))
                i = i + 1
                continue

            if argv[i] == '--list-interfaces':
                self.listInterfaces = True
                i = i + 1
                continue

            if argv[i] == '--count' or argv[i] == '-c':
                if argc <= i + 1:
                    printf("%s requires an argument\n", argv[i])
                    sys.exit(1)
                try:
                    self.packetCount = int(argv[i + 1])
                except:
                    printf("%s requires an integer argument\n", argv[i])
                    sys.exit(2)
                i = i + 2
                continue

            if argv[i] == '--timeout' or argv[i] == '-t':
                if argc <= i + 1:
                    printf("%s requires an argument\n", argv[i])
                    sys.exit(1)
                try:
                    self.runTimeout = int(argv[i + 1])
                except:
                    printf("%s requires an integer argument\n", argv[i])
                    sys.exit(2)
                i = i + 2
                continue

            if argv[i] == '--user' or argv[i] == '-u':
                if argc <= i + 1:
                    printf("%s requires an argument\n", argv[i])
                    sys.exit(1)
                else:
                    self.sshUser = argv[i + 1]
                    i = i + 2
                    continue

            if argv[i] == '--filter' or argv[i] == '-f':
                if argc <= i + 1:
                    printf("%s requires an argument\n", argv[i])
                    sys.exit(1)
                else:
                    self.dumpFilter = argv[i + 1]
                    self.validateFilter()
                    self.escapeFilter()
                    i = i + 2
                    continue

            if argv[i] == '--interface' or argv[i] == '-i':
                if argc <= i + 1:
                    printf("%s requires an argument\n", argv[i])
                    sys.exit(1)
                else:
                    self.interface = argv[i + 1]
                    self.validateIface()
                    i = i + 2
                    continue

            # Consume the first non-recognized argument as the host
            if self.sshHost == None:
                self.sshHost = argv[i]
                self.validateHost()
                i = i + 1
                continue

            printf("Unrecognized parameter %s\n", argv[i])
            i = i + 1

    def validateFilter(self):
        """ Validates the PCAP filter in order to ensure that some special symbols are not used """
        test = re.search('[\\\\;"`-]', self.dumpFilter)
        if test != None:
            printf("PCAP filter cannot have semicolon (;), backslash (\), dash (-), dollar sign ($), backtick (`) or double quotes (\")\n")
            sys.exit(1)
        return

    def escapeFilter(self):
        """ Escapes several special symbols in the PCAP filter """
        self.dumpFilter = re.sub('\(', '\(', self.dumpFilter)
        self.dumpFilter = re.sub('\)', '\)', self.dumpFilter)
        return

    def validateIface(self):
        """ Validates interface name """
        test = re.search('[ \t"/$`]', self.interface)
        if test != None:
            printf("Interface cannot have white spaces, slashes, dollar signs, backtick or double quotes\n")
            sys.exit(1)
        if len(self.interface) == 0:
            printf("Interface name cannot be empty\n")
            sys.exit(1)
        print(self.interface)
        return

    def validateHost(self):
        """ Validates specified host """
        try:
            ip_address(self.sshHost)
            if self.debug > 2:
                printf("Detected host (%s) as an IP address\n", self.sshHost)
            return
        except:
            try:
                buf = gethostbyname(self.sshHost)
                if self.debug > 2:
                    printf("Resolved host (%s) to %s\n", self.sshHost, buf)
            except:
                printf("Cannot resolve host %s\n", self.sshHost)
                sys.exit(1)
            return

    def __str__(self):
        """ Convert the configuration to string for debug purposes """
        data = ""
        for x in inspect.getmembers(self):
            if not x[0].startswith('_'):
                if not inspect.ismethod(x[1]):
                    data = data + sprintf("%s=%s\n", x[0], x[1])
        return data

class RemoteShark:
    platform = None
    cfg = None

    __sshProcess = None
    __plinkProcess = None
    __wireProcess = None
    
    def __init__(self):
        global cfg

        self.platform = platform.system()
        self.cfg = cfg
        
        if cfg.debug >= 2:
            printf("Detected platform '%s'\n", self.platform)
    
    def printHelp(self):
        """ Print usage information for the utility """
        helpData = """Usage: remoteShark.py [OPTIONS] host
 -c  --count             Stop capture after receiving count packets
 -d  --debug             Enables debug mode
 -f  --filter            Filters which packets will be captured. For filter
                         syntax see pcap-filter(7) man page on a Linux system.
                         Default filter is "not port 22".
 -h  --help              Prints the current help message
     --list-interfaces   Connects to the remote host and lists interfaces
                         available for capturing traffic
 -i  --interface         Remote interface to listen on (default any)
 -t  --timeout           Stop capture after timeout has expired
 -u  --user              SSH user to connect as (default root)

    """
        printf("%s\n", helpData)
        return

    def detectRequirement(self):
        """ Detect plink/ssh and wireshark availability and capabilities """
        global WIN_WIRESHARK_PATH
        global WIN_PLINK_PATH
        global cfg

        WIRESHARK_FOUND = False
        PLINK_FOUND = False
        
        if self.platform == 'Windows':
            if os.path.exists(os.environ["ProgramFiles"] + WIN_WIRESHARK_PATH):
                cfg.wiresharkPath = os.environ["ProgramFiles"] + WIN_WIRESHARK_PATH
                WIRESHARK_FOUND = True
    
            if os.path.exists(os.environ["ProgramFiles(x86)"] + WIN_WIRESHARK_PATH):
                cfg.wiresharkPath = os.environ["ProgramFiles(x86)"] + WIN_WIRESHARK_PATH
                WIRESHARK_FOUND = True
    
            if os.path.exists(os.environ["ProgramFiles"] + WIN_PLINK_PATH):
                cfg.plinkPath = os.environ["ProgramFiles"] + WIN_PLINK_PATH
                PLINK_FOUND = True
    
            if os.path.exists(os.environ["ProgramFiles(x86)"] + WIN_PLINK_PATH):
                cfg.plinkPath = os.environ["ProgramFiles(x86)"] + WIN_PLINK_PATH
                PLINK_FOUND = True

        if self.platform == 'Linux' or self.platform == 'Darwin':
            # Check for SSH support
            try:
                process = subprocess.Popen([ "ssh", "-V" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = process.communicate()
            except:
                if self.cfg.debug > 1:
                    printf("Unable to detect ssh\n")
                return False

            if process.returncode != 0:
                if self.cfg.debug > 1:
                    printf("Unable to detect ssh\n")
                PLINK_FOUND = False
            else:
                if self.cfg.debug > 2:
                    printf("Detected SSH version %s%s\n", out.decode(), err.decode())
                cfg.plinkPath = 'ssh'
                PLINK_FOUND = True
            
            # Check for Wireshark support
            if self.platform == 'Linux':
                wiresharkPath = 'wireshark'
            else: # IF self.platform == 'Darwin':
                wiresharkPath = MAC_WIRESHARK_PATH
            
            try:
                process = subprocess.Popen([ wiresharkPath, "-v" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = process.communicate()
            except:
                if self.cfg.debug > 1:
                    printf("Unable to detect wireshark\n")
                return False

            if process.returncode != 0:
                if self.cfg.debug > 1:
                    printf("Unable to detect wireshark\n")
                WIRESHARK_FOUND = False
            else:
                if self.cfg.debug > 2:
                    printf("Detected Wireshark version %s%s\n", out.decode().split("\n")[0], err.decode().split("\n")[0])
                cfg.wiresharkPath = wiresharkPath
                WIRESHARK_FOUND = True
            
        return WIRESHARK_FOUND and PLINK_FOUND
    
    def listInterfaces(self):
        """ Connect to remote host and list available interfaces on the remote system """
        global cfg
        login = sprintf('%s@%s', cfg.sshUser, cfg.sshHost)
        command = """
printf "%10s | %24s\\n" "Interface" "Status";
printf -- "-----------+--------------------------\\n";
tcpdump --list-interfaces | sed 's/^[0-9]\+\.//' | sort |
sed 's/(.*)//g;s/\[//g;s/\\]//g;s/ [ ]\+/ /g' | sed "s/^\([^ ]\+\) \(.*\)$/'\\1' '\\2'/" |
xargs printf "%10s | %24s\\n"
"""
        if self.platform == 'Windows':
            self.testConnection()
            process = subprocess.Popen([cfg.plinkPath, '-batch', '-ssh', login, command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else: # Linux or Mac (Darwin)
            process = subprocess.Popen([cfg.plinkPath, login, command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        out, err = process.communicate()
        print(out.decode())
    
    def remotePCAP(self):
        """ Proof of concept/development method for fetching remote packet capture instead of live capturing of traffic """
        # No implementation at the moment
        """ Some notes
For Windows:
    (successful proof of concept)
        # plinkCmd = [cfg.plinkPath, '-batch', '-ssh', login, "cat /tmp/p.pcap"]
    (an idea) Wireshak generally understands GZIP data, might be an idea to reduce transfer times
        # plinkCmd = [cfg.plinkPath, '-batch', '-ssh', login, "cat /tmp/p.pcap | gzip"]
        Added general ideas for accessing remote
For Linux: (an idea)
    linkCmd = ["scp USER@REMOTE:/tmp/p.pcap /tmp/XXX ; wireshak /tmp/xxx"]
        """

    def testConnection(self):
        """ Tests connection to the remote host (for Windows) and adds the remote host SSH key if needed """
        # :: Try to login and generate output of "All good" to check for connection issues
        # %PLINK_PATH% -batch -ssh root@%REMOTE_HOST% "echo All good" 2>NUL | findstr "All good" >NUL
        global cfg
        login = sprintf('%s@%s', cfg.sshUser, cfg.sshHost)
        plinkCmd = [cfg.plinkPath, '-batch', '-ssh', login, "echo \"remoteShark::connectionTest::good\""]

        if self.cfg.debug >= 3:
            printf('Running connection process "%s"\n', plinkCmd)

        self.__plinkProcess = subprocess.Popen(plinkCmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        out, err = self.__plinkProcess.communicate()

        if (re.search("remoteShark::connectionTest::good", out.decode())):
            if self.cfg.debug >= 2:
                printf('Successful connection to the remote host')
            return

        if (re.search("The server's host key is not cached", err.decode())):
            printf("%s\n", err.decode())
            printf("\n\nThis utility will automatically add the host key in 5 seconds.\n")
            printf("Press Ctrl+C to abort... \n")
            try:
                time.sleep(5)
            except(KeyboardInterrupt):
                printf("ABORTED\n")
                sys.exit(0)

            if (self.addHostKeyCache()):
                return
            else:
                printf("Error occurred while attempting to add the host key\n")
                printf("%s\n", out.decode())
                printf("%s\n", err.decode())
                sys.exit(1)
        else:
            printf("Error while testing connection to %s\n", cfg.sshHost)
            printf("%s\n", out.decode())
            printf("%s\n", err.decode())
            sys.exit(1)

        return

    def addHostKeyCache(self):
        """ Automatically adds the remote host RSA keys to the local cache """
        global cfg
        login = sprintf('%s@%s', cfg.sshUser, cfg.sshHost)

        plinkCmd = [cfg.plinkPath, '-ssh', login, "echo \"remoteShark::connectionTest::good\""]
        self.__plinkProcess = subprocess.Popen(plinkCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

        if self.cfg.debug >= 3:
            printf('Running connection process "%s"\n', plinkCmd)

        self.__plinkProcess.stdin.write('y'.encode())
        self.__plinkProcess.stdin.flush()
        out, err = self.__plinkProcess.communicate()

        printf("%s\n", out.decode())
        printf("%s\n", err.decode())

        if (re.search("remoteShark::connectionTest::good", out.decode())):
            return True
        else:
            return False

    def runWireshark(self):
        """ Connect to the remote host and start local Wireshark for live capturing of traffic """
        global cfg
        login = sprintf('%s@%s', cfg.sshUser, cfg.sshHost)

        tcpdumpCMD = ''
        if cfg.runTimeout != None and cfg.runTimeout > 0:
            # It usually takes about a second to establish the connection
            # Thus - increase the timeout by 1
            tcpdumpCMD = sprintf("%s timeout %d ", tcpdumpCMD, cfg.runTimeout + 1)

        tcpdumpCMD = tcpdumpCMD + 'tcpdump'

        if cfg.packetCount != None and cfg.packetCount > 0:
            tcpdumpCMD = sprintf("%s -c %d", tcpdumpCMD, cfg.packetCount)
        # It is important to suppress STDERR, otherwise the data from tcpdump STDERR will break Wireshark
        tcpdumpCMD = sprintf('%s -U -ni "%s" -s 0 -q -w - %s 2>/dev/null', tcpdumpCMD, cfg.interface, cfg.dumpFilter)
	
        if self.cfg.debug >= 3:
            printf('Running command remote "%s"\n', tcpdumpCMD)

        # Wireshark is run with the same arguments for all OS
        wireCmd = [cfg.wiresharkPath, '-k', '-i', '-']

        self.setupSignals()

        if self.platform == 'Windows':
            DETACHED_PROCESS = 0x00000008
            plinkCmd = [cfg.plinkPath, '-batch', '-ssh', login, tcpdumpCMD]

            self.testConnection()

            if self.cfg.debug >= 3:
                printf('Running connection process "%s"\n', plinkCmd)
                printf('Running Wireshark process "%s"\n', wireCmd)
            
            self.__plinkProcess = subprocess.Popen(plinkCmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            self.__wireProcess = subprocess.Popen(wireCmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=self.__plinkProcess.stdout,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        else: # Linux or Mac (Darwin)
            sshCmd = [cfg.plinkPath, login, tcpdumpCMD]

            if self.cfg.debug >= 3:
                printf('Running connection process "%s"\n', sshCmd)
                printf('Running Wireshark process "%s"\n', wireCmd)

            self.__sshProcess = subprocess.Popen(sshCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ.copy())
            self.__wireProcess = subprocess.Popen(wireCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=self.__sshProcess.stdout, start_new_session=True)

        # Run processes
        if cfg.runTimeout != None and cfg.runTimeout > 0:
            try:
                self.__wireProcess.wait(cfg.runTimeout)
            except subprocess.TimeoutExpired:
                # Leave wireshark process running
                if self.cfg.debug >= 1:
                    printf("Reached timeout\n")
                sys.exit(0)
            except:
                printf("Unknown issue\n")
                sys.exit(1)
        else:
            printf("Press Ctrl+C to terminate capture and exit\n")
            while True:
                for p in (self.__sshProcess, self.__plinkProcess):
                    if p != None and p.poll() != None:
                        if self.cfg.debug > 3:
                            printf("Detected exit from SSH, exiting\n")
                        sys.exit(0)
                
                if self.__wireProcess.poll() != None:
                    if self.cfg.debug > 3:
                        printf("Detected exit from Wireshark, exiting\n")
                    sys.exit(0)
                
                time.sleep(1)

    def signalHandler(self, sig, frame):
        printf("Cleaning the child with sig %d\n", sig)
        if self.__plinkProcess != None:
            printf("Stopping plink\n")
            if self.__sshProcess.poll() == None:
                os.kill(self.__sshProcess.pid, signal.SIGTERM)
            if self.__plinkProcess.poll() == None:
                os.kill(self.__plinkProcess.pid, signal.SIGTERM)
        sys.exit(0)

    def setupSignals(self):
        for sig in (signal.SIGABRT, signal.SIGILL, signal.SIGINT, signal.SIGTERM):
            if self.cfg.debug > 3:
                printf("Setting the hook %s\n", signal.strsignal(sig))
            signal.signal(sig, self.signalHandler)


if __name__ == '__main__':
    # Initialize configuration
    cfg = AppConfig(sys.argv)

    if cfg.sshHost == None or len(cfg.sshHost) == 0:
        printf("No host was specified\n\n")
        app = RemoteShark()
        app.printHelp()
        sys.exit(1)

    # Initialize the application
    app = RemoteShark()

    if not app.detectRequirement():
        if app.platform == 'Windows':
            printf("Cannot detect Wireshark or plink\n")
        else:
            printf("Cannot detect wireshark or ssh\n")
        
        sys.exit(1)

    if cfg.debug >= 3:
        printf("Current config:\n%s\n", cfg)

    if cfg.listInterfaces:
        app.listInterfaces()
        sys.exit(0)

    app.runWireshark()
#" set autoindent expandtab tabstop=4 shiftwidth=4
#" vim: autoindent expandtab tabstop=4 shiftwidth=4
# vim: et ts=4 sw=4 sts=4
