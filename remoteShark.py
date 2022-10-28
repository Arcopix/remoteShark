#!/usr/bin/python3
# remoteShark utility, Python version

import sys
import os
import os.path
import re
import inspect
import time
import subprocess
import platform

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

            if argv[i] == '--debug' or argv[i] == '-d':
                self.debug = self.debug + 1
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
                i = i + 1
                continue

            printf("Unrecognized parameter %s\n", argv[i])
            i = i + 1

    """ Validates the PCAP filter in order to ensure that some special symbols are not used """
    def validateFilter(self):
        test = re.search('[\\\\;"`-]', self.dumpFilter)
        if test != None:
            printf("PCAP filter cannot have semicolon (;), backslash (\), dash (-), dollar sign ($), backtick (`) or double quotes (\")\n")
            sys.exit(1)
        return

    """ Escapes several special symbols in the PCAP filter """
    def escapeFilter(self):
        self.dumpFilter = re.sub('\(', '\(', self.dumpFilter)
        self.dumpFilter = re.sub('\)', '\)', self.dumpFilter)
        return

    """ Validates interface name """
    def validateIface(self):
        test = re.search('[ \t"/$`]', self.interface)
        if test != None:
            printf("Interface cannot have white spaces, slashes, dollar signs, backtick or double quotes\n")
            sys.exit(1)
        if len(self.interface) == 0:
            printf("Interface name cannot be empty\n")
            sys.exit(1)
        print(self.interface)
        return

    """ Convert the configuration to string for debug purposes """
    def __str__(self):
        data = ""
        for x in inspect.getmembers(self):
            if not x[0].startswith('_'):
                if not inspect.ismethod(x[1]):
                    data = data + sprintf("%s=%s\n", x[0], x[1])
        return data

class RemoteShark:
    platform = None
    cfg = None

    def __init__(self):
        global cfg

        self.platform = platform.system()
        self.cfg = cfg
        
        if cfg.debug >= 2:
            printf("Detected platform '%s'\n", self.platform)
    
    """ Print usage information for the utility """
    def printHelp(self):
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
    
    """ Detect plink/ssh and wireshark availability and capabilities """
    def detectRequirement(self):
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
    
    """ Connect to remote host and list available interfaces on the remote system """
    def listInterfaces(self):
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
    
    """ Proof of concept/development method for fetching remote packet capture instead of live capturing of traffic """
    def remotePCAP(self):
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

    """ Tests connection to the remote host (for Windows) and adds the remote host SSH key if needed """
    def testConnection(self):
        # :: Try to login and generate output of "All good" to check for connection issues
        # %PLINK_PATH% -batch -ssh root@%REMOTE_HOST% "echo All good" 2>NUL | findstr "All good" >NUL
        global cfg
        login = sprintf('%s@%s', cfg.sshUser, cfg.sshHost)
        plinkCmd = [cfg.plinkPath, '-batch', '-ssh', login, "echo \"remoteShark::connectionTest::good\""]

        if self.cfg.debug >= 3:
            printf('Running connection process "%s"\n', plinkCmd)

        plinkProcess = subprocess.Popen(plinkCmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        out, err = plinkProcess.communicate()

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
        global cfg
        login = sprintf('%s@%s', cfg.sshUser, cfg.sshHost)

        plinkCmd = [cfg.plinkPath, '-ssh', login, "echo \"remoteShark::connectionTest::good\""]
        plinkProcess = subprocess.Popen(plinkCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

        if self.cfg.debug >= 3:
            printf('Running connection process "%s"\n', plinkCmd)

        plinkProcess.stdin.write('y'.encode())
        plinkProcess.stdin.flush()
        out, err = plinkProcess.communicate()

        printf("%s\n", out.decode())
        printf("%s\n", err.decode())

        if (re.search("remoteShark::connectionTest::good", out.decode())):
            return True
        else:
            return False

    """ Connect to the remote host and start local Wireshark for live capturing of traffic """
    def runWireshark(self):
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

        if self.platform == 'Windows':
            DETACHED_PROCESS = 0x00000008
            plinkCmd = [cfg.plinkPath, '-batch', '-ssh', login, tcpdumpCMD]

            self.testConnection()

            if self.cfg.debug >= 3:
                printf('Running connection process "%s"\n', plinkCmd)
                printf('Running Wireshark process "%s"\n', wireCmd)
            
            plinkProcess = subprocess.Popen(plinkCmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            wireProcess = subprocess.Popen(wireCmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=plinkProcess.stdout,
                creationflags=DETACHED_PROCESS)
        else: # Linux or Mac (Darwin)
            sshCmd = [cfg.plinkPath, login, tcpdumpCMD]

            if self.cfg.debug >= 3:
                printf('Running connection process "%s"\n', plinkCmd)
                printf('Running Wireshark process "%s"\n', wireCmd)

            sshProcess = subprocess.Popen(sshCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ.copy())
            wireProcess = subprocess.Popen(wireCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=sshProcess.stdout)

        # Run processes
        if cfg.runTimeout != None and cfg.runTimeout > 0:
            try:
                wireProcess.wait(cfg.runTimeout)
            except subprocess.TimeoutExpired:
                # Leave wireshark process running
                if self.cfg.debug >= 1:
                    printf("Reached timeout\n")
                sys.exit(0)
            except:
                printf("Unknown issue\n")
                sys.exit(1)
        else:
            out, err = wireProcess.communicate()

if __name__ == '__main__':
    # Initialize configuration
    cfg = AppConfig(sys.argv)

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
