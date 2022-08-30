#!/usr/bin/python3
# Test python script

import sys
import os
import os.path
import re
import inspect
import subprocess
import platform

try:
    from devhex.common import *
except:
    from local import sprintf
    from local import printf

WIRESHARK_PATH="\\Wireshark\\Wireshark.exe"
PLINK_PATH="\\PuTTY\\plink.exe"

class AppConfig:
    # Path of binaries
    wiresharkPath = None
    plinkPath = None
    packetCount = None
    runTimeout = None
    listInterfaces = False
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
                    i = i + 2
                    continue

            # Consume the first non-recognized argument as the host
            if self.sshHost == None:
                self.sshHost = argv[i]
                i = i + 1
                continue

            printf("Unrecognized parameter %s\n", argv[i])
            i = i + 1

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

    def __init__(self):
        global cfg

        self.platform = platform.system()
        
        if cfg.debug >= 2:
            printf("Detected platform '%s'\n", self.platform)

    def printHelp(self):
        helpData = """Usage: remoteShark.py [OPTIONS] host
 -d  --debug             Enables debug mode
 -h  --help              TBA
     --list-interfaces   TBA
 -c  --count             TBA
 -t  --timeout           TBA
 -u  --user              TBA
 -t  --timeout           TBA
 -f  --filter            TBA
    """
        printf("%s\n", helpData)

    def detectRequirement(self):
        global WIRESHARK_PATH
        global PLINK_PATH
        global cfg

        WIRESHARK_FOUND = False
        PLINK_FOUND = False
        
        if self.platform == 'Windows':
            if os.path.exists(os.environ["ProgramFiles"] + WIRESHARK_PATH):
                cfg.wiresharkPath = os.environ["ProgramFiles"] + WIRESHARK_PATH
                WIRESHARK_FOUND = True
    
            if os.path.exists(os.environ["ProgramFiles(x86)"] + WIRESHARK_PATH):
                cfg.wiresharkPath = os.environ["ProgramFiles(x86)"] + WIRESHARK_PATH
                WIRESHARK_FOUND = True
    
            if os.path.exists(os.environ["ProgramFiles"] + PLINK_PATH):
                cfg.plinkPath = os.environ["ProgramFiles"] + PLINK_PATH
                PLINK_FOUND = True
    
            if os.path.exists(os.environ["ProgramFiles(x86)"] + PLINK_PATH):
                cfg.plinkPath = os.environ["ProgramFiles(x86)"] + PLINK_PATH
                PLINK_FOUND = True

        if self.platform == 'Linux':
            printf("Not (yet) supported!\n")
            sys.exit(1)

        return WIRESHARK_FOUND and PLINK_FOUND

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
        process = subprocess.Popen([cfg.plinkPath, '-batch', '-ssh', login, command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        print(out.decode())
        print(err.decode())

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

        tcpdumpCMD = sprintf('%s -U -ni eth0 -s 0 -q -w - %s 2>/dev/null', tcpdumpCMD, cfg.dumpFilter)

        process = subprocess.Popen([
            cfg.plinkPath, '-batch', '-ssh', login, tcpdumpCMD, '|',
            cfg.wiresharkPath, '-k', '-i', '-'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if cfg.runTimeout != None and cfg.runTimeout > 0:
            process.wait(cfg.runTimeout)
        out, err = process.communicate()
        #print(out.decode())
        #print(err.decode())

if __name__ == '__main__':
    # Initialize configuration
    cfg = AppConfig(sys.argv)

    # Initialize the application
    app = RemoteShark()

    if not app.detectRequirement():
        printf("Cannot detect Wireshark or plink\n")
        sys.exit(1)

    if cfg.debug >= 3:
        printf("Current config:\n%s\n", cfg)

    if cfg.listInterfaces:
        app.listInterfaces()
        sys.exit(0)

    app.runWireshark()
