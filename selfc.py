from mitmproxy.platform import windows
import psutil
import json
from datetime import datetime

class SelfCShared:
    # Static members are set from plugin onload
    HTTPFilterObj = None
    FailedLogPath = ""
    TcpTable = None
    
    def writeFailedSSLDomain(domain, reason, conn):
        jsonObj = SelfCShared.getPath(conn).copy();
        jsonObj.update({"time":str(datetime.now()), "url": domain, "reason": reason})
        if SelfCShared.FailedLogPath != "":
            with open(SelfCShared.FailedLogPath, "a") as f:
                json.dump(jsonObj,f)
                f.write('\n')

    def isTrusted(domain):
        result = False
        if not SelfCShared.HTTPFilterObj is None:
            result = SelfCShared.HTTPFilterObj.isTrustedHost(domain)
        return result
        
    def getPath(conn):
        result = {"user": "NONE", "path": "NONE", "pid": -1}
        try:
            addr = conn[0] # String
            port = conn[1] # int
            
            if addr is None:  
                return result
        
            # Instance init
            if SelfCShared.TcpTable is None:
                SelfCShared.TcpTable = windows.TcpConnectionTable()
            
            # Try original address (may contain router ip like 192.168.1.105)
            if (addr,port) not in SelfCShared.TcpTable:
                SelfCShared.TcpTable.refresh()            
            pid = SelfCShared.TcpTable.get((addr,port), -1)
            
            if pid < 0 and  addr.startswith("::ffff:"): # Table might have it as ip4
                pid = SelfCShared.TcpTable.get((addr.replace("::ffff:",""),port), -1)
            
            if pid > -1:
                result = {"user": "ERROR", "path": "ERROR", "pid": pid}
                proc = psutil.Process(pid)
                cmdline = "" # Future:  " " + " ".join(proc.cmdline())
                result = {"user": proc.username(), "path": proc.exe() + cmdline, "pid": pid}
            else:
                print(SelfCShared.TcpTable.__dict__)
        except Exception as ex:
            print("******* Error selfc getting path: " + str(ex))
        
        return result