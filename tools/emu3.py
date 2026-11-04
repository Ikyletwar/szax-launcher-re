#!/usr/bin/env python3
# Emulator stub packer SZAX/UPX ARM64 dengan VFS (/proc/self/exe) dan memfd
import struct, os
from unicorn import *
from unicorn.arm64_const import *

PATH = "/tmp/opencode/szax/bin/szax.arm64"
BASE = 0x40000000
raw = open(PATH, "rb").read()

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mu.mem_map(BASE, (len(raw)+0xfffff)&~0xfffff, UC_PROT_ALL)
mu.mem_write(BASE, raw)
mu.mem_map(0x30000000, 0x4000000, UC_PROT_ALL)   # area tujuan loader
mu.mem_map(0x50000000, 0x8000000, UC_PROT_ALL)
mu.mem_map(0x5ff00000, 0x100000, UC_PROT_ALL)    # stack
mu.reg_write(UC_ARM64_REG_SP, 0x5ffff000 - 0x100)
ENTRY = BASE + 0xa81a6c
mu.reg_write(UC_ARM64_REG_PC, ENTRY)

class F:
    def __init__(self, data, name=""):
        self.b = bytearray(data); self.p = 0; self.name = name
files = {}
nextfd = [10]
memfd_name = {}
dumps = []
log = []
alloc_cursor = [0x38000000]
execs = []

def rd(a,n):
    try: return bytes(mu.mem_read(a,n))
    except Exception: return b""
def cstr(a,m=300):
    b=rd(a,m); z=b.find(b"\0"); return b[:z if z>=0 else m].decode("latin1","replace")
def alloc(n, fixed=None):
    n=(n+0xfff)&~0xfff
    if fixed is not None:
        try: mu.mem_map(fixed,n,UC_PROT_ALL)
        except Exception: pass
        return fixed
    a=alloc_cursor[0]; alloc_cursor[0]=(a+n+0xfff)&~0xfff
    try: mu.mem_map(a,n,UC_PROT_ALL)
    except Exception:
        pass
    return a

def newfd(data, name=""):
    nextfd[0]+=1; files[nextfd[0]]=F(data,name); return nextfd[0]

def on_svc():
    pc=mu.reg_read(UC_ARM64_REG_PC); x8=mu.reg_read(UC_ARM64_REG_X8)
    a=[mu.reg_read(UC_ARM64_REG_X0+i) for i in range(6)]
    s=f"pc={pc-BASE:#x} nr={x8} "+" ".join(f"x{i}={v:#x}" for i,v in enumerate(a))
    r=0
    if x8==279:  # memfd_create
        nm=cstr(a[0]); r=newfd(b"",nm); memfd_name[r]=b""
        s+=f" memfd({nm!r})->{r}"
    elif x8==56:  # openat
        p=cstr(a[1]); s+=f" openat({p!r})"
        if p=="/proc/self/exe": r=newfd(raw,"/proc/self/exe")
        elif p in ("/dev/null","/dev/urandom"): r=-2
        else: r=-2
        s+=f"->{r}"
    elif x8==78:  # readlinkat
        p=cstr(a[1]); s+=f" readlinkat({p!r})"
        if p=="/proc/self/exe":
            dst=b"/data/local/tmp/.szx/szaxbin\0"
            if a[3] > len(dst): mu.mem_write(a[2], dst)
            r=len(dst)-1
        else: r=-2
        s+=f"->{r}"
    elif x8==57: s+=" close"; r=0
    elif x8==62:  # lseek
        f=files.get(a[0]); s+=f" lseek(fd={a[0]},off={a[1]},wh={a[2]})"
        if f:
            if a[2]==0: f.p=a[1]
            elif a[2]==1: f.p+=a[1]
            elif a[2]==2: f.p=len(f.b)+a[1]
            r=f.p
        else: r=-9
    elif x8==63:  # read
        f=files.get(a[0]); s+=f" read(fd={a[0]},len={a[2]})"
        if f:
            chunk=f.b[f.p:f.p+a[2]]; mu.mem_write(a[1],bytes(chunk)); f.p+=len(chunk); r=len(chunk)
        else: r=-9
        s+=f"->{r}"
    elif x8==64:  # write
        b=rd(a[1],a[2]); s+=f" write(fd={a[0]},len={a[2]},head={b[:20].hex()})"
        f=files.get(a[0])
        if f: f.b[f.p:f.p+len(b)]=b; f.p+=len(b)   # memfd
        else: dumps.append((a[0],b))
        r=a[2]
    elif x8==222:  # mmap
        addr,ln,prot,flags,fd,off=a
        if fd in files:
            f=files[fd]; sz=len(f.b)
            base=alloc(max(ln,sz), fixed=(addr if (flags&0x10 and addr) else None))
            content=bytes(f.b[off:off+ln])
            if content: mu.mem_write(base,content)
            r=base
            s+=f" mmap(fd={fd},len={ln:#x},off={off},flags={flags:#x}) -> {r:#x} (file {sz})"
        else:
            base=alloc(ln, fixed=(addr if (flags&0x10 and addr) else None))
            r=base; s+=f" mmap(addr={addr:#x},len={ln:#x},prot={prot},flags={flags:#x},fd={fd},off={off}) -> {r:#x}"
    elif x8==226: s+=f" mprotect({a[0]:#x},{a[1]:#x},{a[2]})"
    elif x8==215: s+=f" munmap({a[0]:#x},{a[1]:#x})"
    elif x8==214: s+=f" brk({a[0]:#x})"; r=0x54000000
    elif x8 in (221,281):
        path=cstr(a[0] if x8==221 else a[1]); s+=f" EXEC {path!r} fd={a[0] if x8==281 else '-'}"
        log.append(s); execs.append((a,rd(0,0))); raise SystemExit(0)
    elif x8==93:
        s+=f" exit({a[0]})"; log.append(s); raise SystemExit(0)
    else:
        s+=" UNHANDLED"; r=0
    log.append(s)
    mu.reg_write(UC_ARM64_REG_X0, r & 0xffffffffffffffff)
    mu.reg_write(UC_ARM64_REG_PC, pc+4)

def on_code(mu,addr,size,ud):
    try: w=struct.unpack("<I",bytes(mu.mem_read(addr,4)))[0]
    except Exception: return
    if (w & 0xffe0001f)==0xd4000001: on_svc()

mu.hook_add(UC_HOOK_CODE,on_code)
try:
    mu.emu_start(ENTRY,0,count=2000000000)
except SystemExit: pass
except UcError as e: print("UCERR",e,"pc",hex(mu.reg_read(UC_ARM64_REG_PC)-BASE))

print("syscalls:",len(log))
for l in log[:40]: print(l)
print("...last...")
for l in log[-12:]: print(l)
for fd,f in files.items():
    if len(f.b)>0x1000:
        p=f"/tmp/opencode/szax/out_fd{fd}.bin"; open(p,"wb").write(bytes(f.b)); print("FILE",p,len(f.b),f.name,bytes(f.b[:8]).hex())
