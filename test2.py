import pyvex, ctypes, archinfo

"""
add(a longlong, b longlong) -> long long
0:  55                      push   rbp
1:  48 89 e5                mov    rbp,rsp
4:  48 89 f8                mov    rax,rdi
7:  48 01 f0                add    rax,rsi
a:  5d                      pop    rbp
b:  c3                      ret
"""

code = "\x55\x48\x89\xE5\x48\x89\xF8\x48\x01\xF0\x48\x39\xF0\x7F\x05\xB8\xEF\xBE\xAD\xDE\x5D\xC3"
code = "\x55\x48\x89\xE5\x48\x89\xF8\x48\x01\xF0\xB8\xEF\xBE\xAD\xDE\x5D\xC3"
code = "\xcc\x55\x48\x89\xE5\x48\x89\xF8\x48\x01\xF0\x5D\xC3"
#code = "\xC3"

def run_code(code, type, *args):
	code_buffer = ctypes.create_string_buffer(4096*2+len(code))
	addr = (ctypes.addressof(code_buffer) + 4096) & (~(4096-1))
	ctypes.memmove(addr, code, len(code))

	libc = ctypes.cdll.LoadLibrary("libc.so.6")
	mprotect = libc.mprotect
	mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
	mp_ret = mprotect(addr, len(code), 4)
	if mp_ret:
		errno = ctypes.c_int.in_dll(ctypes.pythonapi, "errno")
		libc.strerror.restype = ctypes.c_char_p
		errno_str = libc.strerror(errno)
		raise OSError("Failed to set memory protection (%s)" % (errno_str))

	try:
		print args
		func = type(addr)
		ret = func(*args)
	finally:
		mprotect(addr, len(code), 3)

	return ret

#print run_code(code, ctypes.CFUNCTYPE(ctypes.c_longlong, ctypes.c_longlong, ctypes.c_longlong), 1, 2)

arch = archinfo.arch_amd64.ArchAMD64()
p = pyvex.IRSB(code, 0x1234, arch)

print p.offsIP

irsb = p._to_c()
p2 = pyvex.IRSB.from_c(irsb, 0x1234, arch)
assert p._pp_str() == p2._pp_str()
p.pp()

p.arch.vex_archinfo['hwcache_info']['caches'] = pyvex.ffi.NULL

#pvc.log_level = l.getEffectiveLevel()

#if self.max_inst is None: self.max_inst = 99
#if self.max_bytes is None: self.max_bytes = 5000
#c_irsb = pvc.vex_lift(vex_arch, self.irsb.arch.vex_archinfo, self.data + self.bytes_offset, self.irsb._addr, self.max_inst, self.max_bytes, self.opt_level, self.traceflags, self.allow_lookback)

buf = pyvex.ffi.new('unsigned char [%d]' % 4096, '\0' * 4096)
bytes_used = pyvex.ffi.new('int*')
print pyvex.pvc.vex_drop, (p.arch.vex_arch, p.arch.vex_archinfo, irsb, buf, 4096)
pyvex.pvc.vex_drop(getattr(pyvex.pvc, p.arch.vex_arch), p.arch.vex_archinfo, irsb, buf, 4096, bytes_used)
n_bytes = bytes_used[0]
if n_bytes > 0:
	buf = pyvex.ffi.buffer(buf, n_bytes)
	code = str(buf)
	print code.encode("hex")
	code = "\xcc" + code
	#print run_code(code, ctypes.CFUNCTYPE(ctypes.c_longlong, ctypes.c_longlong, ctypes.c_longlong), 1, 2)

log_str = str(pyvex.ffi.buffer(pyvex.pvc.msg_buffer, pyvex.pvc.msg_current_size)) if pyvex.pvc.msg_buffer != pyvex.ffi.NULL else None
print log_str

#print repr(buf)

"""
log_str = str(ffi.buffer(pvc.msg_buffer, pvc.msg_current_size)) if pvc.msg_buffer != ffi.NULL else None

if c_irsb == ffi.NULL:
    self._error = "libvex: unkown error" if log_str is None else log_str
    return False
else:
    if log_str is not None:
        l.info(log_str)
"""