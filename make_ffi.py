import re
import os
import sys
import cffi
import subprocess
import platform

import logging
l = logging.getLogger('cffier')
l.setLevel(logging.DEBUG)

def find_good_bsearch(known_good, questionable):
    ffi = cffi.FFI()
    l.debug("bsearch - trying %d good and %d questionable", len(known_good), len(questionable))

    try:
        ffi.cdef('\n'.join(known_good + questionable))
    except (cffi.CDefError, AssertionError):
        return find_good_bsearch(known_good, questionable[:len(questionable)/2])

    return questionable

def find_good_scan(known_good, questionable):
    ffi = cffi.FFI()
    l.debug("scan - trying %d good and %d questionable", len(known_good), len(questionable))

    #print "GOOD:"
    #print '  ...'
    #print '  ' + '\n  '.join(known_good[-5:])
    #print "UNKNOWN:"
    #print '  ' + '\n  '.join(questionable[:5])
    #print '  ...'
    #print '  ' + '\n  '.join(questionable[-5:])

    try:
        ffi.cdef('\n'.join(known_good + questionable))
        return questionable
    except AssertionError:
        return [ ]
    except cffi.CDefError as e:
        if str(e).count(':') >= 2:
            fail = int(str(e).split('\n')[1].split(':')[1])
        elif 'unrecognized construct' in str(e):
            fail = int(str(e).split()[1][:-1])
        elif 'end of input' in str(e):
            return find_good_scan(known_good, questionable[:-1])
        else:
            raise Exception("Unknown error")
    except cffi.FFIError as e:
        if str(e).count(':') >= 2:
            fail = int(str(e).split('\n')[0].split(':')[1])
        else:
            raise Exception("Unknown error")

    return find_good_scan(known_good, questionable[:fail-2-len(known_good)])

def doit(vex_path):
    cpplist = ['cl', 'cpp']
    cpp = os.getenv("CPP")
    if cpp:
        cpplist.insert(0, cpp)
    if platform.system() == 'Darwin':
        cpplist.insert(0, "clang")

    errs = []
    for cpp in cpplist:
        cmd = [cpp, '-I' + vex_path, os.path.join("pyvex_c", "pyvex.h")]
        if cpp in ('cl', 'clang', 'gcc', 'cc', 'clang++', 'g++'):
            cmd.append("-E")
        try:
            p = subprocess.Popen(cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            header, stderr = p.communicate()
            if not header.strip() or p.returncode != 0:
                errs.append((" ".join(cmd), p.returncode, stderr))
                continue
            else:
                break
        except OSError:
            errs.append((" ".join(cmd), -1, "does not exist"))
            continue
    else:
        l.warning("failed commands:\n" +
                  "\n".join("{} ({}) -- {}".format(*e) for e in errs))
        raise Exception("Couldn't process pyvex headers." +
                "Please set CPP environmental variable to local path of \"cpp\"." +
                "Note that \"cpp\" and \"g++\" are different."
                )
    #header = vex_pp + pyvex_pp

    linesep = '\r\n' if '\r\n' in header else '\n'
    ffi_text = linesep.join(line for line in header.split(linesep) if '#' not in line and line.strip() != '' and 'jmp_buf' not in line)
    ffi_text = re.sub('\{\s*\} NoOp;', '{ int DONOTUSE; } NoOp;', ffi_text)
    ffi_text = re.sub('__attribute__\s*\(.*\)', '', ffi_text)
    ffi_text = re.sub('__declspec\s*\([^\)]*\)', '', ffi_text)
    ffi_text = ffi_text.replace('__const', 'const')
    ffi_text = ffi_text.replace('__inline', '')
    ffi_text = ffi_text.replace('__w64', '')
    ffi_text = ffi_text.replace('__cdecl', '')
    ffi_text = ffi_text.replace('__int64', 'long')
    ffi_lines = ffi_text.split(linesep)

    good = find_good_scan([], ffi_lines)
    remaining = ffi_lines[len(good)+1:]

    while len(remaining) > 1:
        l.debug("%d uncertain lines remaining", len(remaining))
        new_good = find_good_scan(good, remaining[1:])
        good += new_good
        remaining = remaining[len(new_good)+1:]

    good += [ 'extern VexControl vex_control;' ]

    open('pyvex/vex_ffi.py', 'w').write('ffi_str = """' + '\n'.join(good) + '"""')

if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.DEBUG)
    doit(sys.argv[1])
