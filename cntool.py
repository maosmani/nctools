import click 
import os
from ipaddress import ip_address 
import socket
from ipwhois import IPWhois
from pprint import pprint
#THis part is for the working code

def IPAddress(IP: str) -> str: 
    return "Private" if (ip_address(IP).is_private) else "Public"
#os.system('cmd /k netstat')
#This part of the code will create a file and write all connection on the device to it.
def write():
    file_exists = os.path.isfile('empty.txt') 
    if file_exists:
        file = open("empty.txt","r+")
        file.truncate(0)
        file.close()
    else:
        file = open('empty.txt','a+')
        file.close()

    file_exists = os.path.isfile('out.txt') 
    if file_exists:
        file = open("out.txt","r+")
        file.truncate(0)
        file.close()
    else:
        file = open('out.txt','a+')
        file.close()
    # do something else


    file = open('empty.txt',"w")
    netstat = os.popen(' netstat -n').read()
    file.write(netstat + "\n")
    file.close()
    # Read lines as a list
    fh = open("empty.txt", "r")
    lines = fh.readlines()
    fh.close()
    # Weed out blank lines with filter
    lines = filter(lambda x: not x.isspace(), lines)
    # Write
    fh = open("out.txt", "w")
    for line in lines:
        if line.strip("\n") != "line1":
        	fh.write("".join(lines))

    fh.close()

    lines = open('out.txt', 'r').readlines() 
    lines =lines[1:] 
    open('out.txt', 'w').writelines(lines) 

def seeWhoIs():
    write()


    logFile = open("out.txt", "r")
    i = 0
    for line  in logFile:

        
        s = line.split()
        x = s[2]
       
        ip = x.split(":")
        ipLook = ip[0]
        port = ip[1]

        ipLook = socket.gethostbyname(ipLook)
        ipType =    IPAddress(ipLook)
        
        if ipType == "Public":
            obj = IPWhois(ipLook)
            results = obj.lookup_whois()
            print(i,results['asn_description'])
            #pprint(obj.lookup_whois())
            #print(socket.getfqdn(ipLook))#This part of the code will get you the domains and ip addresses where your device is connected to

        else:
            print(i,'The ip address : ' + ipLook + "  it is privite ip address!!!")
                
        i=i+1
#This part is for the code that command line use

def who_ip(ipLook):

        ipLook = socket.gethostbyname(ipLook)
        ipType =    IPAddress(ipLook)
        
        if ipType == "Public":
            obj = IPWhois(ipLook)
            results = obj.lookup_whois()
            print("Ip Address Belong To: ",results['asn_description'])
            #pprint(obj.lookup_whois())
            #print(socket.getfqdn(ipLook))#This part of the code will get you the domains and ip addresses where your device is connected to

        else:
            print('The ip address : ' + ipLook + "  it is privite ip address!!!")
                
def port_to_service():
    write()
    

    logFile = open("out.txt", "r")
    for line  in logFile:
        s = line.split()
        protocolname = s[0]
        x = s[2]
        ip = x.split(":")
        port = ip[1]
        port = int(port)
        try: 
            print ("Port: %s => service name: %s" %(port, socket.getservbyport(port, protocolname))) 
        except:
            print("Port %s are private port"%(port))

        #print(port)
        #print(protocol)
        #service = socket.getservbyport(port)
        #print(service)
def find_service_name(): 
    protocolname = 'tcp' 
    for port in [80, 25]: 
        print ("Port: %s => service name: %s" %(port, socket.getservbyport(port, protocolname))) 
     
    print ("Port: %s => service name: %s" %(53, socket.getservbyport(53, 'udp'))) 


@click.group()
def main():
  pass


@click.command()
def cn():
    click.echo(' ')
    click.echo('You are connected to:')
    click.echo(' ')
    write()
    with open('out.txt') as file:
    	lines = file.readlines()
    	for line in lines:
            line = line.split()
            ip_with_port = line[2]
            ip = ip_with_port.split(':')

            click.echo(f"  {ip[0]}")


@click.command()
def whois():
    click.echo(' ')
    click.echo('You are connected to:')
    click.echo(' ')
    seeWhoIs()
@click.command()
@click.argument('ip')
def whoip(ip):
    #ipLook = click.prompt('Please enter Ip Address')
    #click.echo(f"Ip Address is: {ipLook}")
    who_ip(ip)
    
@click.command()
def port():
    port_to_service()
    
    
    

main.add_command(cn)
main.add_command(whois)
main.add_command(whoip)
main.add_command(port)

if __name__ == '__main__':
    main()