import nmap, sys
import subprocess
from os import system
######################################################
#                        KEY                         #
#                                                    #
#       #### = Start or End of Function              #
#                                                    #
#       # = notes and simple comments                #
#                                                    #
#       ### = Explanation of function processes      #
#                                                    #
#       ######### = End of Functions in Class        #
#                                                    #
#       ##### = section identifier                   #
#                                                    #
######################################################
class NmapLearningTool:
    #### Start of NmapScam() ####
    ### Take Ip from ping and do 1 of 3 scans: TCP, UDP , or indepth-TCP ### 
    def pullIpPing():
            url = input("Website?: ") 
            pingCommand = ("ping -i 1 -c 1  " + url)
            pingOutput= subprocess.run(pingCommand, shell=True,text=True,capture_output=True)
            pingCheck = system(pingcommand)
            if(pingCheck != 256):
                #strip down
                global pingResultHolder
                pingResultHolder = pingOutput.stdout.split(" ")[2].strip("()")
                return(pingResultHolder)
            else:
                print("Server Is Not responding, Try Again")
                sys.exit()
        #### End of pullIpPing() ####

    def NmapScan():
        global userIP
        #### Start of pullIpPing() ####
        ### Using System to ping a url ###
        
        ### start main process of function, call pullIpPing, then go through with the stats ###                    
        nm = nmap.PortScanner()    
        userIP = pingResultHolder
        scanType = int(input("Pick a Scan Type:\n\t1: TCP Scan\n\t2: UDP Scan(Run in Root)\n\t3: In-Depth TCP(Run in Root)\n    Choice: "))

         
        #This will look at the server status and then print out the open ports
        #IS SOLEY CONNECTED TO THE MATCH AS IT WILL PRINT OUT THE OPEN PORTS
        #### Start of ServerStat() #### 
        ### used to tell if our servers are up, if so they will print out the ports ###
        def ServerStat():
            if((nm[userIP].state()) == ("up")):
                print("Server Staus: up")
                print("Open Ports:", openPorts)
            else:
                print("Server is Down")            
        #### End of ServerStat() ####
        openPorts = ""
        match scanType:
            case 1:#TCP SCANs
                nm.scan(userIP, "1-1024", "-sT")
                openPorts = str(nm[userIP]['tcp'].keys()).strip("dict_keys()")
                ServerStat()                
            case 2:#UDP SCAN -sU
                nm.scan(userIP, "1-1024", "-sU")
                openPorts = str(nm[userIP]['udp'].keys()).strip("dict_keys()")
                ServerStat()
            case 3:# TCP SCAN -sT -O        
                nm.scan(userIP, "1-1024", "-sT -O")      
                openPorts = str(nm[userIP]['tcp'].keys()).strip("dict_keys()")
                ServerStat()
                print("osFamily:",nm[userIP][f"osmatch"][1]['osclass'][0]['osfamily'])  
            case _:
                print("That was not an option!")
    #### End of NmapScan() ####
                            ######### End of Functions in Class ######### 
    ######## RunSequence ########
    pullIPPing()
    NmapScan() 
