import requests, json, sys, os, argparse
from json2html import *
import urllib3
urllib3.disable_warnings()


def checkcredential():
    global mgmt_host
    mgmt_host = str(os.environ.get("mgmthost"))
    global mgmt_port
    mgmt_port = str(os.environ.get("mgmtport"))
    global username
    username=str(os.environ.get("user"))
    global password
    password=str(os.environ.get("pass"))
    if mgmt_host == "None" or mgmt_port == "None" or username == "None" or password == "None":
        print("The following environment variables need to be set")
        print("mgmthost: {}".format(mgmt_host))
        print("mgmtport: {}".format(mgmt_port))
        print("user: {}".format(username))
        print("pass: {}".format(len(password)))
        return 0
    else:
        return 1

def getnumberlist(input,typeofinput):
    result = []
    if typeofinput=="f":
        with open(input,"r") as f:
            line = f.readlines()
    else:
        line = input.split()
    for l in line:
        l=l.rstrip("\n")
        if "-" in l:
            list=l.split("-")
            assert (int(list[1])>int(list[0])),"list must be incremental"
            for i in range (int(list[0]),int(list[1])+1):
                result.append(str(i))
                i+=1
        elif "," in l:
            for i in l.split(","):
                result.append(i)
        elif l!="":
            result.append(l)
    return result

def getnamelist(input,typeofinput):
    result=[]
    if typeofinput=="f":
        with open(input,"r") as f:
            line = f.readlines()
    else:
        line = input.split(",")
    for l in line:
        l=l.rstrip("\n")
        if "," in l:
            for i in l.split(","):
                result.append(i)
        elif l!="":
            result.append(l)
    return result

def api_call(ip_addr, port, command, json_payload, sid):
    url = 'https://' + ip_addr + ':' + port + '/web_api/' + command
    if sid == '':
        request_headers = {'Content-Type' : 'application/json'}
    else:
        request_headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}
    r = requests.post(url,data=json.dumps(json_payload), headers=request_headers,verify=False)
    return r.json()

def login(host, port, user,password):
    payload = {'user':user, 'password' : password}
    response = api_call(host, port, 'login',payload, '')
    return response["sid"]

def logout(user,password,sid):
    logout_result = api_call(mgmt_host, mgmt_port,"logout", {},sid)
    if logout_result["message"] == "OK":
        print("logout successfully")				
    #print("logout result: " + json.dumps(logout_result))				

def get_key(data,key1,key2):
    data1=data.get(key1)
    try:
        if key2 == "":
            return str(data1)
        else:
            if key2 not in data1:
                key2="name"	
            return str(data1.get(key2))
    except:
	    return "ERROR"

def getaccesslayers(server,port,sid):
    command = 'show-access-layers'
    layer = 'Network'
    host_data = {"limit" : 50, "offset" : 0, "details-level" : "standard"}
    result = api_call(mgmt_host, mgmt_port,command,host_data,sid)
    print(json.dumps(result))
    formatted_table = json2html.convert(json=result)
    print(formatted_table)

def getnatrule(server,port,rulelist,sid):
    command = 'show-nat-rule'
    policy = 'DC_Policy'
    header=["Rule","Source","Destination","Port","Protocol","NAT_Src","NAT_Dest","NAT_Services","Comment"]
    listofrule=[]
    listofrule.append(header)
    for rulenumber in rulelist:
        host_data = {'rule-number':rulenumber, 'package':policy}
        result = api_call(mgmt_host, mgmt_port,command, host_data ,sid)
        rule=[]
        rule.append(rulenumber)
        rule.append(get_key(result,'original-source','ipv4-address-first')) #0
        rule.append(get_key(result,'original-destination','ipv4-address')) #1
        rule.append(get_key(result,'original-service','port')) #2
        rule.append(get_key(result,'original-service','type')) #3
        rule.append(get_key(result,'translated-source','ipv4-address')) #4
        rule.append(get_key(result,'translated-destination','ipv4-address')) #5
        rule.append(get_key(result,'translated-service','name')) #6
        rule.append(get_key(result,'comments','')) #7
        listofrule.append(rule)
    return listofrule

def getaccessrule(server,port,rulelist,sid):
    command = 'show-access-rule'
    layer = 'DC_Policy Security'
    header=["Rule","Name","Source","Destination","Services","VPN","Content","Action","Time","Track","Install On","Comment"]
    listofrule=[]
    listofrule.append(header)
    for rulenumber in rulelist:
        host_data = {'rule-number':rulenumber, 'layer':layer}
        result = api_call(mgmt_host, mgmt_port,command, host_data ,sid)
        rule=[]
        rule.append(rulenumber)
        rule.append(get_key(result,'name',"")) #0
        listofsource=""
        for r in result['source']:
            for k,v in r.items():
                if k == 'type' and v == 'host':
                    # print(k,": ",v,end='')
                    # print("name:",r['name'],end='')
                    # print("IP: ",r['ipv4-address'])
                    source = r['name'] + " - IP: " + r['ipv4-address'] + " + "
                if k == 'type' and v == 'network':
                    # print(k,": ",v,end='')
                    # print("name:",r['name'],end='')
                    # print("Net: ",r['subnet4'])
                    source = r['name'] + " - Net: " + r['subnet4'] + "/" + str(r['mask-length4']) + " + "
                elif k == 'type' and v == 'group':
                    # print(k,": ",v, end='')
                    # print("name:",r['name'])
                    source = r['name'] + " + "
                elif k == 'type' and v == 'CpmiAnyObject':
                    source = r['name'] + " + "
            listofsource+=source
        if result['source-negate'] == False:
            rule.append(listofsource[:-3])
        else:
            rule.append("NOT ("+listofsource[:-3]+")")
        listofdestination=""
        for r in result['destination']:
            for k,v in r.items():
                if k == 'type' and v == 'host':
                    destination = r['name'] + " - IP: " + r['ipv4-address'] + " + "
                if k == 'type' and v == 'network':
                    destination = r['name'] + " - Net: " + r['subnet4'] + "/" + str(r['mask-length4']) + " + "
                elif k == 'type' and v == 'group':
                    destination = r['name'] + " + "
                elif k == 'type' and v == 'CpmiAnyObject':
                    destination = r['name'] + " + "
            listofdestination+=destination
        if result['destination-negate'] == False:
            rule.append(listofdestination[:-3])
        else:
            rule.append("NOT ("+listofdestination[:-3]+")")
        listofservice=""
        for r in result['service']:
            if r['name'] == "Any" or r['type']=="service-group":
                service=r['name'] + " + "
            elif r['type']=="service-tcp":
                service=r['name']+(" - TCP/") +r['port'] + " + "
            elif r['type']=="service-udp":
                service=r['name']+(" - UDP/") +r['port'] + " + "
            listofservice+=service
        if result['service-negate'] == False:
            rule.append(listofservice[:-3])
        else:
            rule.append("NOT ("+listofservice[:-3]+")")
        rule.append(result['vpn'][0]['name'])
        rule.append(result['content'][0]['name'])
        rule.append(result['action']['name'])
        rule.append(result['time'][0]['name'])
        rule.append(result['track']['type']['name'])
        rule.append(result['install-on'][0]['name'])
        rule.append(result['comments'])            
        listofrule.append(rule)
        if result['action']['name'] == "Inner Layer":
            inlinelayer=result['inline-layer']['name']
            totalinlinerule=getaccessrulebase(mgmt_host,mgmt_port,inlinelayer,sid)
            inlinerule=getaccessruleinline(mgmt_host,mgmt_port,rulenumber,totalinlinerule,inlinelayer,sid,0)
            for r in inlinerule:
                listofrule.append(r)
    return listofrule

def getaccessruleinline(server,port,parentrule,total,layer,sid,addheader):
    command = 'show-access-rule'
    header=["Rule","Name","Source","Destination","Services","VPN","Content","Action","Time","Track","Install On","Comment"]
    listofrule=[]
    if addheader == 1:
        listofrule.append(header)
    for rulenumber in range(1,total+1):
        host_data = {'rule-number':rulenumber, 'layer':layer}
        result = api_call(mgmt_host, mgmt_port,command, host_data ,sid)
        rule=[]
        rule.append(str(parentrule)+"."+str(rulenumber))
        rule.append(get_key(result,'name',"")) #0
        listofsource=""
        for r in result['source']:
            for k,v in r.items():
                if k == 'type' and v == 'host':
                    source = r['name'] + " - IP: " + r['ipv4-address'] + " + "
                if k == 'type' and v == 'network':
                    source = r['name'] + " - Net: " + r['subnet4'] + "/" + str(r['mask-length4']) + " + "
                elif k == 'type' and v == 'group':
                    source = r['name'] + " + "
                elif k == 'type' and v == 'CpmiAnyObject':
                    source = r['name'] + " + "
            listofsource+=source
        if result['source-negate'] == False:
            rule.append(listofsource[:-3])
        else:
            rule.append("NOT ("+listofsource[:-3]+")")
        listofdestination=""
        for r in result['destination']:
            for k,v in r.items():
                if k == 'type' and v == 'host':
                    destination = r['name'] + " - IP: " + r['ipv4-address'] + " + "
                if k == 'type' and v == 'network':
                    destination = r['name'] + " - Net: " + r['subnet4'] + "/" + str(r['mask-length4']) + " + "
                elif k == 'type' and v == 'group':
                    destination = r['name'] + " + "
                elif k == 'type' and v == 'CpmiAnyObject':
                    destination = r['name'] + " + "
            listofdestination+=destination
        if result['destination-negate'] == False:
            rule.append(listofdestination[:-3])
        else:
            rule.append("NOT ("+listofdestination[:-3]+")")
        listofservice=""
        for r in result['service']:
            if r['name'] == "Any" or r['type']=="service-group" or r['type']=="application-site":
                service=r['name'] + " + "
            elif r['type']=="service-tcp":
                service=r['name']+(" - TCP/") +r['port'] + " + "
            elif r['type']=="service-udp":
                service=r['name']+(" - UDP/") +r['port'] + " + "
            listofservice+=service
        if result['service-negate'] == False:
            rule.append(listofservice[:-3])
        else:
            rule.append("NOT ("+listofservice[:-3]+")")
        rule.append(result['vpn'][0]['name'])
        rule.append(result['content'][0]['name'])
        if result['action']['name'] == "Inner Layer":
            rule.append(result['action']['name'] + " - " + result['inline-layer']['name'])
        else:
            rule.append(result['action']['name'])
        rule.append(result['time'][0]['name'])
        rule.append(result['track']['type']['name'])
        rule.append(result['install-on'][0]['name'])
        rule.append(result['comments'])            
        listofrule.append(rule)
    return listofrule

def getaccessrulebase(server,port,layer,sid):
    command = 'show-access-rulebase'
    #layer = 'DC_Policy Security'
    #layer = 'School_8030_InlinePolicy_Outbound'
    header=["Rule","Name","Source","Destination","Services","VPN","Content","Action","Time","Track","Install On","Comment"]
    listofrule=[]
    listofrule.append(header)
    host_data = {'name':layer}
    result = api_call(mgmt_host, mgmt_port,command, host_data ,sid)
    #formatted_table = json2html.convert(json=result)
    #print(formatted_table)
    return result['total']

def getapplicationsite(server,port,names,sid):
    command = 'show-application-site'
    header=["Name","Primary-Category","URL-List"]
    listofrule=[]
    listofrule.append(header)
    for name in names:
        host_data = {'name':name}
        result = api_call(mgmt_host, mgmt_port,command, host_data ,sid)
        rule=[]
        rule.append(name)
        rule.append(result['primary-category'])
        for r in result['url-list']:
            rule.append(r)
        listofrule.append(rule)    
    return listofrule

def getnetworkgroup(server,port,groups,sid):
    command = 'show-group'
    header=["GroupName","Name","Type","Address"]
    output=[]
    output.append(header)
    for groupname in groups:
        host_data = {'name':groupname}
        result = api_call(mgmt_host, mgmt_port,command, host_data ,sid)
        for r in result['members']:
            listofmembers=[]
            listofmembers.append(groupname)
            listofmembers.append(r['name'])
            listofmembers.append(r['type'])
            if r['type'] == 'host':
                listofmembers.append(r['ipv4-address'])
            if r['type'] == 'network':
                listofmembers.append(r['subnet4']+"/"+str(r['mask-length4']))
            if r['type'] == 'address-range':
                listofmembers.append(r['ipv4-address-first']+"-"+str(r['ipv4-address-last']))
            output.append(listofmembers)
    return output

def printresult(data,printto,format,filename="output.txt"):
    try:
        output=""
        if format=="csv":
            for line in data:
                for i,item in enumerate(line):
                    output+=item.replace("\n","")+","
                output+="\n"
        elif format=="text":
            data.pop(0)
            for line in data:
                for i,item in enumerate(line):
                    output+=item+"\n"
                output+="\n"
        if printto == "stdout":
            print(output)
        elif printto == "file":
            with open(filename,'w') as f:
                f.write(output)
            print("Save to {} successfully".format(filename))
    except Exception as e:
        print(e)

def main():
#Menu
    parser=argparse.ArgumentParser(description='Check Point Policy Management')
    parser.add_argument('-w','--writefile',type=str,metavar='',help='File to write output to')
    group1=parser.add_mutually_exclusive_group(required=True)
    group1.add_argument('-f','--file',type=str,metavar='',help='File contains rule list')
    group1.add_argument('-r','--rule',type=str,metavar='',help='Rule list, dash or comma separted, no space')
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-n', '--nat',action='store_true', help='nat policy')
    group.add_argument('-a', '--access',action='store_true', help='security access')
    group.add_argument('-as', '--applicationsite',action='store_true', help='applicaiton site')
    group.add_argument('-g', '--group',action='store_true', help='network group')
    args=parser.parse_args()

#GET Rule List or Application Site Name List
    if args.applicationsite or args.group and args.file:
        rulelist=getnamelist(args.file,"f")
    elif args.applicationsite or args.group and args.rule:
        rulelist=getnamelist(args.rule,"r")
    elif args.file:
        rulelist=getnumberlist(args.file,"f")
    elif args.rule:
        rulelist=getnumberlist(args.rule,"r")

#CHECK if credential set  
    if checkcredential():
        sid = login(mgmt_host, mgmt_port, username,password)
    else:
        print("Please set host and credential!")
        sys.exit(1)

#NAT RULE
    if args.nat:
        result=getnatrule(mgmt_host,mgmt_port,rulelist,sid)
        if not args.writefile:
            printresult(result,"stdout","csv")
        else:
            printresult(result,"file","csv",args.writefile)

#ACCESS RULE
    if args.access:
        result = getaccessrule(mgmt_host,mgmt_port,rulelist,sid)
        if not args.writefile:
            printresult(result,"stdout","csv")
        else:
            printresult(result,"file","csv",args.writefile)

#Application Site
    if args.applicationsite:
        result=getapplicationsite(mgmt_host,mgmt_port,rulelist,sid)
        if not args.writefile:
            printresult(result,"stdout","csv")
        else:
            printresult(result,"file","csv",args.writefile)
    
#Network Group
    if args.group:
        result=getnetworkgroup(mgmt_host,mgmt_port,rulelist,sid)
        if not args.writefile:
            printresult(result,"stdout","csv")
        else:
            printresult(result,"file","csv",args.writefile)
        

#Access Rule Base
    # inlinelayer="InlinePolicy_Outbound"
    # totalinlinerule=getaccessrulebase(mgmt_host,mgmt_port,inlinelayer,sid)
    #print(totalinlinerule)

#Access Rule Inline
    # result=getaccessruleinline(mgmt_host,mgmt_port,totalinlinerule,inlinelayer,sid)
#ACCESS LAyer
    # getaccesslayers(mgmt_host,mgmt_port,sid)
    # logout(username,password,sid)	

if __name__ == '__main__':
    main()
