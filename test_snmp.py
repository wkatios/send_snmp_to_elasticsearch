#coding=utf-8
import time
import json
import copy

from pysnmp.hlapi import *
from pysnmp.smi import builder, view, compiler, rfc1902
from pysnmp.entity.rfc3413.oneliner import cmdgen

from elasticsearch import Elasticsearch
from elasticsearch import helpers
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

# read conf.ini
import  ConfigParser
cf = ConfigParser.ConfigParser()
cf.read('conf.ini')

# iterator
cmdGen = cmdgen.CommandGenerator()

#snmpwalk -v 2c -c public 127.0.0.1 1.3.6.1.2.1.4.20.1.2

# judge windows or linux
def init_system():
    oid_init_system = cf.get("init_system", "oid")
    errorIndication, errorStatus, errorIndex, varBindTable = iterator_get(oid_init_system)
    if errorIndication:
        print(errorIndication)
        return None
    elif errorStatus:
        print('%s at %s\n' % (errorStatus.prettyPrint(), errorIndex and varBindTable[int(errorIndex) - 1][0] or '?'))
        return None
    elif 'indows' in varBindTable[0].prettyPrint():
        system = 'Windows'
    elif 'Linux' in varBindTable[0].prettyPrint():
        system = 'Linux'
    return system

# iterator for snmp walk
def iterator(oid):
    iterator = cmdGen.nextCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((target_server, 161)),
        oid,
        lookupNames=True, lookupValues=True
    )
    return iterator

# iterator for snmp get
def iterator_get(oid):
    iterator_get=getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((target_server, 161)),
               ContextData(),
               ObjectType(ObjectIdentity(oid))
               ).next()
    return iterator_get

# get response key and value   type:list  -- key_list:["1.3.6.1.4.1.2021.10.1.3.3"]   value_list: ["0.01"]
def get_info(errorIndication, errorStatus, errorIndex, varBindTable):
    info_list_key = []
    info_list_value = []
    # print varBindTable
    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s\n' % (errorStatus.prettyPrint(),errorIndex and varBindTable[int(errorIndex) - 1][0] or '?'))
    elif isinstance(varBindTable[0], list) :
        for varBindTableRow in varBindTable:
            for oid, value in varBindTableRow:
                info_list_key.append(str(oid))
                info_list_value.append(str(value))
    else:
        for oid, value in varBindTable:
            info_list_key.append(str(oid))
            info_list_value.append(str(value))
    return info_list_key,info_list_value

# timestamp to time for human
def time_conversion(atime):
    day, hour, min, sec, ms = 0,0,0,0,0
    if int(atime) > 24*60*60*100:
        day = int(atime)/(24*60*60*100)
        atime = int(atime)%(24*60*60*100)
    if 60*60*100 <= int(atime) < 24*60*60*100:
        hour = int(atime)/(60*60*100)
        atime = int(atime)%(60*60*100)
    if 60*100 <= int(atime) < 60*60*100:
        min = int(atime)/(60*100)
        atime = int(atime)%(60*100)
    if 100 <= int(atime) <60*100:
        sec = int(atime)/100
        atime = int(atime)%100
    if 0 <= int(atime) < 100:
        ms = int(atime)
    # if 100 < int(atime) <=
    time_hunman = '%s day, %s:%s:%s.%s'%(day,hour,min,sec,ms)
    return time_hunman

# disk Byte to GB for human
def disk_human(disk,format=1024):
    # GB, MB, KB,B = None,None,None,None
    if disk > format**3:    #G*M*K
        GB = (disk / (format**3))
        disk_odd = disk % (format**3)/(format**2)
        return '%s.%s GB'%(GB,str(disk_odd)[:1])
    if format**2 <= disk < format**3:   #M*K
        MB = (disk / (format**2))
        disk_odd = disk % (format**2)/format
        return '%s.%s MB' % (MB, str(disk_odd)[:1])
    if format <= disk < format**2:    #K
        KB = (disk/format)
        disk_odd = disk % format
        return '%s.%s KB' % (KB, str(disk_odd)[:1])
    if 0 <= disk < format:    # B
        B = disk
        return str(B)+'B'

# snmp  get system info
# dict "snmp" for bulk to es
def system_info():
    oid_system_soft = cf.get("%s.system_info"%system, "oid_system_soft")
    errorIndication, errorStatus, errorIndex, varBindTable = iterator(oid_system_soft)
    list_system_soft = get_info(errorIndication, errorStatus, errorIndex, varBindTable)
    if '1.3.6.1.2.1.1.3.0' in list_system_soft[0]:
        system_uptime = list_system_soft[1][list_system_soft[0].index('1.3.6.1.2.1.1.3.0')]
        sys_uptime_human = time_conversion(system_uptime)
        snmp["system"]["sys_uptime"] = sys_uptime_human
    if '1.3.6.1.2.1.1.5.0' in list_system_soft[0]:
        system_name = list_system_soft[1][list_system_soft[0].index('1.3.6.1.2.1.1.5.0')]
        snmp["system"]["sys_name"] = system_name
    if '1.3.6.1.2.1.1.7.0' in list_system_soft[0]:
        system_services = list_system_soft[1][list_system_soft[0].index('1.3.6.1.2.1.1.7.0')]
        snmp["system"]["services"] = int(system_services)
    oid_system_hard = cf.get("%s.system_info" % system, "oid_system_hard")
    errorIndication, errorStatus, errorIndex, varBindTable = iterator(oid_system_hard)
    list_system_hard = get_info(errorIndication, errorStatus, errorIndex, varBindTable)
    if '1.3.6.1.2.1.25.1.1.0' in list_system_hard[0]:
        hard_uptime = list_system_hard[1][list_system_hard[0].index('1.3.6.1.2.1.25.1.1.0')]
        hard_uptime_human = time_conversion(hard_uptime)
        snmp["system"]["hard_uptime"] = hard_uptime_human
    if '1.3.6.1.2.1.25.1.6.0' in list_system_hard[0]:
        system_processes = list_system_hard[1][list_system_hard[0].index('1.3.6.1.2.1.25.1.6.0')]
        snmp["system"]["processes"] = int(system_processes)
    return snmp

# snmp get cpu info
def cpu_info():
    cpu_oid = cf.get("%s.cpu_info"%system, "oid")
    errorIndication, errorStatus, errorIndex, varBindTable = iterator(cpu_oid)
    list_cpu_info = get_info(errorIndication, errorStatus, errorIndex, varBindTable)
    total = 0
    if 'Windows' in system:
        for i in list_cpu_info[1]:
            total += float(i)
        average = round((total/(len(list_cpu_info[1])*1.0))/100.0,2)
    if 'Linux' in system:
        for i in list_cpu_info[1]:
            total += float(i)
        average = round((total/(len(list_cpu_info[1])*1.0)),2)
    # return average
    snmp["cpu"]["userage"] = average
    return snmp

# snmp get memory info
# not used memory also can get from storage info
def memory_info():
    mem_oid = cf.get("%s.memory_info"%system, "oid")
    errorIndication, errorStatus, errorIndex, varBindTable = iterator(mem_oid)
    list_memory_info = get_info(errorIndication, errorStatus, errorIndex, varBindTable)
    test= disk_human(int(list_memory_info[1][0]))
    return test

# snmp get disk info and memory info
def storage_info():
    hrStorageType = []
    list_storageType = []
    oid_storageType = cf.get("%s.storage_info"%system, "oid_storageType")
    errorIndication, errorStatus, errorIndex, varBindTable = iterator(oid_storageType)
    oid_storageType = get_info(errorIndication, errorStatus, errorIndex, varBindTable)
    '''
    disk_info_list = oid_storageType[1]
    for i in xrange(oid_storageType[0].__len__()):
        if 'iso' in oid_storageType[1][i]:
            print oid_storageType.replace('iso','1')
        list_storageType.append(cf.get("%s.storage_info"%system, oid_storageType[1][i]))
    print list_storageType
    '''
    oid_storageDescr = cf.get("%s.storage_info"%system, "oid_storageDescr")
    errorIndication, errorStatus, errorIndex, varBindTable = iterator(oid_storageDescr)
    list_storageDescr = get_info(errorIndication, errorStatus, errorIndex, varBindTable)

    oid_storageUnits = cf.get("%s.storage_info"%system, "oid_storageUnits")  #Bytes
    errorIndication, errorStatus, errorIndex, varBindTable = iterator(oid_storageUnits)
    list_storageUnits = get_info(errorIndication, errorStatus, errorIndex, varBindTable)

    oid_storageSize = cf.get("%s.storage_info"%system, "oid_storageSize")
    errorIndication, errorStatus, errorIndex, varBindTable = iterator(oid_storageSize)
    list_storageSize = get_info(errorIndication, errorStatus, errorIndex, varBindTable)

    oid_storageUsed = cf.get("%s.storage_info"%system, "oid_storageUsed")
    errorIndication, errorStatus, errorIndex, varBindTable = iterator(oid_storageUsed)
    list_storageUsed = get_info(errorIndication, errorStatus, errorIndex, varBindTable)
    # oid_storageFailures = cf.get("%s.storage_info"%system, "oid_storageFailures")
    # errorIndication, errorStatus, errorIndex, varBindTable = iterator(oid_storageFailures)
    # list_storageFailures = get_info(errorIndication, errorStatus, errorIndex, varBindTable)
    useful_disk_total = list_storageSize[1]
    useful_disk_used = list_storageUsed[1]
    useful_disk_units = list_storageUnits[1]

    #disk_total
    disk_total_list = map(lambda(x,y):int(x)*int(y), zip(useful_disk_total,useful_disk_units))
    disk_total_human_list = []
    for disk_total in disk_total_list:
        disk_total_human_list.append(disk_human(disk_total))

    #dist_used
    disk_used_list = map(lambda(x,y):int(x)*int(y),zip(useful_disk_used,useful_disk_units))
    disk_used_human_list = []
    for disk_used in disk_used_list:
        disk_used_human_list.append(disk_human(disk_used))

    disk_utilization_list = map(lambda(x,y):round(float(x)/float(y),2) if int(y)!= 0 else 0, zip(useful_disk_used,useful_disk_total))

    for i  in  xrange(list_storageDescr[1].__len__()):
        if 'emory' in list_storageDescr[1][i] or 'Swap' in list_storageDescr[1][i]:
            snmp["memory"].append({"total":disk_total_list[i],"used":disk_used_list[i],
                              "label": list_storageDescr[1][i],  "usage":disk_utilization_list[i]})
        else:
            snmp["disk"].append({"total": disk_total_list[i], "used": disk_used_list[i],
                               "label":  list_storageDescr[1][i]  ,"usage": disk_utilization_list[i]})

# snmp get nic inbyte or outbyte
def nic_info():
    oid_ifindex = cf.get("%s.nic_info"%system, "oid_ifindex")
    oid_ifindex = oid_ifindex+'.'+target_server
    errorIndication, errorStatus, errorIndex, varBindTable = iterator_get(oid_ifindex)
    ifindex = get_info(errorIndication, errorStatus, errorIndex, varBindTable)
    # print ifindex[1][0]
    oid_ifInOctets = cf.get("%s.nic_info"%system, "oid_ifInOctets")
    oid_ifInOctets = oid_ifInOctets+'.'+ifindex[1][0]
    oid_ifOutOctets= cf.get("%s.nic_info"%system, "oid_ifOutOctets")
    oid_ifOutOctets = oid_ifOutOctets+'.'+ifindex[1][0]
    #inbyte
    errorIndication, errorStatus, errorIndex, varBindTable = iterator_get(oid_ifInOctets)
    ifInOctets = int(get_info(errorIndication, errorStatus, errorIndex, varBindTable)[1][0])  #Byte
    #outbyte
    errorIndication, errorStatus, errorIndex, varBindTable = iterator_get(oid_ifOutOctets)
    ifOutOctets = int(get_info(errorIndication, errorStatus, errorIndex, varBindTable)[1][0])
    snmp["nic"]["inbyte"] = ifInOctets
    snmp["nic"]["outbyte"] =ifOutOctets
    return snmp


community = cf.get('community','community')
service_list = eval(cf.get('service','service_list'))
# print target_server

es_data ={}
es_data["tags"], es_data["appname"], es_data["snmp"] = {}, 'snmp', ''
es_data["topic"], es_data["guid"], es_data["type"]  =  "snmp", "internal", "snmp"


if __name__ =='__main__':
    es_list= 0
    es = Elasticsearch("ip")
    esindex_prefix = "test"
    esindex = "%s-%s" % (esindex_prefix, time.strftime('%Y.%m.%d'))
    values = []
    while True:
        for target_server in service_list:
            snmp = {}
            snmp["system"], snmp["cpu"], snmp["disk"], snmp["memory"], snmp["nic"]= {}, {}, [], [], {}
            system = init_system()
            if system:
                snmp["ipaddr"] = target_server
                snmp["system"]["os"]=system
                system_info()
                cpu_info()
                storage_info()
                nic_info()
                es_data["snmp"]=snmp
                es_data["dawn_ts"] = time.time() * 1000000
                es_data["@timestamp"] = time.strftime('%Y-%m-%dT%H:%M:%S+08:00')
                es_data_deepcopy = copy.deepcopy(es_data)
                values.append({
                    "_index": esindex,
                    "_type": 'snmp',
                    "_source": es_data_deepcopy
                })
                if len(values) >= 50:
                    helpers.bulk(es, values)
                    print 'bulking to es'
                    values = []
                    threshold = 0


