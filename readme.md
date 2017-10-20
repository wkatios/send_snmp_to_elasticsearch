#snmp 获取相关信息存入elasticsearch

## 配置文件conf.ini

需要修改的是community的作为通信的“key”

service_list是需要取得信息

## 代码
init_system 获取系统os，针对不同的系统采取不同的oid

iterator  snmp walk 方式获取信息，简单的说，返回的是一个list

iterator_get snmp get 方式获取信息，返回的是一个单一的对象

get_info 对snmp 结果的异常判断，正常取值时，则返回key和value的list

time\_coversion 和 disk_human 函数作为时间和磁盘的单位转换函数

system_info 获取系统名称，启动时间等

memory_info  获取系统内存信息，目前没有到，可以从storage中计算得到

storage_info 获取硬盘和内存信息

nic_info  获取网卡流量信息

## TODO

1.多个机器节点可改进为多线程的方式


2.对windows和linux的支持，对于不同型号的交换机，路由器等需要适配oid