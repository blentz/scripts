#!/usr/bin/python

import sys, os
from zabbix_api import ZabbixAPI

from argparse import ArgumentParser

debug_flag = False
progname = os.path.basename(sys.argv[0])

def error(msg) :
    sys.stderr.write('%s:%s\n' % (progname, msg))
    sys.exit(255)

def debug(msg) :
    if debug_flag :
        sys.stderr.write('%s:DEBUG:%s\n' % (progname, msg))

parser = ArgumentParser(description = 'Create Zabbix Screen with specified criteria')
parser.add_argument('--url', dest = 'url', default = 'http://localhost/zabbix', help = 'Zabbix server address')
parser.add_argument('-u', '--user', dest = 'user', default = 'admin', help = 'Zabbix user')
parser.add_argument('-p', '--password', dest = 'password', default = '', help = 'Zabbix password')

parser.add_argument('-S', '--screen', dest = 'screen', required = True, help = 'Screen name')
parser.add_argument('-U', '--update', dest = 'update', default = False, action = 'store_true', help = 'Screen name')

# if None, calculate from found items
parser.add_argument('-H', dest = 'hsize', type = int, default = 2, help = 'Horizontal size of screen')

parser.add_argument('--host', dest = 'host', default = None, help = '(Part of) Host to search for (either host or group must be spcified)')
parser.add_argument('--group', dest = 'group', default = None, help = 'Group name to search for (either host or group must be spcified)')
parser.add_argument('--graph', dest = 'graph', required = True, help = '(Part of) Graph name to search for')

args = parser.parse_args()

zapi = ZabbixAPI(server = args.url, path = "", log_level = 0)
zapi.login(args.user, args.password)

# Check if the screen is already exists

screen = zapi.screen.get({'filter': {"name":args.screen}, 'selectScreenItems':'extend', 'output':'extend'})

debug('screen_result = %s' % (screen))


if screen and not args.update :
    error('Screen already exists')

if screen :
    screen = screen[0]

# Search for item and add to the screen
host_list = []
if args.host :
    for host in zapi.host.get({'search':{'name':args.host}}) :
        host_list.append(host['hostid'])
elif args.group :
    result = zapi.hostgroup.get({'filter':{'name': args.group}, 'output':'extend', 'selectHosts': 'extend'})
    host_map = {}
    for r in result :
        for host in r['hosts'] :
            host_map[host['hostid']] = host['hostid']
    host_list = host_map.values()

debug('Host matches criteria = %s' % str(host_list))

# Look for graph item

if host_list :
    result = zapi.graph.get({'hostids':host_list, 'search':{'name':args.graph}, 'output':'extend'})
else :
    result = zapi.graph.get({'search':{'name':args.graph}, 'output':'extend'})

# Screen creation
hsize = args.hsize

if screen and int(screen['hsize']) != int(hsize) :
    error("Couldn't update screen, existing screen hsize = %s, request screen hsize = %s" % (screen['hsize'], hsize))

# calculate vsize
num_item = len(result)
if screen and screen['screenitems'] :
    num_item += len(screen['screenitems'])
vsize = num_item / hsize
if num_item % hsize != 0 :
    vsize += 1

debug('calculated hsize = %d, vsize = %d' % (hsize, vsize))

hpos = 0
vpos = 0
if screen :
    for i in screen['screenitems'] :
        if hpos < int(i['x']) :
            hpos = int(i['x'])
        if vpos < int(i['y']) : 
            vpos = int(i['y'])

    if hpos >= (hsize - 1) :
        hpos = 0
        vpos += 1

screen_items = []

for graph in result :
    data = {'colspan': 1,
         'rowspan': 1,
         'resourcetype': 0,
         'resourceid': graph['graphid'],
         'x': hpos,
         'y': vpos,
         'width': 500,
         'height': 100,
        }
    if screen :
        data['screenid'] = screen['screenid']
    screen_items.append(data)
    hpos += 1
    if hpos >= hsize :
        hpos = 0
        vpos += 1

if debug_flag :
    for i in screen_items :
        debug('item = %s' % i)

if screen :
    zapi.screen.update({'screenid': screen['screenid'], 'hsize': hsize, 'vsize': vsize})
    for i in screen_items :
        zapi.screenitem.create(i)

else :
    # Create the screen
    # need to know number of item first
    screen_creation_result = zapi.screen.create({'name': args.screen, 'hsize': hsize, 'vsize':vsize, 'screenitems': screen_items})

    debug('Screen creation result = %s' % screen_creation_result)

