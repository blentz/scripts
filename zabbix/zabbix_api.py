
# This is a port of the ruby zabbix api found here:
# http://trac.red-tux.net/browser/ruby/api/zbx_api.rb
#
#LGPL 2.1   http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html
#Zabbix API Python Library.
#Original Ruby Library is Copyright (C) 2009 Andrew Nelson nelsonab(at)pobox(removethisword)(dot)com
#Python Library is Copyright (C) 2009 Brett Lentz brett.lentz(at)gmail(dot)com
#
#This library is free software; you can redistribute it and/or
#modify it under the terms of the GNU Lesser General Public
#License as published by the Free Software Foundation; either
#version 2.1 of the License, or (at your option) any later version.
#
#This library is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#Lesser General Public License for more details.
#
#You should have received a copy of the GNU Lesser General Public
#License along with this library; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA


# NOTES:
# The API requires zabbix 1.8 or later.
# Currently, not all of the API is implemented, and some functionality is
# broken. This is a work in progress.

import httplib
try:
	# Python 2.5
	import json
except ImportError:
	# Python 2.4
	import simplejson as json

import sys

class ZabbixAPIException(Exception):
    """ generic zabbix api exception """
    pass

class zabbix_api(object):
    __username__ = ''
    __password__ = ''

    auth = ''
    id = 0
    url = '/zabbix/api_jsonrpc.php'
    server = "localhost"
    debug_level = 0
    params = None
    method = None

    # sub-class instances.
    user = None
    usergroup = None
    host = None
    item = None
    hostgroup = None
    application = None
    trigger = None
    sysmap = None
    template = None

    def __init__(self, **kwargs):
        if 'server' in kwargs:
            self.server = kwargs['server']

        if 'url' in kwargs:
            self.url = kwargs['url']

        if 'debug_level' in kwargs:
            self.debug_level = kwargs['debug_level']

        self.user = zabbix_api_user(self)
        self.usergroup = zabbix_api_usergroup(self)
        self.host = zabbix_api_host(self)
        self.item = zabbix_api_item(self)
        self.hostgroup = zabbix_api_hostgroup(self)
        self.application = zabbix_api_application(self)
        self.trigger = zabbix_api_trigger(self)
        self.sysmap = zabbix_api_sysmap(self)
        self.template = zabbix_api_template(self)

        self.id = 0

        self.debug(6, "url: " + "http://" + self.server + self.url)

    def debug(self, level, var="", msg=None):
        if level <= self.debug_level:
            strval = "DEBUG(" + str(level) + ") "

            if msg:
                strval = strval + str(msg)

            if var != "":
                strval = strval + ": " + str(var)

            sys.stderr.write(strval + "\n")

    def json_obj(self, method, params={}):
        obj = { 'jsonrpc' : '2.0',
                'method'  : method,
                'params'  : params,
                'auth'    : self.auth,
                'id'      : self.id
              }

        self.debug(10, "json_obj: " + str(obj))

        return json.dumps(obj)

    def login(self, user='', password='', save=True):
        if user != '':
            l_user = user
            l_password = password

            if save:
                self.__username__ = user
                self.__password__ = password
        elif self.__username__ != '':
            l_user = self.__username__
            l_password = self.__password__
        else:
            raise ZabbixAPIException("No authentication information available.")

        obj = self.json_obj('user.authenticate', { 'user' : l_user,
                'password' : l_password })
        result = self.do_request(obj)
        self.auth = result['result']

    def test_login(self):
        if self.auth != '':
            obj = self.json_obj('user.checkauth', {'sessionid' : self.auth})
            result = self.do_request(obj)

            if not result['result']:
                self.auth = ''
                return False # auth hash bad
            return True # auth hash good
        else:
            return False

    def do_request(self, json_obj):
        headers = { 'Content-Type' : 'application/json-rpc',
                    'User-Agent' : 'python/zabbix_api' }
        conn = httplib.HTTPConnection(self.server)

        self.debug(8, "Sending: " + str(json_obj))
        self.debug(10, "Sending headers: " + str(headers))
        conn.request("POST", self.url, json_obj, headers)

        response = conn.getresponse()
        self.debug(8, "Response Code: " + str(response.status) + " " + \
                response.reason)

        # NOTE: Getting a 412 response code means the headers are not in the
        # list of allowed headers.
        if response.status != 200:
            raise ZabbixAPIException("HTTP ERROR %s: %s"
                    % (response.status, response.reason))

        jobj = json.loads(response.read())
        self.debug(10, "Response Body: " + str(jobj))

        self.id += 1

        if 'error' in jobj:
            msg = "Error %s: %s, %s" % (jobj['error']['code'],
                    jobj['error']['message'], jobj['error']['data'])
            raise ZabbixAPIException(msg)
        return jobj

    def logged_in(self):
        if self.auth != '':
            return True
        return False

    def api_version(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('APIInfo.version', options))
        return obj['result']

    def __checkauth__(self):
        if not self.logged_in():
            raise ZabbixAPIException("Not logged in.")

class zabbix_api_subclass(zabbix_api):
    """ wrapper class to ensure all calls go through the parent object """
    parent = None

    def __init__(self, parent):
        self.parent = parent

    def __checkauth__(self):
        self.parent.__checkauth__()

    def do_request(self, req):
        return self.parent.do_request(req)

    def json_obj(self, method, param):
        return self.parent.json_obj(method, param)

    def debug(self, level, param="", msg=None):
        self.parent.debug(level, param, msg)

class zabbix_api_user(zabbix_api_subclass):
    def get(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('user.get', options))
        return obj['result']

    def getbyid(self, userid):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('user.getbyid', {'userid' : userid}))
        return obj['result']

    def getid(self, username):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('user.getid', {'alias' : username}))
        return obj['result']

    def add(self, options):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('user.add', options))
        return obj['result']

    def delete(self, userid):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('user.delete', {'userid' : userid}))
        return obj['result']

    def update(self, options):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('user.update', options))
        return obj['result']

class zabbix_api_host(zabbix_api_subclass):
    def get(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('host.get', options))
        return obj['result']

    def getbyid(self, hostid):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('host.getById', {'hostid' : hostid}))
        return obj['result']

    def add(self, options):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('host.add', options))
        return obj['result']

    def update(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('host.update', options))
        return obj['result']

class zabbix_api_item(zabbix_api_subclass):
    def get(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('item.get', options))
        return obj['result']

    def getbyid(self, itemid):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('item.getbyid', {'itemid' : itemid}))
        return obj['result']

    def getid(self, options):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('item.getid', options))
        return obj['result']

    def add(self, options):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('item.add', options))
        return obj['result']

    def delete(self, ids):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('item.delete', ids))
        return obj['result']

class zabbix_api_usergroup(zabbix_api_subclass):
    def get(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('item.get', options))
        return obj['result']

class zabbix_api_hostgroup(zabbix_api_subclass):
    def get(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('hostgroup.get', options))
        return obj['result']

    def getid(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('hostgroup.getid', options))
        return obj['result']

    def add(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('hostgroup.add', options))
        return obj['result']

class zabbix_api_application(zabbix_api_subclass):
    def get(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('application.get', options))
        return obj['result']

    def getid(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('application.getid', options))
        return obj['result']

    def add(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('application.add', options))
        return obj['result']

class zabbix_api_trigger(zabbix_api_subclass):
    def get(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('trigger.get', options))
        return obj['result']

    def add(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('trigger.add', options))
        return obj['result']

class zabbix_api_sysmap(zabbix_api_subclass):
    def add(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('map.add', options))
        return obj['result']

    def add_element(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('map.addelement', options))
        return obj['result']

    def add_link(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('map.addlink', options))
        return obj['result']

    def add_link_trigger(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('map.addlinktrigger', options))
        return obj['result']

    def getseid(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('map.getseid', options))
        return obj['result']

class zabbix_api_template(zabbix_api_subclass):
    def get(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('template.get', options))
        return obj['result']

    def getObjects(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('template.getObjects', options))
        return obj['result']

    def massAdd(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('temaplte.massAdd', options))
        return obj['result']

    def massRemove(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('template.massRemove', options))
        return obj['result']

    def add(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('template.add', options))
        return obj['result']

    def update(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('template.update', options))
        return obj['result']

    def delete(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('template.delete', options))
        return obj['result']

    def linkHosts(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('template.linkHosts', options))
        return obj['result']

    def unlinkHosts(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('template.unlinkHosts', options))
        return obj['result']

    def linkTemplates(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('template.linkTemplates', options))
        return obj['result']

    def unlinkTemplates(self, options={}):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('template.unlinkTemplates', options))
        return obj['result']





