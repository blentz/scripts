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
import urllib2
import base64
import string
import sys
import logging

#logging.config.fileConfig('/tmp/logging.conf')
logger = logging.getLogger("zabbix_api")
log=logger.log
log(10,"Starting logging")

try:
    # Python 2.5+
    import json
    log(15,"Using native json library")
except ImportError:
    # Python 2.4
    import simplejson as json
    log(15,"Using simplejson library")

class ZabbixAPIException(Exception):
    """ generic zabbix api exception """
    pass

class InvalidProtoError(ZabbixAPIException):
    """ Recived an invalid proto """
    pass

class ZabbixAPI(object):
    __username__ = ''
    __password__ = ''

    auth = ''
    id = 0
    url = '/zabbix/api_jsonrpc.php'
    params = None
    method = None
    # HTTP or HTTPS
    proto = 'http'
    # HTTP authentication
    httpuser = None
    httppasswd = None

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

    def __init__(
                 self,
                 # Server to connect to
                 server='localhost',
                 # Path leading to the zabbix install
                 path='/zabbix/',
                 # Protocol to use. http or https
                 proto='http',
                 # HTTP auth username and password
                 user=None,
                 passwd=None,
                 # Data to pass to each api module 
                 **kwargs
                 ):
        """ Create an API object. 
    
        """
        self._setuplogging()
        
        self.server=server
        self.url=path+'/api_jsonrpc.php'
        self.proto=proto
        self.httpuser=user
        self.httppasswd=passwd 

        self.user = ZabbixAPIUser(self,**kwargs)
        self.usergroup = ZabbixAPIUserGroup(self,**kwargs)
        self.host = ZabbixAPIHost(self,**kwargs)
        self.item = ZabbixAPIItem(self,**kwargs)
        self.hostgroup = ZabbixAPIHostGroup(self,**kwargs)
        self.application = ZabbixAPIApplication(self,**kwargs)
        self.trigger = ZabbixAPITrigger(self,**kwargs)
        self.sysmap = ZabbixAPISysMap(self,**kwargs)
        self.template = ZabbixAPITemplate(self,**kwargs)
        self.action = ZabbixAPIAction(self,**kwargs)
        self.alert = ZabbixAPIAlert(self,**kwargs)
        self.info = ZabbixAPIInfo(self,**kwargs)
        self.event = ZabbixAPIEvent(self,**kwargs)
        self.graph = ZabbixAPIGraph(self,**kwargs)
        self.graphitem = ZabbixAPIGraphItem(self,**kwargs)
        self.map = ZabbixAPIMap(self,**kwargs)
        self.screen = ZabbixAPIScreen(self,**kwargs)
        self.script = ZabbixAPIScript(self,**kwargs)
        self.usermacro = ZabbixAPIUserMacro(self,**kwargs)
        self.map = ZabbixAPIMap(self,**kwargs)
        self.map = ZabbixAPIMap(self,**kwargs)
        
        self.id = 0

        self.debug(6, "url: " + proto+"://" + self.server + self.url)       

    def _setuplogging(self):
        self.logger=logging.getLogger("zabbix_api.%s"%self.__class__.__name__)
        
    def debug(self, level, var="", msg=None):
        strval = ""
        if msg:
            strval = strval + str(msg)
        if var != "":
            strval = strval + ": " + str(var)

        self.logger.log(level,strval)

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

        self.debug(10,"Trying to login with %s:%s"%(repr(l_user),repr(l_password)))
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
        
        if self.httpuser:
            self.debug(10,"HTTP Auth enabled")
            auth='Basic ' + string.strip(base64.encodestring(self.httpuser + ':' + self.httppasswd))
            headers['Authorization']=auth
        
        if self.proto=='http':
            conn = httplib.HTTPConnection(self.server)
        elif self.proto=='https':
            conn = httplib.HTTPSConnection(self.server)
        else:
            raise InvalidProtoError, "%s is not a valid protocol"%repr(self.proto)
        self.debug(10,"Connection object %s"%repr(conn))
        
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

    def api_version(self, **options):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('APIInfo.version', options))
        return obj['result']

    def __checkauth__(self):
        if not self.logged_in():
            raise ZabbixAPIException("Not logged in.")

class ZabbixAPISubClass(ZabbixAPI):
    """ wrapper class to ensure all calls go through the parent object """
    parent = None

    def __init__(self, parent, **kwargs):
        self._setuplogging()
        self.debug(10,"Creating %s"%self.__class__.__name__)
        
        self.parent = parent
        # Save any extra info passed in 
        for key,val in kwargs.items():
            setattr(self,key,val)
            self.debug(5,"Set %s:%s"%(repr(key),repr(val)))
        
    def __checkauth__(self):
        self.parent.__checkauth__()

    def do_request(self, req):
        return self.parent.do_request(req)

    def json_obj(self, method, param):
        return self.parent.json_obj(method, param)
        
def checkauth(fn):
    """ Decorator to check authentication of the decorated method """
    def ret(self,*args,**kwargs):
        self.__checkauth__()
        return fn(self,kwargs)
    return ret
    
def dojson(name):
    def decorator(fn):
        def wrapper(self,opts):
            log(5,"Going to do_request for %s with opts %s"%(repr(fn),repr(opts)))
            return self.do_request(self.json_obj(name,opts))['result']
        return wrapper
    return decorator
        
class ZabbixAPIUser(ZabbixAPISubClass):
    @checkauth
    @dojson('user.get')
    def get(self,**opts):
        """  * Get Users data
 *
 * First part of parameters are filters which limits the output result set, these filters are set only if appropriate parameter is set.
 * For example if "type" is set, then method returns only users of given type.
 * Second part of parameters extends result data, adding data about others objects that are related to objects we get.
 * For example if "select_usrgrps" parameter is set, resulting objects will have additional property 'usrgrps' containing object with
 * data about User UserGroups.
 * Third part of parameters affect output. For example "sortfield" will be set to 'alias', result will be sorted by User alias.
 * All Parameters are optional!
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['nodeids'] filter by Node IDs
 * @param array $options['usrgrpids'] filter by UserGroup IDs
 * @param array $options['userids'] filter by User IDs
 * @param boolean $options['type'] filter by User type [ USER_TYPE_ZABBIX_USER: 1, USER_TYPE_ZABBIX_ADMIN: 2, USER_TYPE_SUPER_ADMIN: 3 ]
 * @param boolean $options['select_usrgrps'] extend with UserGroups data for each User
 * @param boolean $options['get_access'] extend with access data for each User
 * @param boolean $options['extendoutput'] output only User IDs if not set.
 * @param boolean $options['count'] output only count of objects in result. ( result returned in property 'rowscount' )
 * @param string $options['pattern'] filter by Host name containing only give pattern
 * @param int $options['limit'] output will be limited to given number
 * @param string $options['sortfield'] output will be sorted by given property [ 'userid', 'alias' ]
 * @param string $options['sortorder'] output will be sorted in given order [ 'ASC', 'DESC' ]
 * @return array
        """
        return opts
    
    @checkauth
    @dojson('user.checkAuthentication')
    def checkAuthentication(self,**opts):
        """  * Check if session ID is authenticated
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $session
 * @param array $session['sessionid'] Session ID
 * @return boolean
 """
        return opts
    
    @checkauth
    @dojson('user.getObjects')
    def getObjects(self,**opts):
        """  * Get User ID by User alias
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $user_data
 * @param array $user_data['alias'] User alias
 * @return string|boolean """
        return opts
    
    @checkauth
    @dojson('user.add')
    def add(self,**opts):
        """  * Add Users
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $users multidimensional array with Users data
 * @param string $users['name']
 * @param string $users['surname']
 * @param array $users['alias']
 * @param string $users['passwd']
 * @param string $users['url']
 * @param int $users['autologin']
 * @param int $users['autologout']
 * @param string $users['lang']
 * @param string $users['theme']
 * @param int $users['refresh']
 * @param int $users['rows_per_page']
 * @param int $users['type']
 * @param array $users['user_medias']
 * @param string $users['user_medias']['mediatypeid']
 * @param string $users['user_medias']['address']
 * @param int $users['user_medias']['severity']
 * @param int $users['user_medias']['active']
 * @param string $users['user_medias']['period']
 * @return array|boolean
  """
        return opts
    
    @checkauth
    @dojson('user.update')
    def update(self,**opts):
        """  * Update Users
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $users multidimensional array with Users data
 * @param string $users['userid']
 * @param string $users['name']
 * @param string $users['surname']
 * @param array $users['alias']
 * @param string $users['passwd']
 * @param string $users['url']
 * @param int $users['autologin']
 * @param int $users['autologout']
 * @param string $users['lang']
 * @param string $users['theme']
 * @param int $users['refresh']
 * @param int $users['rows_per_page']
 * @param int $users['type']
 * @param array $users['user_medias']
 * @param string $users['user_medias']['mediatypeid']
 * @param string $users['user_medias']['address']
 * @param int $users['user_medias']['severity']
 * @param int $users['user_medias']['active']
 * @param string $users['user_medias']['period']
 * @return boolean """
        return opts
    
    @checkauth
    @dojson('user.updateProfile')
    def updateProfile(self,**opts):
        """  * Update Users
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $users multidimensional array with Users data
 * @param string $users['userid']
 * @param string $users['name']
 * @param string $users['surname']
 * @param array $users['alias']
 * @param string $users['passwd']
 * @param string $users['url']
 * @param int $users['autologin']
 * @param int $users['autologout']
 * @param string $users['lang']
 * @param string $users['theme']
 * @param int $users['refresh']
 * @param int $users['rows_per_page']
 * @param int $users['type']
 * @param array $users['user_medias']
 * @param string $users['user_medias']['mediatypeid']
 * @param string $users['user_medias']['address']
 * @param int $users['user_medias']['severity']
 * @param int $users['user_medias']['active']
 * @param string $users['user_medias']['period']
 * @return boolean """
        return opts
    
    @checkauth
    @dojson('user.delete')
    def delete(self,**opts):
        """  * Delete Users
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $users
 * @param array $users[0,...]['userids']
 * @return boolean 
 """
        return opts
    
    @checkauth
    @dojson('user.addMedia')
    def addMedia(self,**opts):
        """  * Add Medias for User
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $media_data
 * @param string $media_data['userid']
 * @param string $media_data['medias']['mediatypeid']
 * @param string $media_data['medias']['address']
 * @param int $media_data['medias']['severity']
 * @param int $media_data['medias']['active']
 * @param string $media_data['medias']['period']
 * @return boolean
  """
        return opts
    
    @checkauth
    @dojson('user.deleteMedia')
    def deleteMedia(self,**opts):
        """  * Delete User Medias
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $medias
 * @param array $medias[...][mediaid]
 * @return boolean
  """
        return opts
    
    @checkauth
    @dojson('user.updateMedia')
    def updateMedia(self,**opts):
        """  * Update Medias for User
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $media_data
 * @param array $media_data['users']
 * @param array $media_data['users']['userid']
 * @param array $media_data['medias']
 * @param string $media_data['medias']['mediatypeid']
 * @param string $media_data['medias']['sendto']
 * @param int $media_data['medias']['severity']
 * @param int $media_data['medias']['active']
 * @param string $media_data['medias']['period']
 * @return boolean
  """
        return opts

class ZabbixAPIHost(ZabbixAPISubClass):
    
    @checkauth
    @dojson('host.get')
    def get(self,**opts):
        """  * Get Host data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['nodeids'] Node IDs
 * @param array $options['groupids'] HostGroup IDs
 * @param array $options['hostids'] Host IDs
 * @param boolean $options['monitored_hosts'] only monitored Hosts
 * @param boolean $options['templated_hosts'] include templates in result
 * @param boolean $options['with_items'] only with items
 * @param boolean $options['with_monitored_items'] only with monitored items
 * @param boolean $options['with_historical_items'] only with historical items
 * @param boolean $options['with_triggers'] only with triggers
 * @param boolean $options['with_monitored_triggers'] only with monitored triggers
 * @param boolean $options['with_httptests'] only with http tests
 * @param boolean $options['with_monitored_httptests'] only with monitored http tests
 * @param boolean $options['with_graphs'] only with graphs
 * @param boolean $options['editable'] only with read-write permission. Ignored for SuperAdmins
 * @param int $options['extendoutput'] return all fields for Hosts
 * @param boolean $options['select_groups'] select HostGroups
 * @param boolean $options['select_templates'] select Templates
 * @param boolean $options['select_items'] select Items
 * @param boolean $options['select_triggers'] select Triggers
 * @param boolean $options['select_graphs'] select Graphs
 * @param boolean $options['select_applications'] select Applications
 * @param boolean $options['select_macros'] select Macros
 * @param boolean $options['select_profile'] select Profile
 * @param int $options['count'] count Hosts, returned column name is rowscount
 * @param string $options['pattern'] search hosts by pattern in Host name
 * @param string $options['extend_pattern'] search hosts by pattern in Host name, ip and DNS
 * @param int $options['limit'] limit selection
 * @param string $options['sortfield'] field to sort by
 * @param string $options['sortorder'] sort order
 * @return array|boolean Host data as array or false if error
 """
        return opts
    
    @checkauth
    @dojson('host.getObjects')
    def getObjects(self,**opts):
        """  * Get Host ID by Host name
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $host_data
 * @param string $host_data['host']
 * @return int|boolean
  """
        return opts
    
    @checkauth
    @dojson('host.create')
    def create(self,**opts):
        """  * Add Host
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $hosts multidimensional array with Hosts data
 * @param string $hosts['host'] Host name.
 * @param array $hosts['groups'] array of HostGroup objects with IDs add Host to.
 * @param int $hosts['port'] Port. OPTIONAL
 * @param int $hosts['status'] Host Status. OPTIONAL
 * @param int $hosts['useip'] Use IP. OPTIONAL
 * @param string $hosts['dns'] DNS. OPTIONAL
 * @param string $hosts['ip'] IP. OPTIONAL
 * @param int $hosts['proxy_hostid'] Proxy Host ID. OPTIONAL
 * @param int $hosts['useipmi'] Use IPMI. OPTIONAL
 * @param string $hosts['ipmi_ip'] IPMAI IP. OPTIONAL
 * @param int $hosts['ipmi_port'] IPMI port. OPTIONAL
 * @param int $hosts['ipmi_authtype'] IPMI authentication type. OPTIONAL
 * @param int $hosts['ipmi_privilege'] IPMI privilege. OPTIONAL
 * @param string $hosts['ipmi_username'] IPMI username. OPTIONAL
 * @param string $hosts['ipmi_password'] IPMI password. OPTIONAL
 * @return boolean
  """
        return opts
    
    @checkauth
    @dojson('host.update')
    def update(self,**opts):
        """  * Update Host
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $hosts multidimensional array with Hosts data
 * @param string $hosts['host'] Host name.
 * @param int $hosts['port'] Port. OPTIONAL
 * @param int $hosts['status'] Host Status. OPTIONAL
 * @param int $hosts['useip'] Use IP. OPTIONAL
 * @param string $hosts['dns'] DNS. OPTIONAL
 * @param string $hosts['ip'] IP. OPTIONAL
 * @param int $hosts['proxy_hostid'] Proxy Host ID. OPTIONAL
 * @param int $hosts['useipmi'] Use IPMI. OPTIONAL
 * @param string $hosts['ipmi_ip'] IPMAI IP. OPTIONAL
 * @param int $hosts['ipmi_port'] IPMI port. OPTIONAL
 * @param int $hosts['ipmi_authtype'] IPMI authentication type. OPTIONAL
 * @param int $hosts['ipmi_privilege'] IPMI privilege. OPTIONAL
 * @param string $hosts['ipmi_username'] IPMI username. OPTIONAL
 * @param string $hosts['ipmi_password'] IPMI password. OPTIONAL
 * @param string $hosts['groups'] groups
 * @return boolean
  """
        return opts
    
    @checkauth
    @dojson('host.massUpdate')
    def massUpdate(self,**opts):
        """  * Mass update hosts
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $hosts multidimensional array with Hosts data
 * @param array $hosts['hosts'] Array of Host objects to update
 * @param string $hosts['fields']['host'] Host name.
 * @param array $hosts['fields']['groupids'] HostGroup IDs add Host to.
 * @param int $hosts['fields']['port'] Port. OPTIONAL
 * @param int $hosts['fields']['status'] Host Status. OPTIONAL
 * @param int $hosts['fields']['useip'] Use IP. OPTIONAL
 * @param string $hosts['fields']['dns'] DNS. OPTIONAL
 * @param string $hosts['fields']['ip'] IP. OPTIONAL
 * @param int $hosts['fields']['proxy_hostid'] Proxy Host ID. OPTIONAL
 * @param int $hosts['fields']['useipmi'] Use IPMI. OPTIONAL
 * @param string $hosts['fields']['ipmi_ip'] IPMAI IP. OPTIONAL
 * @param int $hosts['fields']['ipmi_port'] IPMI port. OPTIONAL
 * @param int $hosts['fields']['ipmi_authtype'] IPMI authentication type. OPTIONAL
 * @param int $hosts['fields']['ipmi_privilege'] IPMI privilege. OPTIONAL
 * @param string $hosts['fields']['ipmi_username'] IPMI username. OPTIONAL
 * @param string $hosts['fields']['ipmi_password'] IPMI password. OPTIONAL
 * @return boolean
  """
        return opts
    
    @checkauth
    @dojson('host.massAdd')
    def massAdd(self,**opts):
        """  * Add Hosts to HostGroups. All Hosts are added to all HostGroups.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $data
 * @param array $data['groups']
 * @param array $data['hosts']
 * @return boolean
  """
        return opts
    
    @checkauth
    @dojson('host.massRemove')
    def massRemove(self,**opts):
        """  * remove Hosts to HostGroups. All Hosts are added to all HostGroups.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $data
 * @param array $data['groups']
 * @param array $data['hosts']
 * @return boolean
  """
        return opts
    
    @checkauth
    @dojson('host.delete')
    def delete(self,**opts):
        """  * Delete Host
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $hosts
 * @param array $hosts[0, ...]['hostid'] Host ID to delete
 * @return array|boolean
  """
        return opts
    
class ZabbixAPIItem(ZabbixAPISubClass):
    @checkauth
    @dojson('item.get')
    def get(self,**opts):
        """  * Get items data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $options
 * @param array $options['itemids']
 * @param array $options['hostids']
 * @param array $options['groupids']
 * @param array $options['triggerids']
 * @param array $options['applicationids']
 * @param boolean $options['status']
 * @param boolean $options['templated_items']
 * @param boolean $options['editable']
 * @param boolean $options['count']
 * @param string $options['pattern']
 * @param int $options['limit']
 * @param string $options['order']
 * @return array|int item data as array or false if error
"""
        return opts
    
    @checkauth
    @dojson('item.getObjects')
    def getObjects(self,**opts):
        """      * Get itemid by host.name and item.key
     *
     * {@source}
     * @access public
     * @static
     * @since 1.8
     * @version 1
     *
     * @param array $item_data
     * @param array $item_data['key_']
     * @param array $item_data['hostid']
     * @return int|boolean
"""
        return opts
    
    @checkauth
    @dojson('item.add')
    def add(self,**opts):
        """      * Add item
     *
     * {@source}
     * @access public
     * @static
     * @since 1.8
     * @version 1
     *
     * Input array $items has following structure and default values :
     * <code>
     * array( array(
     * *'description'            => *,
     * *'key_'                => *,
     * *'hostid'                => *,
     * 'delay'                => 60,
     * 'history'                => 7,
     * 'status'                => ITEM_STATUS_ACTIVE,
     * 'type'                => ITEM_TYPE_ZABBIX,
     * 'snmp_community'            => '',
     * 'snmp_oid'                => '',
     * 'value_type'                => ITEM_VALUE_TYPE_STR,
     * 'data_type'                => ITEM_DATA_TYPE_DECIMAL,
     * 'trapper_hosts'            => 'localhost',
     * 'snmp_port'                => 161,
     * 'units'                => '',
     * 'multiplier'                => 0,
     * 'delta'                => 0,
     * 'snmpv3_securityname'        => '',
     * 'snmpv3_securitylevel'        => 0,
     * 'snmpv3_authpassphrase'        => '',
     * 'snmpv3_privpassphrase'        => '',
     * 'formula'                => 0,
     * 'trends'                => 365,
     * 'logtimefmt'                => '',
     * 'valuemapid'                => 0,
     * 'delay_flex'                => '',
     * 'params'                => '',
     * 'ipmi_sensor'            => '',
     * 'applications'            => array(),
     * 'templateid'                => 0
     * ), ...);
     * </code>
     *
     * @param array $items multidimensional array with items data
     * @return array|boolean
"""
        return opts
    
    @checkauth
    @dojson('item.update')
    def update(self,**opts):
        """  * Update item
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $items multidimensional array with items data
 * @return boolean
"""
        return opts
    
    @checkauth
    @dojson('item.delete')
    def delete(self,**opts):
        """  * Delete items
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $items multidimensional array with item objects
 * @param array $items[0,...]['itemid']
 * @return deleted items
"""
        return opts
    
class ZabbixAPIUserGroup(ZabbixAPISubClass):
    
    @checkauth
    @dojson('usergroup.get')
    def get(self,**opts):
        """  * Get UserGroups
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['nodeids'] Node IDs
 * @param array $options['usrgrpids'] UserGroup IDs
 * @param array $options['userids'] User IDs
 * @param boolean $options['status']
 * @param boolean $options['with_gui_access']
 * @param boolean $options['with_api_access']
 * @param boolean $options['select_users']
 * @param int $options['extendoutput']
 * @param int $options['count']
 * @param string $options['pattern']
 * @param int $options['limit'] limit selection
 * @param string $options['order']
 * @return array
"""
        return opts
    
    @checkauth
    @dojson('usergroup.getObjects')
    def getObjects(self,**opts):
        """  * Get UserGroup ID by UserGroup name.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * <code>
 * $group_data = array(
 *     *string 'name' => 'UserGroup name'
 * );
 * </code>
 *
 * @param array $group_data
 * @return string|boolean
"""
        return opts
    
    @checkauth
    @dojson('usergroup.add')
    def add(self,**opts):
        """  * Create UserGroups.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * <code>
 * $groups = array( array(
 *     *string 'name'                 => null,
 *     string 'users_status'         => GROUP_STATUS_DISABLED,
 *     string 'gui_access'         => 0,
 *     string 'api_access'         => 0
 * ));
 * </code>
 *
 * @param array $groups multidimensional array with UserGroups data
 * @return boolean
"""
        return opts
    
    @checkauth
    @dojson('usergroup.update')
    def update(self,**opts):
        """  * Update UserGroups.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $groups multidimensional array with UserGroups data
 * @return boolean
"""
        return opts
    
    @checkauth
    @dojson('usergroup.updateRights')
    def updateRights(self,**opts):
        """  * Update UserGroup rights to HostGroups.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * <code>
 * $rights = array(
 *     *string 'groupid' => 'UserGroup ID',
 *     array 'rights' => array( array('id' => 'HostGroup ID', 'permission' => 'permission'), ..)
 * )
 * </code>
 *
 * @param array $rights multidimensional array with rights data
 * @return boolean
"""
        return opts
    
    @checkauth
    @dojson('usergroup.addRights')
    def addRights(self,**opts):
        """  * Add rights for UserGroup to HostGroups. Existing rights are updated, new ones added.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * <code>
 * $rights = array(
 *     *string 'groupid' => 'UserGroup ID',
 *     array 'rights' => array( array('id' => 'HostGroup ID', 'permission' => 'permission'), ..)
 * )
 * </code>
 *
 * @param array $rights multidimensional array with rights data
 * @return boolean
"""
        return opts
    
    @checkauth
    @dojson('usergroup.updateUsers')
    def updateUsers(self,**opts):
        """  * Add Users to UserGroup.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * <code>
 *     @param $usrgrps[0,...]['usrgrpids']
 *     @param $users[0,...]['userids']
 * </code>
 *
 * @param array $data
 * @return boolean
"""
        return opts
    
    @checkauth
    @dojson('usergroup.removeUsers')
    def removeUsers(self,**opts):
        """  * Remove users from UserGroup.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param $usrgrps[0,...]['usrgrps']
 * @param $users[0,...]['users']
 *
 * @param array $data
 * @return boolean
"""
        return opts
    
    @checkauth
    @dojson('usergroup.delete')
    def delete(self,**opts):
        """  * Delete UserGroups.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $groupids
 * @param array $groupids['usrgrpids']
 * @return boolean
"""

class ZabbixAPIHostGroup(ZabbixAPISubClass):

    @checkauth
    @dojson('hostgroup.get')
    def get(self,**opts):
        """  * Get HostGroups
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $params
 * @return array
"""

    @checkauth
    @dojson('hostgroup.getObjects')
    def getObjects(self,**opts):
        """  * Get HostGroup ID by name
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $data
 * @param array $data['name']
 * @return string|boolean HostGroup ID or false if error
"""
        return opts  
    
    @checkauth
    @dojson('hostgroup.create')
    def create(self,**opts):
        """  * Add HostGroups
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $groups array with HostGroup names
 * @param array $groups['name']
 * @return array
"""

    @checkauth
    @dojson('hostgroup.update')
    def update(self,**opts):
        """  * Update HostGroup
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $groups
 * @param array $groups[0]['name'], ...
 * @param array $groups[0]['groupid'], ...
 * @return boolean
"""
        return opts 
         
    @checkauth
    @dojson('hostgroup.delete')
    def delete(self,**opts):
        """  * Delete HostGroups
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $groups
 * @param array $groups[0,..]['groupid']
 * @return boolean
"""

    @checkauth
    @dojson('hostgroup.massAdd')
    def massAdd(self,**opts):
        """  * Add Hosts to HostGroups. All Hosts are added to all HostGroups.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $data
 * @param array $data['groups']
 * @param array $data['hosts']
 * @param array $data['templates']
 * @return boolean
"""
        return opts 
         
    @checkauth
    @dojson('hostgroup.massRemove')
    def massRemove(self,**opts):
        """  * Remove Hosts from HostGroups
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $data
 * @param array $data['groups']
 * @param array $data['hosts']
 * @param array $data['templates']
 * @return boolean
"""

    @checkauth
    @dojson('hostgroup.massUpdate')
    def massUpdate(self,**opts):
        """  * Update HostGroups with new Hosts (rewrite)
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $data
 * @param array $data['groups']
 * @param array $data['hosts']
 * @param array $data['templates']
 * @return boolean
"""
        return opts 
     
class ZabbixAPIApplication(ZabbixAPISubClass):
         
    @checkauth
    @dojson('application.get')
    def get(self,**opts):
        """  * Get Applications data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $options
 * @param array $options['itemids']
 * @param array $options['hostids']
 * @param array $options['groupids']
 * @param array $options['triggerids']
 * @param array $options['applicationids']
 * @param boolean $options['status']
 * @param boolean $options['editable']
 * @param boolean $options['count']
 * @param string $options['pattern']
 * @param int $options['limit']
 * @param string $options['order']
 * @return array|int item data as array or false if error
"""

    @checkauth
    @dojson('application.getObjects')
    def getObjects(self,**opts):
        """  * Get Application ID by host.name and item.key
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $app_data
 * @param array $app_data['name']
 * @param array $app_data['hostid']
 * @return int|boolean
"""
        return opts 
             
    @checkauth
    @dojson('application.add')
    def add(self,**opts):
        """  * Add Applications
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $applications
 * @param array $app_data['name']
 * @param array $app_data['hostid']
 * @return boolean
"""

    @checkauth
    @dojson('application.update')
    def update(self,**opts):
        """  * Update Applications
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $applications
 * @param array $app_data['name']
 * @param array $app_data['hostid']
 * @return boolean
"""
        return opts 
             
    @checkauth
    @dojson('application.delete')
    def delete(self,**opts):
        """  * Delete Applications
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $applications
 * @param array $applications[0,...]['applicationid']
 * @return boolean
"""

    @checkauth
    @dojson('application.addItems')
    def addItems(self,**opts):
        """  * Add Items to applications
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $data
 * @param array $data['applications']
 * @param array $data['items']
 * @return boolean
"""
        return opts 

class ZabbixAPITrigger(ZabbixAPISubClass):

    @checkauth
    @dojson('trigger.get')
    def get(self,**opts):
        """  * Get Triggers data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['itemids']
 * @param array $options['hostids']
 * @param array $options['groupids']
 * @param array $options['triggerids']
 * @param array $options['applicationids']
 * @param array $options['status']
 * @param array $options['editable']
 * @param array $options['extendoutput']
 * @param array $options['count']
 * @param array $options['pattern']
 * @param array $options['limit']
 * @param array $options['order']
 * @return array|int item data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('trigger.getObjects')
    def getObjects(self,**opts):
        """  * Get triggerid by host.host and trigger.expression
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $triggers multidimensional array with trigger objects
 * @param array $triggers[0,...]['expression']
 * @param array $triggers[0,...]['host']
 * @param array $triggers[0,...]['hostid'] OPTIONAL
 * @param array $triggers[0,...]['description'] OPTIONAL
"""
        return opts 

    @checkauth
    @dojson('trigger.add')
    def add(self,**opts):
        """  * Add triggers
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $triggers multidimensional array with triggers data
 * @param array $triggers[0,...]['expression']
 * @param array $triggers[0,...]['description']
 * @param array $triggers[0,...]['type'] OPTIONAL
 * @param array $triggers[0,...]['priority'] OPTIONAL
 * @param array $triggers[0,...]['status'] OPTIONAL
 * @param array $triggers[0,...]['comments'] OPTIONAL
 * @param array $triggers[0,...]['url'] OPTIONAL
 * @param array $triggers[0,...]['templateid'] OPTIONAL
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('trigger.update')
    def update(self,**opts):
        """  * Update triggers
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $triggers multidimensional array with triggers data
 * @param array $triggers[0,...]['expression']
 * @param array $triggers[0,...]['description'] OPTIONAL
 * @param array $triggers[0,...]['type'] OPTIONAL
 * @param array $triggers[0,...]['priority'] OPTIONAL
 * @param array $triggers[0,...]['status'] OPTIONAL
 * @param array $triggers[0,...]['comments'] OPTIONAL
 * @param array $triggers[0,...]['url'] OPTIONAL
 * @param array $triggers[0,...]['templateid'] OPTIONAL
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('trigger.delete')
    def delete(self,**opts):
        """  * Delete triggers
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $triggers multidimensional array with trigger objects
 * @param array $triggers[0,...]['triggerid']
 * @return deleted triggers
"""
        return opts 

    @checkauth
    @dojson('trigger.addDependencies')
    def addDependencies(self,**opts):
        """  * Add dependency for trigger
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $triggers_data
 * @param array $triggers_data['triggerid]
 * @param array $triggers_data['depends_on_triggerid']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('trigger.deleteDependencies')
    def deleteDependencies(self,**opts):
        """  * Delete trigger dependencis
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $triggers multidimensional array with trigger objects
 * @param array $triggers[0,...]['triggerid']
 * @return boolean
"""
        return opts 

class ZabbixAPISysMap(ZabbixAPISubClass):

    @checkauth
    @dojson('map.get')
    def get(self,**opts):
        """  * Get Map data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['nodeids'] Node IDs
 * @param array $options['groupids'] HostGroup IDs
 * @param array $options['hostids'] Host IDs
 * @param boolean $options['monitored_hosts'] only monitored Hosts
 * @param boolean $options['templated_hosts'] include templates in result
 * @param boolean $options['with_items'] only with items
 * @param boolean $options['with_monitored_items'] only with monitored items
 * @param boolean $options['with_historical_items'] only with historical items
 * @param boolean $options['with_triggers'] only with triggers
 * @param boolean $options['with_monitored_triggers'] only with monitored triggers
 * @param boolean $options['with_httptests'] only with http tests
 * @param boolean $options['with_monitored_httptests'] only with monitored http tests
 * @param boolean $options['with_graphs'] only with graphs
 * @param boolean $options['editable'] only with read-write permission. Ignored for SuperAdmins
 * @param int $options['extendoutput'] return all fields for Hosts
 * @param int $options['count'] count Hosts, returned column name is rowscount
 * @param string $options['pattern'] search hosts by pattern in host names
 * @param int $options['limit'] limit selection
 * @param string $options['sortorder']
 * @param string $options['sortfield']
 * @return array|boolean Host data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('map.add')
    def add(self,**opts):
        """  * Add Map
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $maps
 * @param string $maps['name']
 * @param array $maps['width']
 * @param int $maps['height']
 * @param string $maps['backgroundid']
  * @param string $maps['highlight']
 * @param array $maps['label_type']
 * @param int $maps['label_location']
 * @return boolean | array
"""
        return opts 

    @checkauth
    @dojson('map.update')
    def update(self,**opts):
        """  * Update Map
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $maps multidimensional array with Hosts data
 * @param string $maps['sysmapid']
 * @param string $maps['name']
 * @param array $maps['width']
 * @param int $maps['height']
 * @param string $maps['backgroundid']
 * @param array $maps['label_type']
 * @param int $maps['label_location']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('map.delete')
    def delete(self,**opts):
        """  * Delete Map
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $sysmaps
 * @param array $sysmaps['sysmapid']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('map.addLinks')
    def addLinks(self,**opts):
        """  * addLinks Map
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $links
 * @param array $links[0,...]['sysmapid']
 * @param array $links[0,...]['selementid1']
 * @param array $links[0,...]['selementid2']
 * @param array $links[0,...]['drawtype']
 * @param array $links[0,...]['color']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('map.addElements')
    def addElements(self,**opts):
        """  * Add Element to Sysmap
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $elements[0,...]['sysmapid']
 * @param array $elements[0,...]['elementid']
 * @param array $elements[0,...]['elementtype']
 * @param array $elements[0,...]['label']
 * @param array $elements[0,...]['x']
 * @param array $elements[0,...]['y']
 * @param array $elements[0,...]['iconid_off']
 * @param array $elements[0,...]['iconid_unknown']
 * @param array $elements[0,...]['iconid_on']
 * @param array $elements[0,...]['iconid_disabled']
 * @param array $elements[0,...]['url']
 * @param array $elements[0,...]['label_location']
"""
        return opts 

    @checkauth
    @dojson('map.addLinkTrigger')
    def addLinkTrigger(self,**opts):
        """  * Add link trigger to link (Sysmap)
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $links[0,...]['linkid']
 * @param array $links[0,...]['triggerid']
 * @param array $links[0,...]['drawtype']
 * @param array $links[0,...]['color']
"""
        return opts 

class ZabbixAPITemplate(ZabbixAPISubClass):

    @checkauth
    @dojson('template.get')
    def get(self,**opts):
        """  * Get Template data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @static
 * @param array $options
 * @return array|boolean Template data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('template.getObjects')
    def get(self,**opts):
        """  * Get Template ID by Template name
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $template_data
 * @param array $template_data['host']
 * @return string templateid
"""
        return opts 

    @checkauth
    @dojson('template.create')
    def create(self,**opts):
        """  * Add Template
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $templates multidimensional array with templates data
 * @param string $templates['host']
 * @param string $templates['port']
 * @param string $templates['status']
 * @param string $templates['useip']
 * @param string $templates['dns']
 * @param string $templates['ip']
 * @param string $templates['proxy_hostid']
 * @param string $templates['useipmi']
 * @param string $templates['ipmi_ip']
 * @param string $templates['ipmi_port']
 * @param string $templates['ipmi_authtype']
 * @param string $templates['ipmi_privilege']
 * @param string $templates['ipmi_username']
 * @param string $templates['ipmi_password']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('template.update')
    def update(self,**opts):
        """  * Update Template
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $templates multidimensional array with templates data
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('template.delete')
    def delete(self,**opts):
        """  * Delete Template
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $templateids
 * @param array $templateids['templateids']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('template.massUpdate')
    def massUpdate(self,**opts):
        """  * Mass update hosts
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $hosts multidimensional array with Hosts data
 * @param array $hosts['hosts'] Array of Host objects to update
 * @param string $hosts['fields']['host'] Host name.
 * @param array $hosts['fields']['groupids'] HostGroup IDs add Host to.
 * @param int $hosts['fields']['port'] Port. OPTIONAL
 * @param int $hosts['fields']['status'] Host Status. OPTIONAL
 * @param int $hosts['fields']['useip'] Use IP. OPTIONAL
 * @param string $hosts['fields']['dns'] DNS. OPTIONAL
 * @param string $hosts['fields']['ip'] IP. OPTIONAL
 * @param int $hosts['fields']['proxy_hostid'] Proxy Host ID. OPTIONAL
 * @param int $hosts['fields']['useipmi'] Use IPMI. OPTIONAL
 * @param string $hosts['fields']['ipmi_ip'] IPMAI IP. OPTIONAL
 * @param int $hosts['fields']['ipmi_port'] IPMI port. OPTIONAL
 * @param int $hosts['fields']['ipmi_authtype'] IPMI authentication type. OPTIONAL
 * @param int $hosts['fields']['ipmi_privilege'] IPMI privilege. OPTIONAL
 * @param string $hosts['fields']['ipmi_username'] IPMI username. OPTIONAL
 * @param string $hosts['fields']['ipmi_password'] IPMI password. OPTIONAL
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('template.massAdd')
    def massAdd(self,**opts):
        """  * Link Template to Hosts
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $data
 * @param string $data['templates']
 * @param string $data['hosts']
 * @param string $data['groups']
 * @param string $data['templates_link']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('template.massRemove')
    def massRemove(self,**opts):
        """  * remove Hosts to HostGroups. All Hosts are added to all HostGroups.
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $data
 * @param array $data['templates']
 * @param array $data['groups']
 * @param array $data['hosts']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('template.linkTemplates')
    def linkTemplates(self,**opts):
        """  * Link Host to Templates
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $data
 * @param string $data['hosts']
 * @param array $data['templats']
 * @return boolean
"""
        return opts 

class ZabbixAPIAction(ZabbixAPISubClass):
    @checkauth
    @dojson('action.get')
    def get(self,**opts):
        """  * Get Actions data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['itemids']
 * @param array $options['hostids']
 * @param array $options['groupids']
 * @param array $options['actionids']
 * @param array $options['applicationids']
 * @param array $options['status']
 * @param array $options['templated_items']
 * @param array $options['editable']
 * @param array $options['extendoutput']
 * @param array $options['count']
 * @param array $options['pattern']
 * @param array $options['limit']
 * @param array $options['order']
 * @return array|int item data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('action.add')
    def add(self,**opts):
        """  * Add actions
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $actions multidimensional array with actions data
 * @param array $actions[0,...]['expression']
 * @param array $actions[0,...]['description']
 * @param array $actions[0,...]['type'] OPTIONAL
 * @param array $actions[0,...]['priority'] OPTIONAL
 * @param array $actions[0,...]['status'] OPTIONAL
 * @param array $actions[0,...]['comments'] OPTIONAL
 * @param array $actions[0,...]['url'] OPTIONAL
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('action.update')
    def update(self,**opts):
        """  * Update actions
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $actions multidimensional array with actions data
 * @param array $actions[0,...]['actionid']
 * @param array $actions[0,...]['expression']
 * @param array $actions[0,...]['description']
 * @param array $actions[0,...]['type'] OPTIONAL
 * @param array $actions[0,...]['priority'] OPTIONAL
 * @param array $actions[0,...]['status'] OPTIONAL
 * @param array $actions[0,...]['comments'] OPTIONAL
 * @param array $actions[0,...]['url'] OPTIONAL
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('action.addConditions')
    def addConditions(self,**opts):
        """  * add conditions
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $conditions multidimensional array with conditions data
 * @param array $conditions[0,...]['actionid']
 * @param array $conditions[0,...]['type']
 * @param array $conditions[0,...]['value']
 * @param array $conditions[0,...]['operator']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('action.addOperations')
    def addOperations(self,**opts):
        """  * add operations
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $operations multidimensional array with operations data
 * @param array $operations[0,...]['actionid']
 * @param array $operations[0,...]['operationtype']
 * @param array $operations[0,...]['object']
 * @param array $operations[0,...]['objectid']
 * @param array $operations[0,...]['shortdata']
 * @param array $operations[0,...]['longdata']
 * @param array $operations[0,...]['esc_period']
 * @param array $operations[0,...]['esc_step_from']
 * @param array $operations[0,...]['esc_step_to']
 * @param array $operations[0,...]['default_msg']
 * @param array $operations[0,...]['evaltype']
 * @param array $operations[0,...]['mediatypeid']
 * @param array $operations[0,...]['opconditions']
 * @param array $operations[0,...]['opconditions']['conditiontype']
 * @param array $operations[0,...]['opconditions']['operator']
 * @param array $operations[0,...]['opconditions']['value']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('action.delete')
    def delete(self,**opts):
        """  * Delete actions
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $actionids
 * @param array $actionids['actionids']
 * @return boolean
"""
        return opts 

class ZabbixAPIAlert(ZabbixAPISubClass):
    @checkauth
    @dojson('alert.get')
    def get(self,**opts):
        """  * Get Alerts data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['itemids']
 * @param array $options['hostids']
 * @param array $options['groupids']
 * @param array $options['alertids']
 * @param array $options['applicationids']
 * @param array $options['status']
 * @param array $options['templated_items']
 * @param array $options['editable']
 * @param array $options['extendoutput']
 * @param array $options['count']
 * @param array $options['pattern']
 * @param array $options['limit']
 * @param array $options['order']
 * @return array|int item data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('alert.add')
    def add(self,**opts):
        """  * Add alerts
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $alerts multidimensional array with alerts data
 * @param array $alerts[0,...]['expression']
 * @param array $alerts[0,...]['description']
 * @param array $alerts[0,...]['type'] OPTIONAL
 * @param array $alerts[0,...]['priority'] OPTIONAL
 * @param array $alerts[0,...]['status'] OPTIONAL
 * @param array $alerts[0,...]['comments'] OPTIONAL
 * @param array $alerts[0,...]['url'] OPTIONAL
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('alert.delete')
    def delete(self,**opts):
        """  * Delete alerts
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $alertids
 * @param array $alertids['alertids']
 * @return boolean
"""
        return opts 

class ZabbixAPIInfo(ZabbixAPISubClass):
    @checkauth
    @dojson('apiinfo.version')
    def version(self,**opts):
        """  * Get API version
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @return string
"""
        return opts 
    
class ZabbixAPIEvent(ZabbixAPISubClass):
    @checkauth
    @dojson('event.get')
    def get(self,**opts):
        """  * Get events data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['itemids']
 * @param array $options['hostids']
 * @param array $options['groupids']
 * @param array $options['eventids']
 * @param array $options['applicationids']
 * @param array $options['status']
 * @param array $options['templated_items']
 * @param array $options['editable']
 * @param array $options['extendoutput']
 * @param array $options['count']
 * @param array $options['pattern']
 * @param array $options['limit']
 * @param array $options['order']
 * @return array|int item data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('event.add')
    def add(self,**opts):
        """  * Add events ( without alerts )
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $events multidimensional array with events data
 * @param array $events[0,...]['source']
 * @param array $events[0,...]['object']
 * @param array $events[0,...]['objectid']
 * @param array $events[0,...]['clock'] OPTIONAL
 * @param array $events[0,...]['value'] OPTIONAL
 * @param array $events[0,...]['acknowledged'] OPTIONAL
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('event.delete')
    def delete(self,**opts):
        """  * Delete events by eventids
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $eventids
 * @param array $eventids['eventids']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('event.deleteByTriggerIDs')
    def deleteByTriggerIDs(self,**opts):
        """      * Delete events by triggerids
     *
     * {@source}
     * @access public
     * @static
     * @since 1.8
     * @version 1
     *
     * @param _array $triggerids
     * @return boolean
"""
        return opts 

    @checkauth
    @dojson('event.acknowledge')
    def acknowledge(self,**opts):
        """ 
        events
        eventids
        triggers
        triggerids
        message
"""
        return opts 

class ZabbixAPIGraph(ZabbixAPISubClass):
    @checkauth
    @dojson('graph.get')
    def get(self,**opts):
        """ * Get graph data
*
* <code>
* $options = array(
*    array 'graphids'                => array(graphid1, graphid2, ...),
*    array 'itemids'                    => array(itemid1, itemid2, ...),
*    array 'hostids'                    => array(hostid1, hostid2, ...),
*    int 'type'                    => 'graph type, chart/pie'
*    boolean 'templated_graphs'            => 'only templated graphs',
*    int 'count'                    => 'count',
*    string 'pattern'                => 'search hosts by pattern in graph names',
*    integer 'limit'                    => 'limit selection',
*    string 'order'                    => 'deprecated parameter (for now)'
* );
* </code>
*
* @static
* @param array $options
* @return array|boolean host data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('graph.getObjects')
    def getObjects(self,**opts):
        """  * Get graphid by graph name
 *
 * <code>
 * $graph_data = array(
 *     *string 'graph' => 'graph name'
 * );
 * </code>
 *
 * @static
 * @param array $graph_data
 * @return string|boolean graphid
"""
        return opts 

    @checkauth
    @dojson('graph.add')
    def add(self,**opts):
        """  * Add graph
 *
 * <code>
 * $graphs = array(
 *     *string 'name'            => null,
 *     int 'width'            => 900,
 *     int 'height'            => 200,
 *     int 'ymin_type'            => 0,
 *     int 'ymax_type'            => 0,
 *     int 'yaxismin'            => 0,
 *     int 'yaxismax'            => 100,
 *     int 'ymin_itemid'        => 0,
 *     int 'ymax_itemid'        => 0,
 *     int 'show_work_period'        => 1,
 *     int 'show_triggers'        => 1,
 *     int 'graphtype'            => 0,
 *     int 'show_legend'        => 0,
 *     int 'show_3d'            => 0,
 *     int 'percent_left'        => 0,
 *     int 'percent_right'        => 0
 * );
 * </code>
 *
 * @static
 * @param array $graphs multidimensional array with graphs data
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('graph.update')
    def update(self,**opts):
        """  * Update graphs
 *
 * @static
 * @param array $graphs multidimensional array with graphs data
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('graph.delete')
    def delete(self,**opts):
        """  * Delete graphs
 *
 * @static
 * @param _array $graphs
 * @param array $graphs['graphids']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('graph.addItems')
    def addItems(self,**opts):
        """  * Add items to graph
 *
 * <code>
 * $items = array(
 *     *string 'graphid'        => null,
 *     array 'items'             => (
 *        'item1' => array(
 *             *int 'itemid'            => null,
 *             int 'color'            => '000000',
 *             int 'drawtype'            => 0,
 *             int 'sortorder'            => 0,
 *             int 'yaxisside'            => 1,
 *             int 'calc_fnc'            => 2,
 *             int 'type'            => 0,
 *             int 'periods_cnt'        => 5,
 *        ), ... )
 * );
 * </code>
 *
 * @static
 * @param array $items multidimensional array with items data
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('graph.deleteItems')
    def deleteItems(self,**opts):
        """ /**
 * Delete graph items
 *
 * @static
 * @param array $items
 * @return boolean
 */
"""
        return opts 

class ZabbixAPIGraphItem(ZabbixAPISubClass):
    @checkauth
    @dojson('graphitem.get')
    def get(self,**opts):
        """ * Get GraphItems data
*
* @static
* @param array $options
* @return array|boolean
"""
        return opts 

    @checkauth
    @dojson('graphitem.getObjects')
    def getObjects(self,**opts):
        """  * Get graph items by graph id and graph item id
 *
 * @static
 * @param _array $gitem_data
 * @param array $gitem_data['itemid']
 * @param array $gitem_data['graphid']
 * @return string|boolean graphid
"""
        return opts 

    @checkauth
    @dojson('maintenance.get')
    def get(self,**opts):
        """  * Get maintenances data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $options
 * @param array $options['itemids']
 * @param array $options['hostids']
 * @param array $options['groupids']
 * @param array $options['triggerids']
 * @param array $options['maintenanceids']
 * @param boolean $options['status']
 * @param boolean $options['templated_items']
 * @param boolean $options['editable']
 * @param boolean $options['count']
 * @param string $options['pattern']
 * @param int $options['limit']
 * @param string $options['order']
 * @return array|int item data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('maintenance.getObjects')
    def getObjects(self,**opts):
        """  * Get Maintenance ID by host.name and item.key
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $maintenance
 * @param array $maintenance['name']
 * @param array $maintenance['hostid']
 * @return int|boolean
"""
        return opts 

    @checkauth
    @dojson('maintenance.add')
    def add(self,**opts):
        """  * Add maintenances
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $maintenances
 * @param array $maintenance['name']
 * @param array $maintenance['hostid']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('maintenance.update')
    def update(self,**opts):
        """  * Update maintenances
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $maintenances
 * @param array $maintenance['name']
 * @param array $maintenance['hostid']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('maintenance.delete')
    def delete(self,**opts):
        """  * Delete maintenances
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $maintenanceids
 * @param _array $maintenanceids['maintenanceids']
 * @return boolean
"""
        return opts 

class ZabbixAPIMap(ZabbixAPISubClass):
    @checkauth
    @dojson('map.get')
    def get(self,**opts):
        """  * Get Map data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['nodeids'] Node IDs
 * @param array $options['groupids'] HostGroup IDs
 * @param array $options['hostids'] Host IDs
 * @param boolean $options['monitored_hosts'] only monitored Hosts
 * @param boolean $options['templated_hosts'] include templates in result
 * @param boolean $options['with_items'] only with items
 * @param boolean $options['with_monitored_items'] only with monitored items
 * @param boolean $options['with_historical_items'] only with historical items
 * @param boolean $options['with_triggers'] only with triggers
 * @param boolean $options['with_monitored_triggers'] only with monitored triggers
 * @param boolean $options['with_httptests'] only with http tests
 * @param boolean $options['with_monitored_httptests'] only with monitored http tests
 * @param boolean $options['with_graphs'] only with graphs
 * @param boolean $options['editable'] only with read-write permission. Ignored for SuperAdmins
 * @param int $options['extendoutput'] return all fields for Hosts
 * @param int $options['count'] count Hosts, returned column name is rowscount
 * @param string $options['pattern'] search hosts by pattern in host names
 * @param int $options['limit'] limit selection
 * @param string $options['sortorder']
 * @param string $options['sortfield']
 * @return array|boolean Host data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('map.add')
    def add(self,**opts):
        """  * Add Map
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $maps
 * @param string $maps['name']
 * @param array $maps['width']
 * @param int $maps['height']
 * @param string $maps['backgroundid']
  * @param string $maps['highlight']
 * @param array $maps['label_type']
 * @param int $maps['label_location']
 * @return boolean | array
"""
        return opts 

    @checkauth
    @dojson('update.')
    def update(self,**opts):
        """  * Update Map
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $maps multidimensional array with Hosts data
 * @param string $maps['sysmapid']
 * @param string $maps['name']
 * @param array $maps['width']
 * @param int $maps['height']
 * @param string $maps['backgroundid']
 * @param array $maps['label_type']
 * @param int $maps['label_location']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('map.delete')
    def delete(self,**opts):
        """  * Delete Map
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $sysmaps
 * @param array $sysmaps['sysmapid']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('map.addLinks')
    def addLinks(self,**opts):
        """  * addLinks Map
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $links
 * @param array $links[0,...]['sysmapid']
 * @param array $links[0,...]['selementid1']
 * @param array $links[0,...]['selementid2']
 * @param array $links[0,...]['drawtype']
 * @param array $links[0,...]['color']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('map.addElements')
    def addElements(self,**opts):
        """  * Add Element to Sysmap
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $elements[0,...]['sysmapid']
 * @param array $elements[0,...]['elementid']
 * @param array $elements[0,...]['elementtype']
 * @param array $elements[0,...]['label']
 * @param array $elements[0,...]['x']
 * @param array $elements[0,...]['y']
 * @param array $elements[0,...]['iconid_off']
 * @param array $elements[0,...]['iconid_unknown']
 * @param array $elements[0,...]['iconid_on']
 * @param array $elements[0,...]['iconid_disabled']
 * @param array $elements[0,...]['url']
 * @param array $elements[0,...]['label_location']
"""
        return opts 

    @checkauth
    @dojson('map.addLinkTrigger')
    def addLinkTrigger(self,**opts):
        """  * Add link trigger to link (Sysmap)
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $links[0,...]['linkid']
 * @param array $links[0,...]['triggerid']
 * @param array $links[0,...]['drawtype']
 * @param array $links[0,...]['color']
"""
        return opts 

class ZabbixAPIScreen(ZabbixAPISubClass):
    @checkauth
    @dojson('screen.get')
    def get(self,**opts):
        """  * Get Screen data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['nodeids'] Node IDs
 * @param boolean $options['with_items'] only with items
 * @param boolean $options['editable'] only with read-write permission. Ignored for SuperAdmins
 * @param int $options['extendoutput'] return all fields for Hosts
 * @param int $options['count'] count Hosts, returned column name is rowscount
 * @param string $options['pattern'] search hosts by pattern in host names
 * @param int $options['limit'] limit selection
 * @param string $options['order'] deprecated parameter (for now)
 * @return array|boolean Host data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('screen.add')
    def add(self,**opts):
        """  * Add Screen
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $screens
 * @param string $screens['name']
 * @param array $screens['hsize']
 * @param int $screens['vsize']
 * @return boolean | array
"""
        return opts 

    @checkauth
    @dojson('screen.update')
    def update(self,**opts):
        """  * Update Screen
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $screens multidimensional array with Hosts data
 * @param string $screens['screenid']
 * @param int $screens['name']
 * @param int $screens['hsize']
 * @param int $screens['vsize']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('screen.delete')
    def delete(self,**opts):
        """  * Delete Screen
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $screens
 * @param array $screens[0,...]['screenid']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('screen.setItems')
    def setItems(self,**opts):
        """  * add ScreenItem
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $screen_items
 * @param int $screen_items['screenid']
 * @param int $screen_items['resourcetype']
 * @param int $screen_items['x']
 * @param int $screen_items['y']
 * @param int $screen_items['resourceid']
 * @param int $screen_items['width']
 * @param int $screen_items['height']
 * @param int $screen_items['colspan']
 * @param int $screen_items['rowspan']
 * @param int $screen_items['elements']
 * @param int $screen_items['valign']
 * @param int $screen_items['halign']
 * @param int $screen_items['style']
 * @param int $screen_items['url']
 * @param int $screen_items['dynamic']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('screen.deleteItems')
    def deleteItems(self,**opts):
        """  * delete ScreenItem
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $screen_itemids
 * @return boolean
"""
        return opts 

class ZabbixAPIScript(ZabbixAPISubClass):
    @checkauth
    @dojson('script.get')
    def get(self,**opts):
        """  * Get Scripts data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $options
 * @param array $options['itemids']
 * @param array $options['hostids']
 * @param array $options['groupids']
 * @param array $options['triggerids']
 * @param array $options['scriptids']
 * @param boolean $options['status']
 * @param boolean $options['templated_items']
 * @param boolean $options['editable']
 * @param boolean $options['count']
 * @param string $options['pattern']
 * @param int $options['limit']
 * @param string $options['order']
 * @return array|int item data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('script.getObjects')
    def getObjects(self,**opts):
        """  * Get Script ID by host.name and item.key
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $script
 * @param array $script['name']
 * @param array $script['hostid']
 * @return int|boolean
"""
        return opts 

    @checkauth
    @dojson('script.add')
    def add(self,**opts):
        """  * Add Scripts
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $scripts
 * @param array $script['name']
 * @param array $script['hostid']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('script.update')
    def update(self,**opts):
        """  * Update Scripts
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $scripts
 * @param array $script['name']
 * @param array $script['hostid']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('script.delete')
    def delete(self,**opts):
        """  * Delete Scripts
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $scriptids
 * @param array $scriptids
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('script.execute')
    def execute(self,**opts):
        """ 
"""
        return opts 

    @checkauth
    @dojson('script.getCommand')
    def getCommand(self,**opts):
        """ 
"""
        return opts 

    @checkauth
    @dojson('script.getScriptsByHosts')
    def getScriptsByHosts(self,**opts):
        """ 
"""
        return opts 

class ZabbixAPIUserMacro(ZabbixAPISubClass):
    @checkauth
    @dojson('usermacro.get')
    def get(self,**opts):
        """  * Get UserMacros data
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $options
 * @param array $options['nodeids'] Node IDs
 * @param array $options['groupids'] UserMacrosGroup IDs
 * @param array $options['macroids'] UserMacros IDs
 * @param boolean $options['monitored_macros'] only monitored UserMacros
 * @param boolean $options['templated_macros'] include templates in result
 * @param boolean $options['with_items'] only with items
 * @param boolean $options['with_monitored_items'] only with monitored items
 * @param boolean $options['with_historical_items'] only with historical items
 * @param boolean $options['with_triggers'] only with triggers
 * @param boolean $options['with_monitored_triggers'] only with monitored triggers
 * @param boolean $options['with_httptests'] only with http tests
 * @param boolean $options['with_monitored_httptests'] only with monitored http tests
 * @param boolean $options['with_graphs'] only with graphs
 * @param boolean $options['editable'] only with read-write permission. Ignored for SuperAdmins
 * @param int $options['extendoutput'] return all fields for UserMacros
 * @param int $options['count'] count UserMacros, returned column name is rowscount
 * @param string $options['pattern'] search macros by pattern in macro names
 * @param int $options['limit'] limit selection
 * @param string $options['order'] deprecated parameter (for now)
 * @return array|boolean UserMacros data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('usermacro.getHostMacroObjects')
    def getHostMacroObjects(self,**opts):
        """  * Gets all UserMacros data from DB by UserMacros ID
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $macro_data
 * @param string $macro_data['macroid']
 * @return array|boolean UserMacros data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('usermacro.add')
    def add(self,**opts):
        """  * add Host Macro
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $macros
 * @param string $macros[0..]['hostid']
 * @param string $macros[0..]['macro']
 * @param string $macros[0..]['value']
 * @return array of object macros
"""
        return opts 

    @checkauth
    @dojson('usermacro.update')
    def update(self,**opts):
        """  * Update host macros, replace all with new ones
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $macros
 * @param string $macros['hostid']
 * @param string $macros['macros'][0..]['macro']
 * @param string $macros['macros'][0..]['value']
 * @return array|boolean
"""
        return opts 

    @checkauth
    @dojson('usermacro.updateValue')
    def updateValue(self,**opts):
        """  * Update macros values
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $macros
 * @param string $macros['hostid']
 * @param string $macros['macros'][0..]['macro']
 * @param string $macros['macros'][0..]['value']
 * @return array|boolean
"""
        return opts 

    @checkauth
    @dojson('usermacro.deleteHostMacro')
    def deleteHostMacro(self,**opts):
        """  * Delete UserMacros
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $hostmacroids
 * @param array $hostmacroids['hostmacroids']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('usermacro.addGlobal')
    def addGlobal(self,**opts):
        """  * Add global macros
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $macros

 * @param string $macros[0..]['macro']
 * @param string $macros[0..]['value']
 * @return array|boolean
"""
        return opts 

    @checkauth
    @dojson('usermacro.deleteGlobalMacro')
    def deleteGlobalMacro(self,**opts):
        """  * Delete UserMacros
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param array $globalmacroids
 * @param array $globalmacroids['globalmacroids']
 * @return boolean
"""
        return opts 

    @checkauth
    @dojson('usermacro.validate')
    def validate(self,**opts):
        """  * Validates macros expression
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $macros array with macros expressions
 * @return array|boolean
"""
        return opts 

    @checkauth
    @dojson('usermacro.getGlobalMacroObjects')
    def getGlobalMacroObjects(self,**opts):
        """  * Gets all UserMacros data from DB by UserMacros ID
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $macro_data
 * @param string $macro_data['macroid']
 * @return array|boolean UserMacros data as array or false if error
"""
        return opts 

    @checkauth
    @dojson('usermacro.getHostMacroId')
    def getHostMacroId(self,**opts):
        """  * Get UserMacros ID by UserMacros name
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $macro_data
 * @param string $macro_data['macro']
 * @param string $macro_data['hostid']
 * @return int|boolean
"""
        return opts 

    @checkauth
    @dojson('usermacro.getGlobalMacroId')
    def getGlobalMacroId(self,**opts):
        """  * Get UserMacros ID by UserMacros name
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $macro_data
 * @param string $macro_data['macro']
 * @return int|boolean
"""
        return opts 

    @checkauth
    @dojson('usermacro.getMacros')
    def getMacros(self,**opts):
        """ 
"""
        return opts 

    @checkauth
    @dojson('usermacro.resolveTrigger')
    def resolveTrigger(self,**opts):
        """ 
"""
        return opts 

    @checkauth
    @dojson('usermacro.resolveItem')
    def resolveItem(self,**opts):
        """ 
"""
        return opts 
