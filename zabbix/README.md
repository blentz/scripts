This is an implementation of the Zabbix API in Python.
Please note that the Zabbix API is still in a draft state,
and subject to change.

Implementations of the Zabbix API in other languages may
be found on the wiki.

Zabbix 1.8, 2.0, 2.2, 2.4, 3.0 and 3.2 are supported.
Python 2 and 3 are supported.

Future versions must be supported too, if there is no deep changes.

Installation:
```sh
# pip install zabbix-api
```

Short example:

```python
>>> from zabbix_api import ZabbixAPI
>>> zapi = ZabbixAPI(server="https://server/")
>>> zapi.login("login", "password")
>>> zapi.trigger.get({"expandExpression": "extend", "triggerids": range(0, 100)})
```

See also:
* http://www.zabbix.com/wiki/doc/api
* https://www.zabbix.com/documentation/2.4/manual/api
* http://www.zabbix.com/forum/showthread.php?t=15218
