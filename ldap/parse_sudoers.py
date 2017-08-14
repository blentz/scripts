#!/usr/bin/env python
#
# This program parses a sudoers file and can be used to test who has
# what access
#
# Author: Joel Heenan 30/09/2008
# Author: Brett Lentz 30/09/2009 - added ldif support
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import re,grp,socket,sys,os,commands
import StringIO
import csv
from optparse import OptionParser

#TODO: fix ldif output:
# on the same host, if there are different runas users across multiple commands,
# it's output into a single DN.

try:
    import netgroup
    netgroupSupport = True
except:
    netgroupSupport = False

class SudoCmnd:
    def __init__(self,runas,passwd,command,sp,comment="",options=None):
        self.runas = runas
        self.passwd = passwd
        self.command = command
        self.sp = sp
        self.comment = comment
        self.options = options

    def __repr__(self):
        commands = []
        for cmndAlias in self.sp.cmndAliases:
            if(cmndAlias == self.command):
                commands = self.sp.cmndAliases[cmndAlias]

        if(self.passwd):
            str = "(%s) %s" % (self.runas, self.command)
        else:
            str = "(%s) NOPASSWD: %s" % (self.runas, self.command)
        for command in commands:
            str += "\t%s\n" % command
        return str

    def matchCommand(self,command):
        if(command == self.command):
            return True
        for cmndAlias in self.sp.cmndAliases:
            if(cmndAlias == self.command):
                return self.sp.matchCmndAlias(self.sp.cmndAliases[cmndAlias],command)
        return self.sp.matchCmndAlias([self.command],command)

    def getLDIF(self):
        my_ldif = []
        commands = {}
        aliases = self.sp.cmndAliases.keys()

        for cmndAlias in self.sp.cmndAliases:
            if(cmndAlias == self.command):
                for cmd in self.sp.cmndAliases[cmndAlias]:
                    commands[cmd] = 1
            elif self.command not in aliases:
                commands[self.command] = 1

        if self.runas and self.runas not in ["ANY", "ALL", "ALL*ALL"]:
            my_ldif.append("sudoRunas: %s" % self.runas)
        if not self.passwd:
            my_ldif.append("sudoOption: !authenticate")
        for command in commands.keys():
            my_ldif.append("sudoCommand: %s" % command)
        return my_ldif

class SudoRule:
    def __init__(self,user,server,command,sp,options=None):
        self.user = user
        self.server = server
        self.command = command
        self.sp = sp
        self.options = options

    def __repr__(self):
        return "%s %s %s" % (self.user,self.server,self.command)

    def matchUser(self,user):
        if(user == self.user):
            return True
        for userAlias in self.sp.userAliases:
            if(userAlias == self.user): #I'm a user alias
                return self.sp.matchUserAlias(self.sp.userAliases[userAlias],user)
        return self.sp.matchUserAlias([self.user],user)

    def matchHost(self,host):
        if(host == self.server):
            return True
        for hostAlias in self.sp.hostAliases:
            if(hostAlias == self.server): #I'm a host alias
                return self.sp.matchHostAlias(self.sp.hostAliases[hostAlias],host)
        return self.sp.matchHostAlias([self.server],host)

    def getLDIF(self):
        my_ldif = []

        users = []
        aliased = False
        for userAlias in self.sp.userAliases:
            if(userAlias == self.user): #I'm a user alias
                users.extend(self.sp.userAliases[userAlias])
                aliased = True

        if not aliased:
            users.append(self.user)

        for user in users:
            my_ldif.append("sudoUser: %s" % user)

        found = False
        for hostAlias in self.sp.hostAliases:
            if hostAlias == self.server:
                for host in self.sp.hostAliases[hostAlias]:
                    my_ldif.append("sudoHost: %s" % host)
                found = True

        if not found:
            my_ldif.append("sudoHost: %s" % self.server)

        for cmd in self.command:
            my_ldif.extend(cmd.getLDIF())

        return my_ldif

class SudoersParser:
    def __init__(self, options=None):
        self.hostAliases  = {}
        self.userAliases  = {}
        self.cmndAliases  = {}
        self.rules        = []
        self.options      = options

        self.netgroupWarning = 'netgroup syntax used in file but no python netgroup support. Install the python netgroup module for support'

    def _readfile(self, file):
        fh = open(file,"r")
        return fh.readlines()

    def getLDIF(self):
        my_ldif = []
        for rule in self.rules:
            my_ldif.append(rule.getLDIF())
        return my_ldif

    def getSudoers(self):
        my_sudoers = []
        for rule in self.rules:
            cmd = ""
            for cmnd in rule.command.command:
                if rule.command.runas not in [ "ANY", "ALL", "root" ]:
                    cmd += "(%s) " % rule.command.runas

                #FIXME: if one command is NOPASSWD, they all are.
                if not rule.command.passwd:
                    cmd += "NOPASSWD: "

                cmd += cmnd.strip() + ", "
            cmd = re.sub(",\s*$", "", cmd) # remove the final comma.

            if rule.command.comment:
                my_sudoers.append("# %s" % rule.command.comment)

            my_sudoers.append("%s %s = %s" % (rule.user, \
                    rule.server, cmd))
        return my_sudoers

    def parseFile(self,file):
        lines = self._readfile(file)
        lines = self._collapseLines(lines)

        defaultsRE  = re.compile("^\s*Defaults")
        hostAliasRE = re.compile("^\s*Host_Alias")
        userAliasRE = re.compile("^\s*User_Alias")
        cmndAliasRE = re.compile("^\s*Cmnd_Alias")

        for line in lines:
            if(defaultsRE.search(line)):
                # don't currently do anything with these
                continue
            if(hostAliasRE.search(line)):
                self.hostAliases.update(self._parseAlias(line,"Host_Alias"))
                continue
            if(userAliasRE.search(line)):
                self.userAliases.update(self._parseAlias(line,"User_Alias"))
                continue
            if(cmndAliasRE.search(line)):
                self.cmndAliases.update(self._parseAlias(line,"Cmnd_Alias"))
                continue

            rule = self._parseRule(line)
            if(rule):
                self.rules.extend(rule)

    def parseLDIF(self, file):
        lines = self._readfile(file)

        nameRE  = re.compile("^\s*dn: ")
        optionsRE  = re.compile("^\s*sudoOption")
        hostRE = re.compile("^\s*sudoHost")
        userRE = re.compile("^\s*sudoUser")
        cmndRE = re.compile("^\s*sudoCommand")
        runasRE = re.compile("^\s*sudoRunAs")

        obj = {}
        seen = False
        dn = ""

        # parse the ldif into individual objects.
        for line in lines:
            if nameRE.search(line):
                seen = True
                dn = line[3:].strip()
                obj[dn] = []
                continue

            if re.compile("^\s*$").search(line):
                seen = False
                dn = ""
                continue

            # capture everything between the dn and the final empty line.
            if seen:
                obj[dn].append(line.strip())


        rule = {}
        sudo_rules = []
        for sudoer in obj:
            hosts = []
            users = []
            cmds = []
            runas = "ANY"
            passwd = True
            option = None

            for line in obj[sudoer]:
                if hostRE.search(line):
                    host = self._parseLDIFAlias(line,"sudoHost")
                    hosts.append(host)
                    self.hostAliases.update({host:host})
                    continue
                if userRE.search(line):
                    user = self._parseLDIFAlias(line,"sudoUser")
                    users.append(user)
                    self.userAliases.update({user:user})
                    continue
                if cmndRE.search(line):
                    cmd = self._parseLDIFAlias(line,"sudoCommand").strip()
                    cmds.append(cmd)
                    self.cmndAliases.update({cmd:cmd})
                    continue
                if runasRE.search(line):
                    runas = self._parseLDIFRunas(line)
                    continue
                if optionsRE.search(line):
                    passwd, option = self._parseLDIFOptions(line)
                    continue

            # the joys of normalizing many:many relationships. :-\
            for host in hosts:
                for user in users:
                    sudo_rules.append(SudoRule(user,host,SudoCmnd(runas,passwd,cmds,self,sudoer,self.options),self,self.options,))

        self.rules.extend(sudo_rules)

    # what commands can a user run on a particular host?
    # note: we assume that the current user/group environment is the
    # same as the host 
    def getCommands(self, user, host="localhost", csv_out=False):
        if(host=="localhost" or host is None):
            host=socket.gethostname()

        if csv_out:
            stringIO = StringIO.StringIO()
            csv_writer = csv.writer(stringIO)
        else:
            print "\nTesting what %s can run on %s\n" % (user,host)
        match = False
        for rule in self.rules:
            if(rule.matchUser(user) and rule.matchHost(host)):
                match = True
                for cmnd in rule.command:
                    if not csv_out:
                        print cmnd
                    else:
                        csv_writer.writerow([host, user, cmnd])
        if csv_out:
            stringIO.pos = 0
            print(stringIO.read())
        if not match and not csv_out:
            print "No matches - check spelling\n"

    def canRunCommand(self,user,command,host="localhost"):
        """
        Can the user run this particular command?
        """
        if(host=="localhost" or host==None):
            host=socket.gethostname()
        for rule in self.rules:
            if(rule.matchUser(user) and rule.matchHost(host)):
                for cmnd in rule.command:
                    if(cmnd.matchCommand(command)):
                        print "User %s can run command %s" % (user,command)
                        return True
        print "User %s can not run command %s" % (user,command)
        return False

    # given the contents of a user alias, see if it matches a particular user
    def matchUserAlias(self,userAlias, user):
        for entry in userAlias:
            if(entry == user):
                return True
            elif(entry[0] == "%"):
                return self._userInGroup(entry[1:],user)
            elif(entry[0] == "+"):
                return self._userInNetgroup(entry[1:],user)
        return False

    def matchHostAlias(self,hostAlias,host):
        for entry in hostAlias:
            if(entry == "ALL"):
                return True
            elif(entry.find(host) == 0):
                return True
            elif(entry[0] == '+'):
                return self._hostInNetgroup(entry[1:],host)
        return False

    def matchCmndAlias(self,cmndAlias,command):
        match = False
        for entry in cmndAlias:
            negate = False
            if(entry[0] == "!"):
                negate = True
                entry = entry[1:]
            if(entry.find(command) == 0):
                if(negate):
                    return False
                match = True
            if(os.path.normpath(entry) == os.path.dirname(command)):
                if(negate):
                    return False
                match = True
            if(entry == "ALL"):
                match = True
        return match

    def _userInGroup(self,group,user):
        try:
            (gr_name, gr_passwd, gr_gid, gr_mem) = grp.getgrnam(group)
        except KeyError:
#            print "warning: group %s was not found" % group
            return False
        if(user in gr_mem):
            return True

    def _userInNetgroup(self,group,searchUser):
        if(netgroupSupport):
            return netgroup.innetgr(group,user=searchUser)
        else:
            print self.netgroupWarning

    def _hostInNetgroup(self,searchNetgroup,searchHost):
        if(netgroupSupport):
            return netgroup.innetgr(searchNetgroup,host=searchHost)
        else:
            print self.netgroupWarning

    def _parseAlias(self,line,marker):
        res = {}

        aliasRE = re.compile("\s*%s\s*(\S+)\s*=\s*((\S+,?\s*)+)" % marker)
        m = aliasRE.search(line)
        if(m):
            alias = str(m.group(1))
            nodes = str(m.group(2)).split(",")
            nodes = [ node.strip() for node in nodes ]
            res[alias] = nodes

        return res

    def _parseLDIFAlias(self, line, marker):
        aliasRE = re.compile("^\s*%s: " % marker)
        return aliasRE.sub("", line).strip()

    def _parseLDIFOptions(self, line):
        passwd = True
        option = None

        optionRE = re.compile("^\s*sudoOption:\s*")

        m = optionRE.match(line)
        if (m):
            if "!authenticate" in optionRE.sub("", line):
                passwd = False
            else:
                option = optionRE.sub("",line).strip()

        return passwd, option

    def _parseLDIFRunas(self, line):
        runas = "ANY"
        runasRE = re.compile("^\s*sudoRunAs:\s*")
        m = runasRE.search(line)
        if (m):
            runas = runasRE.sub("", line).strip()
        return runas

    def _parseRule(self,line):
        sudo_rules = []

        ruleRE = re.compile("\s*(\S+)\s*(.*=.*)")
        runasRE = re.compile("^\s*\((\S+)\)(.*)")

        #remove the colon at the end of NOPASSWDs. Makes parsing easier.
        line = re.sub("NOPASSWD:", "NOPASSWD", line, 0)
        line = re.sub("PASSWD:", "PASSWD", line, 0)
        # line = re.sub("\([^:]+:[^:]+\)", "", line, 0)
        line = re.sub('\(([^:]+):([^:]+)\)', lambda n: '(' + n.group(1) + '*' +
                n.group(2) + ')', line, 0)

        m = ruleRE.search(line)
        if m:
            users = str(m.group(1))
            if ',' in users:
                users = users.split(',')
            else:
                users = [users]

            for user in users:
                for rule in str(m.group(2)).split(":"):
                    hosts, commands = rule.split("=")
                    parsedCommands = []
                    seenCommands = {}

                    #TODO: we should probably make SudoCmnd store a list of hosts.
                    for host in hosts.split(","):
                        host = host.strip()

                        cmnds = commands.split(",")
                        cmnds = [ cmnd.strip() for cmnd in cmnds ]
                        for cmnd in cmnds:
                            unparsed = cmnd
                            ra = runasRE.search(unparsed)
                            if ra:
                                runas = str(ra.group(1))
                                unparsed = str(ra.group(2))
                            else:
                                runas = "ANY"
                            pos = unparsed.find("PASSWD")
                            if pos > -1:
                                passwd = False
                                unparsed = unparsed[pos+len("PASSWD"):]
                            else:
                                passwd = True
                            unparsed = unparsed.strip()

                            if unparsed not in seenCommands.keys():
                                parsedCommands.append(SudoCmnd(runas,passwd,unparsed,self,self.options))
                                seenCommands[unparsed] = 1
                        sudo_rules.append(SudoRule(user,host,parsedCommands,self,self.options))
            return sudo_rules

    def _collapseLines(self,lines):
        res = []
        currentline = ""

        for line in lines:
            if(line.rstrip()[-1:] == "\\"):
                currentline += line.rstrip()[:-1]
            else:
                currentline += line
                res.append(currentline)
                currentline = ""

        return res

def createParser():
    parser = OptionParser(usage="%prog [options] -u user")
    parser.add_option("-f", "--file", dest="sudoersFile", metavar="FILE",
                      help="sudoers file to parser (default /etc/sudoers)", default="/etc/sudoers")
    parser.add_option("-s", "--host", dest="host", metavar="HOST",
                      help="host (default is this host)")
    parser.add_option("-u", "--user", dest="user", metavar="USER",
                      help="username to lookup (mandatory)")
    parser.add_option("-c", "--command", dest="command", metavar="COMMAND",
                      help="Instead of printing all commands, test whether this command can be run")
    parser.add_option("-C", "--csv", dest="csv_output", action="store_true",
                      help="CSV output")
    parser.add_option("-l", "--ldif", dest="ldif", action="store_true",
                      help="Print out the sudoers file in LDIF format")
    parser.add_option("--parse-ldif", dest="parse_ldif", action="store_true",
                      help="parse an LDIF file and output an equivalent sudoers file.")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
                      help="Increase verbosity. Provides debugging output")
    return parser

def main():
    parser = createParser()
    (options,args) = parser.parse_args()
    if not options.user and not options.ldif and not options.parse_ldif:
        parser.print_help()
        sys.exit(1)

    sp = SudoersParser(options)

    if options.parse_ldif:
        sp.parseLDIF(options.sudoersFile)
    else:
        sp.parseFile(options.sudoersFile)

    if(options.command):
        cmnd = options.command
        if(options.command.find('/') == -1):
            cmnd = commands.getstatusoutput('which %s' % options.command.split(" ")[0])[1]
        elif(options.command[0] != '/'):
            cmnd = os.path.normpath(os.path.join(os.getcwd(),options.command))
        if(sp.canRunCommand(options.user,cmnd,options.host)):

            sys.exit(0)
        else:
            sys.exit(1)
    elif options.user or options.host:
        sp.getCommands(options.user,options.host, options.csv_output)
    elif options.ldif:
        my_ldif = sp.getLDIF()

        counter = 0
        for x in my_ldif:
            print "dn: cn=CN_GOES_HERE_%s,ou=sudoers,ou=ENV_GOES_HERE,dc=example,dc=com" % counter
            print "cn: CN_GOES_HERE_%s" % counter
            for y in x:
                print y
            print "objectClass: sudoRole"
            print "objectClass: top"
            print "\n"
            counter += 1
    elif options.parse_ldif:
        my_sudoers = sp.getSudoers()
        for line in my_sudoers:
            print str(line)

if(__name__ == "__main__"):
    main()

