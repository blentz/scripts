#!/bin/env python

# This script is intended to allow a fast way to mass-update cobbler's
# mgmt_classes.

import optparse
import xmlrpclib
import sys

from copy import deepcopy
from getpass import getpass


def get_options():
    """ command-line options """

    usage = "usage: %prog [options]"
    OptionParser = optparse.OptionParser
    parser = OptionParser(usage)

    parser.add_option("-a", "--add", action="store", type="string", \
            dest="additions", help="Add or insert these classes (space delimited) into all systems or profiles")
    parser.add_option("-d", "--delete", action="store", type="string", \
            dest="deletes", help="delete these classes (space delimited) from all systems or profiles")
    parser.add_option("--host", action="store", type="string", \
            dest="host", help="Change only a single host.")
    parser.add_option("-p", "--password", action="store", type="string", \
            dest="password", help="Password to log into cobbler.")
    parser.add_option("--profile", action="store", type="string", \
            dest="profile", help="Change only a single profile.")
    parser.add_option("--newname", action="store", type="string", \
            dest="newname", help="New name for class specified by --rename")
    parser.add_option("-r", "--rename", action="store", type="string", \
            dest="rename", help="Rename a single class. Requires --newname")
    parser.add_option("-s", "--server", action="store", type="string", \
            dest="server", help="Cobbler server.")
    parser.add_option("-t", "--test", action="store_true", dest="test_only", \
            help="Test changes. Show what would change. (Doesn't require auth)")
    parser.add_option("-u", "--username", action="store", type="string", \
            dest="username", help="Username to log into cobbler.")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", \
            help="Increase verbosity. Print additional information.")

    options, args = parser.parse_args()

    # XXX: ugh. brute force method of showing the help text if no options are set
    if len(args) < 1 and not options.additions \
            and not options.deletes and not options.host \
            and not options.password and not options.profile \
            and not options.newname and not options.rename \
            and not options.server and not options.test_only \
            and not options.username and not options.verbose:
       parser.print_help()
       sys.exit(-1)

    if options.rename and not options.newname:
        print "Rename requires --newname"
        sys.exit(-1)

    if not options.test_only:
        sys.stderr.write("Warning: username and password are required for" + \
                "making changes to Cobbler.\n")
        if not options.username:
            options.username = raw_input('Username: ')
        if not options.password:
            options.password = getpass()

    if not options.server:
        options.server = "localhost"

    return options, args

def __pre(obj):
    if options.test_only or options.verbose:
        print "Name: %s" % obj['name']
        print "Current value: %s" % obj['mgmt_classes']
    return check_inherited(obj)

def __post(obj):
    if options.test_only or options.verbose:
        print "New value: %s" % obj['mgmt_classes']

def extend_classes(obj):
    if __pre(obj):
        classes = options.additions.split(" ")
        obj['mgmt_classes'].extend(classes)
        __post(obj)

def rename_classes(obj):
    if __pre(obj):
        if options.rename in obj['mgmt_classes']:
            obj['mgmt_classes'].remove(options.rename)
            obj['mgmt_classes'].append(options.newname)
        __post(obj)

def delete_classes(obj):
    if __pre(obj):
        classes = options.deletes.split(" ")
        for clazz in classes:
            if clazz in obj['mgmt_classes']:
                obj['mgmt_classes'].remove(clazz)
        __post(obj)

def check_inherited(obj):
    if "<<inherit>>" in obj['mgmt_classes']:
        sys.stderr.write("Warning: unable to make changes to %s. Inherited.\n" \
                % obj['name'])
        return False
    return True

if  __name__ == "__main__":
    options, args = get_options()

    url = "http://%s/cobbler_api" % options.server

    try:
        server = xmlrpclib.Server(url)
        server.ping()
    except:
        traceback.print_exc()
        sys.exit(-1)

    if not options.test_only:
        token = server.login(options.username,options.password)

        if not token:
            sys.stderr.write("Error obtaining auth token.\n")
            sys.exit(-1)

    if options.verbose:
        print "Token: " + token

    # Profiles loop.
    if not options.host:
        profiles = server.get_profiles()
        for profile in profiles:
            orig_profile = deepcopy(profile)

            if not options.test_only:
                handle = server.get_profile_handle(profile['name'],token)

                if not handle:
                    sys.stderr.write("Error obtaining handle on %s.\n" \
                            % profile['name'])
                    sys.exit(-1)

            if options.verbose:
                print "Handle: " + handle

            if options.additions:
                if options.profile and options.profile not in profile['name']:
                    continue
                else:
                    extend_classes(profile)
            elif options.rename and options.newname:
                if options.profile and options.profile not in profile['name']:
                    continue
                else:
                    rename_classes(profile)
            elif options.deletes:
                if options.profile and options.profile not in profile['name']:
                    continue
                else:
                    delete_classes(profile)

            if orig_profile['mgmt_classes'] != profile['mgmt_classes'] and not options.test_only:
                try:
                    ret = server.modify_profile(handle, "mgmt_classes", \
                            profile['mgmt_classes'], token)

                    if options.verbose:
                        print "Modify result: " + str(ret)

                    ret = server.save_profile(handle, token)

                    if options.verbose:
                        print "Save result: " + str(ret)
                except xmlrpclib.Fault as err:
                    sys.stderr.write("Error: %s\n" % err.faultString)

            # add some white-spacing between each spin through the loop.
            if options.verbose or options.test_only:
                print ""

    # Systems loop.
    if not options.profile:
        systems = server.get_systems()
        for system in systems:
            orig_system = deepcopy(system)

            if not options.test_only:
                handle = server.get_system_handle(system['name'],token)

                if not handle:
                    sys.stderr.write("Error obtaining handle on %s.\n" \
                            % profile['name'])
                    sys.exit(-1)

            if options.verbose:
                print "Handle: " + handle

            if options.additions:
                if options.host and options.host not in system['name']:
                    continue
                else:
                    extend_classes(system)
            elif options.rename and options.newname:
                if options.host and options.host not in system['name']:
                    continue
                else:
                    rename_classes(system)
            elif options.deletes:
                if options.host and options.host not in system['name']:
                    continue
                else:
                    delete_classes(system)

            if orig_system['mgmt_classes'] != system['mgmt_classes'] and not options.test_only:
                try:
                    ret = server.modify_system(handle, "mgmt_classes", \
                            system['mgmt_classes'], token)

                    if options.verbose:
                        print "Modify result: " + str(ret)

                    ret = server.save_system(handle, token)

                    if options.verbose:
                        print "Save result: " + str(ret)
                except xmlrpclib.Fault as err:
                    sys.stderr.write("Error: %s\n" % err.faultString)

            # add some white-spacing between each spin through the loop.
            if options.verbose or options.test_only:
                print ""


