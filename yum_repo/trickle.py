#!/bin/env python

# This script is intended to be used for moving rpms from an 'upstream'
# repository to a 'downstream' repository. All it really does is some version
# comparisons and, if it detects a newer version, it copies the file from the
# source location to the destination location.

# Author: Brett Lentz

import optparse
import shutil
import sys
from libupdate import get_updates_list, get_updates_for_pkglist


def get_options():
    """ command-line options """

    usage = "usage: %prog [options] -s SRC -d DEST"
    OptionParser = optparse.OptionParser
    parser = OptionParser(usage)

    required = optparse.OptionGroup(parser, "Required")
    optional = optparse.OptionGroup(parser, "Optional")

    required.add_option("-d", "--dest-dir", action="store", type="string", \
        dest="dest", help="Directory containing older RPMs to be updated.")
    required.add_option("-s", "--src-dir", action="store", type="string", \
        dest="src", help="Directory containing newer RPMs to update from.")
    optional.add_option("-n", "--new", action="store_true", dest="include_newpkgs", \
        help="Include new packages. (i.e. packages that don't exist in the " \
        "destination)")
    optional.add_option("-p", "--pkgs", action="store", type="string", \
        dest="pkgs", help="Space-delimited list of package names to check " \
        "for updates. Note: uses globbing to match against \'*PKG*.rpm\'")
    optional.add_option("-t", "--test", action="store_true", dest="test", \
        help="Show what would happen, but don't alter the filesystem.")
    optional.add_option("-v", "--verbose", action="store_true", dest="verbose", \
        help="Increases verbosity.")

    parser.add_option_group(required)
    parser.add_option_group(optional)
    options, args = parser.parse_args()

    if not options.src or not options.dest:
        parser.print_help()
        sys.exit(-1);

    return options, args

def copy_file(src, dst):
    if options.test or options.verbose:
        print "Copying " + src + " to " + dst

    if not options.test:
        try:
            shutil.copy(src, dst)
        except IOError, err:
            print err

if  __name__ == "__main__":
    options, args = get_options()

    if options.pkgs:
        updates, newpkgs, srcdupes, destdupes = \
            get_updates_for_pkglist(options.pkgs.split(" "), options.src, \
                options.dest, options.verbose)
    else:
        updates, newpkgs, srcdupes, destdupes = get_updates_list(options.src, \
            options.dest, options.verbose)

    for pkg in updates:
        copy_file(options.src + "/" + updates[pkg]['pkg'], options.dest)

    if options.include_newpkgs:
        for pkg in newpkgs:
            copy_file(options.src + "/" + newpkgs[pkg]['pkg'], options.dest)

