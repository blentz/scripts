#!/bin/env python

# This is a collection of functions that was split off from the original update
# scanner. This code was needed for the other new tools for updating the
# yum repositories.

### TODO: This could be more OOP-y. Make it a class, add accessors, etc.
### I just don't care enough to do this right now.

# Author: Brett Lentz

import os
import rpm
import re

from fnmatch import fnmatch

def _build_rpmdict(rpmlist, dir=".", verbose=False):
    """ Scans through the given directory, extracts RPM headers from the files
    in the rpmlist. """

    rpmdict = {}
    dupes = {}
    for pkg in rpmlist:
        hdr = get_rpm_hdr(dir + "/" + pkg)

        # Ugh. Unsanitary repo. We'll try to make the best of it.
        # We're going to use whichever package rpm.labelCompare
        # deems is the "best".
        if rpmdict.has_key(hdr['name']):
            e1, v1, r1 = get_evr(hdr)
            e2, v2, r2 = get_evr(rpmdict[hdr['name']]['hdr'])

            # return 1: a is newer than b
            # 0: a and b are the same version
            # -1: b is newer than a
            if rpm.labelCompare((e1,v1,r1), (e2,v2,r2)) == 1:
                rpmdict[hdr['name']] = { "pkg" : pkg, "hdr" : hdr }
                if verbose:
                    print "WARNING! Duplicate package: %s. Using %s" % \
                        (hdr['name'], pkg)
            else:
                if verbose:
                    print "WARNING! Duplicate package: %s. Using %s" % \
                        (hdr['name'], rpmdict[hdr['name']]['pkg'])
            dupes[hdr['name']] = { "pkg" : pkg, "hdr" : hdr }
        else:
            rpmdict[hdr['name']] = { "pkg" : pkg, "hdr" : hdr }

    return rpmdict, dupes

def _compare_rpmlists(srclist, destlist, verbose=False):
    """ compares two lists of rpms, looking for new/updated rpms """

    updates = {}
    newpkgs = {}
    keys = srclist.keys()
    keys.sort()
    for pkg in keys:
        if verbose:
            print "DEBUG: Examining %s" % pkg

        if destlist.has_key(pkg):
            e1, v1, r1 = get_evr(srclist[pkg]['hdr'])
            e2, v2, r2 = get_evr(destlist[pkg]['hdr'])

            # return 1: a is newer than b
            # 0: a and b are the same version
            # -1: b is newer than a
            if rpm.labelCompare((e1,v1,r1), (e2,v2,r2)) == 1:
                if verbose:
                    print "INFO: " \
                        "Update found: %s - s(%s, %s, %s) d(%s, %s, %s)" % \
                        (pkg, e1, v1, r1, e2, v2, r2)
                updates[pkg] = srclist[pkg]
        else:
            if verbose:
                e1 = str(srclist[pkg]['hdr']['epoch'])
                v1 = str(srclist[pkg]['hdr']['version'])
                r1 = str(srclist[pkg]['hdr']['release'])
                print "INFO: New package found: %s (%s, %s, %s)" % \
                    (pkg, e1, v1, r1)
            newpkgs[pkg] = srclist[pkg]
    return updates, newpkgs

def _get_rpm_list(dir, verbose=False):
    """ fetches RPM header data from any packages in a given directory """

    filelist = os.listdir(dir)
    rpmlist = []
    for file in filelist:
        if re.compile("\.rpm$").search(file):
            rpmlist.append(file)

    if verbose:
        print "INFO: reading %s" % (dir)

    rpmdict, dupes = _build_rpmdict(rpmlist,dir,verbose)
    return rpmdict, dupes

def _get_rpm_list_for_pkg(name, dir, verbose=False):
    """ fetches RPM header data for the named package in a given directory """
    filelist = os.listdir(dir)
    rpmlist = []
    for file in filelist:
        if re.compile("\.rpm$").search(file) and \
                fnmatch(file, "*"+name+"*"):
            rpmlist.append(file)

    if verbose:
        print "INFO: reading %s" % (dir)

    rpmdict, dupes = _build_rpmdict(rpmlist,dir,verbose)
    return rpmdict, dupes

def get_rpm_hdr(filename):
        try:
            fdno = os.open(filename, os.O_RDONLY)
        except IOError, (errno, strerror):
            print "Unable to open dir %s: %s" % (dir, strerror)
            sys.exit(-1)

        ts = rpm.TransactionSet()
        ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
        hdr = ts.hdrFromFdno(fdno)
        os.close(fdno)
        return hdr

def get_evr(hdr):
    """ return epoch, version, release from rpm header """
    try:
        e = str(hdr['epoch'])
        v = str(hdr['version'])
        r = str(hdr['release'])
        return e, v, r
    except KeyError:
        print "KEYERROR: "
        print hdr.keys()
        raise

def get_updates_list(src, dest, verbose=False):
    """ Given a source and a destination, compare all of the rpms in the two
    directories, and compile four pieces of information:
        1. packages in destination that have updates in source
        2. packages in source that do not exist in destination (i.e. are new
        to destination)
        3. duplicate packages in source (e.g. foo-1.0.1-1 and foo-1.0.1-2)
        4. duplicate packages in destination.
        """
    srclist, srcdupes = _get_rpm_list(src,verbose)
    destlist, destdupes = _get_rpm_list(dest,verbose)

    if verbose:
        print "DEBUG: srclist: %s" % srclist.keys().sort()
        print "DEBUG: destlist: %s" % destlist.keys().sort()

    updates, newpkgs = _compare_rpmlists(srclist,destlist,verbose)
    return updates, newpkgs, srcdupes, destdupes

def get_updates_for_pkg(name, src, dest, verbose=False):
    """ given the name of a package, check src directory for newer versions of
    the package that don't exist in the dest directory.
    """

    srclist, srcdupes = _get_rpm_list_for_pkg(name,src,verbose)
    destlist, destdupes = _get_rpm_list_for_pkg(name,dest,verbose)

    if verbose:
        print "DEBUG: srclist: %s" % srclist.keys().sort()
        print "DEBUG: destlist: %s" % destlist.keys().sort()

    updates, newpkgs = _compare_rpmlists(srclist,destlist,verbose)
    return updates, newpkgs, srcdupes, destdupes

def get_updates_for_pkglist(pkglist, src, dest, verbose=False):
    """ given a list of packages, check src directory for newer versions of all
    packages in the list that don't exist in the dest directory.
    """

    _srclist = {}
    _srcdupes = {}
    _destlist = {}
    _destdupes = {}

    for name in pkglist:
        srclist, srcdupes = _get_rpm_list_for_pkg(name,src,verbose)
        destlist, destdupes = _get_rpm_list_for_pkg(name,dest,verbose)
        # merge the dicts. this is a lossy operation. hopefully we've
        # identified any dupes by this point.
        _srclist.update(srclist)
        _srcdupes.update(srcdupes)
        _destlist.update(destlist)
        _destdupes.update(destdupes)

    updates, newpkgs = _compare_rpmlists(_srclist, _destlist, verbose)
    return updates, newpkgs, _srcdupes, _destdupes

def get_deps(filename):
    """ retrieve dependencies for a given rpm """

    hdr = get_rpm_hdr(filename)
    return hdr.dsOfHeader()
