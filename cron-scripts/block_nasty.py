#! /usr/bin/env python

#
# script for crontab to check for recent repeated [preauth] failures,
# and block corresponding IP addresses. See help() below.
#

from os import getenv,access,stat,chdir,system,R_OK
from re import compile,search
from sys import argv,exit,stdin,stdout,stderr,exc_info,excepthook
from datetime import datetime,timedelta
from collections import defaultdict
from gzip import open as gzopen

#
# globals
#

MONTHS=[ 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' ]
DT0=datetime.utcnow()


def auth_datetime(line):
    # e.g. May 16 06:51:02
    global DT0
    global MONTHS
    try:
        terms = line.split()
        month = MONTHS.index(terms[0]) + 1
        day = int(terms[1])
        hr,mi,se = map(int,terms[2].split(':'))
        year = DT0.year
        dt1 = datetime(year,month,day,hr,mi,se)
        if dt1 < DT0:
            dt1 -= timedelta(365)
        return dt1
    except:
        a,b,c = exc_info()
        stderr.write("Parse error in auth_stamp('{0:s}')\n".format(line.strip()))
        excepthook(a,b,c)
    return None

def datetime_stamp(dt = DT0):
    return int((dt - datetime(1970,1,1,0,0,0)).total_seconds())


def read_last(v=0):
    try:
        with open('.block_nasty.stamp','r') as sf:
            return int(sf.readline().strip())
    except:
        if v:
            a,b,c = exc_info()
            excepthook(a,b,c)
        return 0


def write_last():
    try:
        with open('.block_nasty.stamp','w') as sf:
            sf.write("{0:d}\n".format(datetime_stamp()))
    except:
        stderr.write("Warning: Failed to write stamp at .block_nasty.stamp\n")


X_authst = compile(r'^[A-Z][a-z][a-z] \d+ \d+:\d+:\d+')
X_ipaddr = compile(r'\d+\.\d+\.\d+\.\d+')


def count_nasty(fin,counts,last_stamp,v=0):
    global X_authst
    global X_ipaddr
    nlines,nmatched,npre,nmo,nir = 0,0,0,0,0

    for line in fin:
        nlines += 1
        line = line.strip()
        if len(line) < 9 or line[-9:] != '[preauth]': # only preauth failures
            continue
        npre += 1
        mo = X_authst.match(line)
        if not mo: # only stamped lines
            continue
        nmo += 1
        ir = search(X_ipaddr,line) 
        if not ir: # only with IPv4 address
            continue
        nir += 1
        try:
            ad = auth_datetime(mo.group(0))
            if ad is None:
                continue
            ds = datetime_stamp(ad)
        except:
            a,b,c = exc_info()
            stderr.write("group0: {0:s}\n".format(mo.group(0)))
            excepthook(a,b,c)
            pass
        if ds < last_stamp:
            continue
        nmatched += 1
        counts[ir.group(0)] += 1
    return nlines,nmatched,npre,nmo,nir


def block_ip(ip):
    return system('iptables -A INPUT -s '+ip+' -j DROP')


def help(args):
    stderr.write("""
Usage: {0:s} [-v] [-n] [N]
-v -- verbosity increment
-n -- dryrun (report IPs, no blocking)
N  -- integer failure count threshold precipitating a block

Default N is 8

{0:s} is intended to run from crontab.  It writes to ${HOME}/.block_nasty.stamp
the time-stamp when it last completed, and ignores logged [preauth] failures in
/var/log/auth.log (and its rolled versions) which predate the value of that stamp
at start-up. \n""".format(args[0]))
    return 1


def main(args):
    threshold = 8
    verbosity = 0
    dryrun = False
    for arg in args:
        if arg and arg[0].isdigit():
            threshold = int(arg)
        elif arg == '-n':
            dryrun = True
        elif arg and len(arg) > 1 and arg[:2] == '-v':
            verbosity += sum(1 for x in arg if x == 'v')
        else:
            return help()

    try:
        home = getenv('HOME')
        chdir(home)
    except:
        a,b,c = exc_info()
        stderr.write("Unable to chdir HOME\n")
        excepthook(a,b,c)
        exit(1)

    counts = defaultdict(int)
    nfiles = 0
    paths = [ "/var/log/auth.log.{0:d}".format(ii) for ii in xrange(9,-1,-1) ]
    paths.append("/var/log/auth.log")
    last_stamp = read_last(verbosity)

    for path in paths:
        na = -1
        if path[-1].isdigit() and \
           access(path+".gz",R_OK) and \
           int(stat(path+".gz").st_mtime) > last_stamp:
            with gzopen(path+'.gz','r') as gl:
                nfiles += 1
                nl,nm,np,nd,na = count_nasty(gl,counts,last_stamp)
        elif access(path,R_OK) and \
             int(stat(path).st_mtime) > last_stamp:
            with open(path,"r") as pl:
                nfiles += 1
                nl,nm,np,nd,na = count_nasty(pl,counts,last_stamp)
        if na > -1 and verbosity:
            stderr.write("{0:s} lines {1:d} matches {2:d} ({3:d} {4:d} {5:d})\n"
                         .format(path,nl,nm,np,nd,na))

    nblocks = 0
    for ip in counts.iterkeys():
        if int(counts[ip]) >= threshold:
            nblocks += 1
            if dryrun:
                stderr.write('block: '+ip+"\n")
            else:
                block_ip(ip)

    if verbosity:
        stderr.write("{0:d} files {1:d} addrs\n".format(nfiles,nblocks))

    write_last()

    return 0

if __name__ == '__main__':
    exit(main(argv))

