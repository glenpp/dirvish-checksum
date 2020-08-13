#!/usr/bin/env python3
"""
version:  20200813
finds files in directory and MD5sums and SHA1sums them, being smart enough to
check against previous backup for hard links




Copyright (C) 2008-2019  Glen Pitt-Pladdy

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


See https://www.pitt-pladdy.com/blog/_20120412-224240_0100_dirvish-checksum_available_again/
"""


import re
import os
import stat
import lzma
import bz2
import gzip
import struct
import hashlib
import time
import sys

import pprint


# default config file
CONFIG = "/etc/dirvish/master.conf"

CHECKSUMS = [
    #'MD5SUMS',
    #'SHA1SUMS',
    #'SHA256SUMS',
    'SHA512SUMS',
]

READSIZE = 65536    # 64KiB
INDEX_SANITY_CHECK_PER = 20 # check 1 node in this many
INDEX_SANITY_CHECK_MIN = 100






class Vault(object):
    skip_checksum_types = ('symlink', 'device')

    def __init__(self, vault_path):
        """
        Args:
            vault_path (str): path to dirvish vault
        """
        self.vault_path = vault_path
        # look for days in backup
        self.days = []
        for day in os.scandir(self.vault_path):
            if not day.is_dir():
                continue
            if not os.path.isdir(os.path.join(day.path, 'tree')):
                continue
            self.days.append(day.path)
        self.days = sorted(self.days)
        # caches
        self._last_day = {}
        self._checksum_cache = {}
        self._last_stat = {}
        self._current_stat = None
        self._current_changed = {}

    def process(self):
        last_day = None
        for day in self.days:
            # see what checksum types we have
            existing_checksum = []
            for check in CHECKSUMS:
                # check for existing checksum files
                for compress in ['gz', 'bz2', 'xz']:
                    checkfile = os.path.join(day, '{}.{}'.format(check, compress))
                    if os.path.isfile(checkfile):
                        self._last_day[check] = {   # TODO is this used fully?
                            'day': day,
                            'check_file': checkfile,
                            'compress': compress,
                        }
                        existing_checksum.append(check)
                        break
            # see what checksum types we are missing
            missing_checksum = []
            for check in CHECKSUMS:
                if check not in existing_checksum:
                    missing_checksum.append(check)
            if not missing_checksum:
                # got all checksums this day - can't keep previous data as we need to load
                self._checksum_cache = {}
                self._last_stat = {}
                last_day = day
                continue
            # we do need a checksum
            print(day)
            print("\tReading index ....")
            self._current_stat = self._read_index(day)
            # pull in previous if needed
            if not bool(self._last_stat) and last_day is not None:
                print("\tReading previous index ....")
                self._last_stat = self._read_index(last_day)
                # we had to load a new stat therefore we can't depend on any checksums (just a precaution - it's also cleared above)
                self._checksum_cache = {}

            print("\tReading log ....")
            self._current_changed, self._current_deleted = self._read_log(day)

            total_updates = len(self._current_changed) + len(self._current_deleted)
            print("\tChange: {} / {} = {:.2f}%".format(total_updates, len(self._current_stat), float(total_updates) / len(self._current_stat) * 100))
            # process checksums needed
            for check in missing_checksum:
                # we need to create checksums
                self._checksum(day, check)
            # cycle for next time
            last_day = day
            self._last_stat = self._current_stat
            # remove stale cached checksums
            for check in existing_checksum:
                if check in self._checksum_cache:
                    del self._checksum_cache[check]


    # escaping #################################################################
    def _index_unescape(self, path):
        """unescape entries from dirvish index to native paths

        Args:
            path (str): dirvish index path of file
        Returns:
            str: utf-8 encoded filesystem path
        """
        # always turn into bytes for processing
        path = path.encode('utf-8')
        #$file =~ s/([^\\]) .*+$/$1/;	# clear everything after a real space
        if re.search(b'([^\\\\]) ', path):
            raise Exception("not implemented spaces in: {}".format(path))
        path = path.replace(b'\\ ', b' ')     # convert spaces
#        path = re.sub(r'\\"', '"', path)    # convert quotes
        if re.search(b'^\\\\"', path):
            raise NotImplementedError("not implemented \" in: {}".format(path))
        path = path.replace(b'\\n', b'\n')    # convert newlines
        path = path.replace(b'\\f', b'\f')    # convert form feed
        escapes = True
        while escapes:
            escapes = False
            # escapes in dirvish index is \ooo where ooo = octal
            match = re.match(b'^(.*)\\\\([0-7]{3})(.*)$', path)
            if match:
                escapes = True
                path = match.group(1)
                path += struct.pack('B', int(match.group(2), 8))
                path += match.group(3)
        path = path.replace(b'\\\\', b'\\') # convert remaining backslashes
        path = path.decode('utf-8')
        return path

    def _log_unescape(self, path):
        """unescape entries from dirvish log (rsync output) to native paths

        Args:
            path (str): dirvish log / rsync output path of file
        Returns:
            str: utf-8 encoded filesystem path
        """
        # always turn into bytes for processing
        path = path.encode('utf-8')
        escapes = True
        while escapes:
            escapes = False
            # escapes in rsync log is \#ooo where ooo = octal
            match = re.match(b'^(.*)\\\\#([0-7]{3})(.*)$', path)
            if match:
                escapes = True
                path = match.group(1)
                path += struct.pack('B', int(match.group(2), 8))
                path += match.group(3)
        path = path.decode('utf-8')
        return path

    def _checksum_escape(self, path, checksum):
        """escape entries from native paths to *sum output

        Args:
            path (str): native filesystem path of file
            checksum (str): hex checksum data
        Returns:
            str: *sum output escaped path of file
            str: checksum with leading backslash added when escaping is active
        """
        orig_path = path
        path = path.replace('\\', '\\\\')
        path = path.replace('\n', '\\n')
        if path != orig_path:
            checksum = '\\' + checksum
        return path, checksum

    def _checksum_unescape(self, path, checksum):
        """unescape entries from *sum output to native paths

        Args:
            path (str): *sum output escaped path of file
            checksum (str): hex checksum data with leading backslash when escaping is active
        Returns:
            str: native filesystem path of file
            str: checksum with leading backslash rmoved after decoding
        """
        if checksum[0] != '\\':
            # not escaped
            return path, checksum
        path = path.replace('\\n', '\n')
        path = path.replace('\\\\', '\\')
        return path, checksum[1:]



    def _checksum(self, day, check):
        # load past checksums
        if check not in self._checksum_cache:
            self._load_last_checksums(check)
        # remove out of date checksums
        for path in self._current_changed:
            # might be a socket or other file we don't look at
            if path in self._current_stat:
                inode = self._current_stat[path]['inode']
                # might be new file (no existing)
                if inode in self._checksum_cache[check]:
                    del self._checksum_cache[check][inode]
        for path in self._current_deleted:
            # might be a socket or other file we don't look at
            if path in self._last_stat:
                inode = self._last_stat[path]['inode']
                # might be hard linked and deleted on previous file
                if inode in self._checksum_cache[check]:
                    del self._checksum_cache[check][inode]
        # generate checksums
        time_start = time.time()
        read_bytes = 0
        print("\tGenerating {} ....".format(check))
        for path in self._current_stat:
            if self._current_stat[path]['type'] in self.skip_checksum_types:
                continue
            inode = self._current_stat[path]['inode']
            if inode in self._checksum_cache[check]:
                continue
            with open(os.path.join(day, 'tree', path), 'rb') as f_check:
                if check == 'SHA512SUMS':
                    checksum = hashlib.sha512()
                elif check == 'SHA256UMS':
                    checksum = hashlib.sha256()
                elif check == 'SHA1SUMS':
                    checksum = hashlib.sha1()
                elif check == 'MD5SUMS':
                    checksum = hashlib.md5()
                else:
                    raise ValueError("Unhandled hash: {}".format(check))
                while True:
                    data = f_check.read(READSIZE)
                    read_bytes += len(data)
                    if not data:
                        break
                    checksum.update(data)
                self._checksum_cache[check][inode] = checksum.hexdigest()
        time_elapsed = time.time() - time_start
        rate = float(read_bytes) / time_elapsed
        print("\t\t{:.1f} MiB in {:d} sec => {:.1f} MiB/s".format(float(read_bytes) / 1048576, int(time_elapsed), rate / 1048576))
        # write temp file
        print("\tWriting {} ....".format(check))
        checkfile = os.path.join(day, check + '.xz')
        with lzma.open(checkfile + '.TMP', 'wt') as f_sums:
            for path in self._current_stat:
                if self._current_stat[path]['type'] in self.skip_checksum_types:
                    continue
                inode = self._current_stat[path]['inode']
                escaped_path, escaped_checksum = self._checksum_escape(path, self._checksum_cache[check][inode])
                print('{}  {}'.format(escaped_checksum, escaped_path), file=f_sums)
        # rename temp file
        os.rename(checkfile + '.TMP', checkfile)
#        # done
#        self._last_day[check] = {'day': day, 'check_file': checkfile}






    def _load_last_checksums(self, check):
        """Load in previous day's checksum

        This takes the last day's file from self._last_day and reads checksums into self._checksum_cache indexed by inode

        :arg check: str, check type, ie. SHA512SUMS, ...
        """
        if check in self._last_day:
            # use previous checksums
            print("\tReading previous {} ....".format(os.path.basename(self._last_day[check]['check_file'])))
            if check not in self._checksum_cache:
                self._checksum_cache[check] = {}
            compress = {'xz': lzma, 'bz2': bz2, 'gz': gzip}[self._last_day[check]['compress']]
            with compress.open(self._last_day[check]['check_file'], 'rt') as f_sums:
                for line in f_sums:
                    checksum, path = line.split('  ', 1)
                    path = path.rstrip('\n')
                    if path.startswith('./'):
                        path = path[2:]
                    unescaped_path, unescaped_checksum = self._checksum_unescape(path, checksum)
                    self._checksum_cache[check][self._last_stat[unescaped_path]['inode']] = unescaped_checksum
        else:
            # no previous - start fresh
            self._checksum_cache[check] = {}



    def _read_index(self, day):
        """Read an index file into a dict of paths to properties

        :arg day: str, the day (directory) we are reading the log from
        :return: dict of dicts, keys of path and keys of property
        """
        # get top level path to be able to strip this
        tree = None
        with open(os.path.join(day, 'summary'), 'rt') as f_summary:
            for line in f_summary:
                if line.startswith('tree:'):
                    tree = line.split(':', 1)[1].strip()
                    break
        if tree is None:
            raise Exception("Can't find 'tree' in {}".format(os.path.join(day, 'summary')))
        # read index file
        index = {}
        sanity_check_per_count = 0
        sanity_check_total = 0
        sanity_check_fail = False
        with gzip.open(os.path.join(day, 'index.gz'), 'rt') as f_index:
            for line in f_index:
                line = line.lstrip(' ') # remove leading spaces
                line = line.rstrip('\n')
#                print(line)
                items = re.split(r' +', line, maxsplit=6)
                index_stat = {name: item for item, name in zip(items[:-1], ['inode', '512_blocks', 'mode', 'nlink', 'user', 'group'])}
                if index_stat['mode'][0] in ('c', 'b'):
                    # TODO is there something useful we can do with these?
                    items = re.split(r' +', items[-1], maxsplit=5)
                    items[0] = items[0].rstrip(',')
                    index_stat.update({name: item for item, name in zip(items, ['dev_major', 'dev_minor', 'month', 'day', 'time', 'path'])})
                    for name in ['dev_major', 'dev_minor']:
                        index_stat[name] = int(index_stat[name])
                    index_stat['type'] = 'device'
                elif index_stat['mode'][0] in ('s', 'p', 'd'):
                    # skip sockets TODO is there something useful we can do with these?
                    # skip pipes TODO is there something useful we can do with these?
                    # skip directories TODO is there something useful we can do with these?
                    # index_stat['type'] = 'socket'
                    # index_stat['type'] = 'pipe'
                    # index_stat['type'] = 'directory'
                    continue
                else:
                    # regular node
                    items = re.split(r' +', items[-1], maxsplit=4)
                    index_stat.update({name: item for item, name in zip(items, ['size', 'month', 'day', 'time', 'path'])})
                    for name in ['size']:
                        index_stat[name] = int(index_stat[name])
                    if index_stat['mode'][0] == '-':
                        index_stat['type'] = 'file'
                    elif index_stat['mode'][0] == 'l':
                        index_stat['path'], index_stat['symlink'] = index_stat['path'].split(' -> ', 1)
                        index_stat['symlink'] = self._index_unescape(index_stat['symlink'])
                        index_stat['type'] = 'symlink'
                    else:
                        raise NotImplementedError("Don't know how to handle mode[0] = {}".format(index_stat['mode'][0]))
                # convert to useful formats / types
                index_stat['path'] = self._index_unescape(index_stat['path'])
                index_stat['date'] = '{} {} {}'.format(index_stat['month'], index_stat['day'], index_stat['time'])
                del index_stat['month']
                del index_stat['day']
                del index_stat['time']
                for name in ['inode', '512_blocks', 'nlink']:
                    index_stat[name] = int(index_stat[name])
                if index_stat['path'] == os.path.join(day, 'tree'):
                    index_stat['path'] = '/'
                elif index_stat['path'].startswith(tree):
                    index_stat['path'] = index_stat['path'][len(tree):].lstrip('/')
                index[index_stat['path']] = index_stat
                # sanity check some
                sanity_check_per_count = (sanity_check_per_count + 1) % INDEX_SANITY_CHECK_PER
                if not sanity_check_fail and not sanity_check_per_count:
                    real_inode = os.lstat(os.path.join(day, 'tree', index_stat['path'])).st_ino
                    if index_stat['inode'] != real_inode:
                        print("\t\tsanity check fail: {}".format(index_stat['path']))
                        sanity_check_fail = True
                    sanity_check_total += 1
            # deal with sanity check problems
            if sanity_check_fail or sanity_check_total < INDEX_SANITY_CHECK_MIN:
                # need full reindex
                if sanity_check_fail:
                    print("\tRequire full reindex (sanity check fail)...")
                else:
                    print("\tRequire full reindex (sanity checks {} < min)...".format(sanity_check_total))
                for path, index_stat in index.items():
                    backup_path = os.path.join(day, 'tree', path.lstrip(os.sep))
                    real_stat = os.lstat(backup_path)
                    # not everything is safe to update - these should be
                    index_stat['inode'] = real_stat.st_ino  # we expect this to change
                    # sanity checks
                    if real_stat.st_size != index_stat.get('size', 0):
                        raise ValueError("real size != index size: {} != {}".format(real_stat.st_size, index_stat['size']))
                    if stat.filemode(real_stat.st_mode) != index_stat['mode']:
                        raise ValueError("real mode != index mode: {} != {}".format(stat.filemode(real_stat.st_mode), index_stat['mode']))
                    if stat.S_ISLNK(real_stat.st_mode):
                        if os.readlink(backup_path) != index_stat['symlink']:
                            raise ValueError("real symlink != index symlink: {} != {}".format(os.readlink(backup_path), index_stat['symlink']))

        # TODO sanity check by inode checks on a proportion
        #   TODO get all inodes & mtime if fail

        return index

    def _read_log(self, day):
        """Read in a dirvish log file and return changed (or added) & deleted paths

        :arg day: str, the day (directory) we are reading the log from
        :return: (change, deleted), dicts of changed (or added) and deleted paths, values set to True
        """
        changed = {}
        deleted = {}
        parse_running = False
        lines_running = []
        with gzip.open(os.path.join(day, 'log.gz'), 'rt') as f_log:
            for line in f_log:
                line = line.rstrip('\n')
                # we need to find where file start - once rsync starts sending/receiving
                if not parse_running:
                    lines_running.append(line)
                    if len(lines_running) >= 4:
                        if lines_running[-1] in ['sending incremental file list', 'receiving incremental file list'] and lines_running[-2] == '' and lines_running[-3].startswith('ACTION: rsync '):
                            parse_running = True
                    continue
                # we are running on files whish end with a blank line
                if line == '':
                    # end of file list
                    break
                # if 'deleting' is not prepended this is an addition/change
                if line.startswith('deleting '):
                    line = line.split(' ', 1)[1]
                    deleted[self._log_unescape(line)] = True
                else:
                    changed[self._log_unescape(line)] = True
        return changed, deleted




def main(argv):
    # read the master config
    banks = {}
    def readconfig(config_file):
        with open(config_file, 'rt') as f_conf:
            in_bank = False
            for line in f_conf:
                if line.startswith('bank:'):
                    in_bank = True
                    continue
                # strip comments
                line = line.split('#', 1)[0].rstrip()
                if in_bank and re.match(r'^\s', line):
                    banks[line.strip()] = True
                else:
                    in_bank = False
    if os.path.isfile(CONFIG):
        readconfig(CONFIG)
    if not bool(banks):
        raise Exception("No banks found in configs provided")

    # go through each vault in each bank
    for bank in banks:
        if not os.path.isdir(bank):
            print("Skipping bank not available: {}".format(bank))
            continue
        # look for vaults in this bank
        for vault in os.scandir(bank):
            if not vault.is_dir():
                continue
            if not os.path.isfile(os.path.join(vault.path, 'dirvish', 'default.conf')):
                continue
            # assess the backups in vault
            Vault(vault.path).process()


if __name__ == '__main__':
    main(sys.argv)

