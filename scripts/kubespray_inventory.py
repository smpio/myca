#!/usr/bin/env python

from __future__ import print_function, division, absolute_import, unicode_literals
import os
import sys
import requests
import argparse

inventory_url = os.environ.get('INVENTORY_URL', 'http://localhost:5000/kubespray/vagrant.json?indent=2')


def main():
    parser = argparse.ArgumentParser(description="Dynamic Ansible Inventory script for consul cloud.")
    parser.add_argument('--list', action='store_true',
                        help='return a JSON hash/dictionary of all the groups to be managed')
    parser.add_argument('--host',
                        help='return a hash/dictionary of variables to make available to templates and playbooks')
    args = parser.parse_args()

    if bool(args.list) == bool(args.host):
        parser.error('either --list or --host should be specified')
        return

    sys.stdout.write(load(args))
    sys.stdout.write(b'\n')


def load(args):
    if args.host:
        return '{}'

    sys.stderr.write('Loading vars from MyCA\n')
    resp = requests.get(inventory_url)
    resp.raise_for_status()
    return resp.content


if __name__ == '__main__':
    main()
