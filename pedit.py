#!/usr/bin/env python3

import sys
import os
import argparse
import pefile
from datetime import datetime

from pe_container import PE_Container
from read_pe import Read_PE


class PEdit(object):
    """Edit resources of given portable executable."""

    _version = "1.0.0"

    def __init__(self):
        super(PEdit, self).__init__()
        self.pec = None

    @staticmethod
    def get_args():
        """Take a look at those args."""
        parser = argparse.ArgumentParser(description='Utility designed to \
            edit resources at a given offset of a portable executable')
        parser.add_argument("file", help="path to portable executable")
        parser.add_argument("-f", "--fast-load", action="store_true", help=" prevent parsing the directories. In large PE files this can make loading significantly faster ")
        parser.add_argument("--version", action="store_true", help="Version \
            information")

        return parser.parse_args()

    def get_resource_type(self):
        while True:
            print("The available resource types are:\n")
            for type_id in self.pec.entries:
                print("{0}) {1}".format(type_id, self.pec._resource_type[type_id]))
            selection = int(input("\nplease enter an id to edit: "))

            if selection in self.pec.entries:
                return self.pec.entries[selection]

    def get_resource_directory(self):
        print("The available resources locations:\n")
        for dir_id in self.pec.entry_directories:
            print("{0}) size of {1} bytes".format(
                dir_id, self.pec.entry_directories[dir_id].data.struct.Size))
        selection = int(input("\nplease enter an id to view/edit: "))


    def main(self):
        """Start the interactive session for PEdit."""
        print("Welcome to PEdit by kd8bny {}\n\n".format(self._version))

        args = self.get_args()

        if args.version:
            sys.exit(_version)

        if not os.path.isfile(args.file):
            sys.exit("Supplied pe is not a correct file or location")

        pe = pefile.PE(args.file, fast_load=args.fast_load)
        self.pec = PE_Container(pe)
        readpe = Read_PE(self.pec)
        # writepe

        self.pec.entries = readpe.get_entry_points()
        self.pec.entry = self.get_resource_type()
        self.pec.entry_directories = readpe.get_entry_directories()
        self.get_resource_directory()
        self.pec.resource_val = readpe.get_resource_val()

        readpe.main()


if __name__ == '__main__':
    PEdit().main()
