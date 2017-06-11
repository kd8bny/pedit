#!/usr/bin/env python3
"""
Pedit, portable executable resource editor.

The peedit python application starts the interactive session to allow the user
to select the desired resource to edit and provide means to edit resources.

Pedit makes use of the pefile module and utilizes many data structures of such.

When loaded, pedit with instantiate a pe container which will contain the pe
object, chosen resources and respective values.
"""
import sys
import os
import argparse
import pefile
import tempfile
import subprocess

from pe_container import PE_Container
from read_pe import Read_PE
from write_pe import Write_PE


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
        parser.add_argument(
            "-i", "--insert", help="Insert a given file \
            into a resource directory")
        parser.add_argument(
            "-f", "--fast-load", action="store_true", help="Load large PEs \
            faster by not not parsing all directories")
        parser.add_argument("--version", action="store_true", help="Version \
            information")

        return parser.parse_args()

    def get_resource_type(self):
        """Start interactive chooser to display resource types."""
        while True:
            print("The available resource types are:\n")
            for type_id in self.pec.entries:
                print("{0}) {1}".format(
                    type_id, self.pec._resource_type[type_id]))
            selection = int(input("\nplease enter an id to edit: "))

            if selection in self.pec.entries:
                return self.pec.entries[selection]

    def get_resource_directory(self):
        """Start interactive chooser to display resource directories."""
        print("The available resources locations:\n")
        for dir_id in self.pec.entry_directories:
            print("{0}) size of {1} bytes".format(
                dir_id, self.pec.entry_directories[dir_id].data.struct.Size))
        selection = int(input("\nplease enter an id to view/edit: "))

        if selection in self.pec.entry_directories:
            return self.pec.entry_directories[selection]

    def edit_string_resource(self):
        """Open editor to allow changing resource strings."""
        EDITOR = os.environ.get('EDITOR', 'vi')

        with tempfile.NamedTemporaryFile(suffix=".tmp") as temp_file:
            temp_file.write(self.pec.resource_val)
            temp_file.flush()
            subprocess.run([EDITOR, temp_file.name])

            temp_file.seek(0)
            resource_val_new = temp_file.read()

            if resource_val_new == self.pec.resource_val:
                sys.exit("\nResource was not changed. Exiting\n")
            else:
                return resource_val_new

    def insert_resource(self, filename):
        if not os.path.isfile(filename):
            sys.exit("Supplied file to insert does not exist.")

        data_size = self.pec.directory.data.struct.Size
        with open(filename, 'rb') as insert_file:
            f = insert_file.read()
            bfile = bytes(f)
            if len(bfile) > data_size:
                sys.exit("File is too large to insert into this resource")

            return bfile

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
        read_pe = Read_PE(self.pec)
        write_pe = Write_PE(self.pec)

        self.pec.entries = read_pe.get_entry_points()
        self.pec.entry = self.get_resource_type()
        self.pec.entry_directories = read_pe.get_entry_directories()
        self.pec.directory = self.get_resource_directory()
        self.pec.resource_val = read_pe.get_resource_val()

        if args.insert is None:
            self.pec.resource_val_new = self.edit_string_resource()
        else:
            self.pec.resource_val_new = self.insert_resource(args.insert)

        write_pe.set_resource_val()
        filename = input("\nNew Filename:")
        write_pe.write_executable(filename)


if __name__ == '__main__':
    PEdit().main()
