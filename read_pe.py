"""Public module to read contents of portable exectutable."""
import sys
import os
import argparse
import pefile


class Read_PE(object):
    """Edit resources of given portable executable."""

    def __init__(self, pe_container):
        super(Read_PE, self).__init__()
        self.pec = pe_container
        self.pe = self.pec.pe

    def get_entry_points(self):
        """Parse through pe and returnes pefile resource entries."""
        entries = {entry.id: entry
                   for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries}

        return entries

    def get_entry_directories(self):
        """Parse directories for selected entry point."""
        directories = {}

        for dir_entry in self.pec.entry.directory.entries:
            # This will probably bite me in the ass. Multiple entries per dir?
            directories[dir_entry.id] = dir_entry.directory.entries[0]

        return directories

    def get_resource_val(self):
        """Return value at selected directory."""
        resource_val = list()

        data_rva = self.pec.directory.data.struct.OffsetToData
        data_size = self.pec.directory.data.struct.Size

        data = self.pe.get_memory_mapped_image()[data_rva:data_rva + data_size]
        offset = 0
        while True:
            # Exit once there's no more data to read
            if offset >= data_size:
                break

            str_length = self.pe.get_word_from_data(data[offset:offset + 2], 0)
            offset += 2

            if str_length == 0:
                continue

            str_data = self.pe.get_string_at_rva(data_rva + offset)
            offset += str_length*2
            resource_val.append(str_data)

        return resource_val[0]
