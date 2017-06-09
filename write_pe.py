"""
"""
import sys
import os
import argparse
import pefile


class Write_PE(object):
    """Write resources of given portable executable."""

    def __init__(self, pe_container):
        super(Write_PE, self).__init__()
        self.pec = pe_container
        self.pe = self.pec.pe

    def set_resource_val(self):

        data_rva = self.pec.directory.data.struct.OffsetToData + 2
        data_size = self.pec.directory.data.struct.Size

        resource = bytes(self.pec.resource_val_new, 'utf-8')
        empty_space = data_size - len(resource)
        resource += b'\0' * empty_space
        self.pe.set_bytes_at_rva(data_rva, resource)

    def write_executable(self, filename):
        self.pe.write(filename=filename)
