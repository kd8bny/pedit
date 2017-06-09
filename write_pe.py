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

        data_rva = self.pec.directory.data.struct.OffsetToData
        data_size = self.pec.directory.data.struct.Size

        data = self.pe.get_memory_mapped_image()[data_rva:data_rva + data_size]
        self.pe.set_bytes_at_rva(data_rva, bytes(self.pec.resource_val_new, 'utf-8'))

        self.pe.write(filename='new_file.exe')
