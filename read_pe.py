"""
"""
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
        entries = {entry.id: entry
                   for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries}

        return entries

    def get_entry_directories(self):
        directories = {}

        for dir_entry in self.pec.entry.directory.entries:
            # This will probably bite me in the ass. Multiple entries per dir?
            directories[dir_entry.id] = dir_entry.directory.entries[0]

        return directories

    def get_resource_val(self):
        resource_strings = list()

        data_rva = entry.directory.entries[0].data.struct.OffsetToData
        size = entry.directory.entries[0].data.struct.Size
        print('Directory entry at RVA', hex(data_rva), 'of size', hex(size))

        # Retrieve the actual data and start processing the strings
        #
        data = self.pe.get_memory_mapped_image()[data_rva:data_rva+size]
        offset = 0
        while True:
            # Exit once there's no more data to read
            if offset>=size:
              break
            # Fetch the length of the unicode string
            #
            ustr_length = self.pe.get_word_from_data(data[offset:offset+2], 0)
            offset += 2

            # If the string is empty, skip it
            if ustr_length==0:
              continue

            # Get the Unicode string
            #
            #ustr = self.pe.get_string_u_at_rva(data_rva+offset, max_length=ustr_length)
            ustr = self.pe.get_string_at_rva(data_rva+offset)
            offset += ustr_length*2
            strings.append(ustr)
            print('String of length', ustr_length, 'at offset', offset)


        print(strings[0].decode('ascii'))


    def main(self):

        for section in self.pe.sections:
            print(section.Name, hex(section.VirtualAddress),
            hex(section.Misc_VirtualSize), section.SizeOfRawData)

        # rt_string_directory = self.pe.DIRECTORY_ENTRY_RESOURCE.entries[10]
        # # For each of the entries (which will each contain a block of 16 strings)
        # #
        # for entry in rt_string_directory.directory.entries:
        #
        #     # Get the RVA of the string data and
        #     # size of the string data
        #     #
        #     data_rva = entry.directory.entries[0].data.struct.OffsetToData
        #     size = entry.directory.entries[0].data.struct.Size
        #     print('Directory entry at RVA', hex(data_rva), 'of size', hex(size))
        #
        #     # Retrieve the actual data and start processing the strings
        #     #
        #     data = self.pe.get_memory_mapped_image()[data_rva:data_rva+size]
        #     offset = 0
        #     while True:
        #         # Exit once there's no more data to read
        #         if offset>=size:
        #           break
        #         # Fetch the length of the unicode string
        #         #
        #         ustr_length = self.pe.get_word_from_data(data[offset:offset+2], 0)
        #         offset += 2
        #
        #         # If the string is empty, skip it
        #         if ustr_length==0:
        #           continue
        #
        #         # Get the Unicode string
        #         #
        #         #ustr = self.pe.get_string_u_at_rva(data_rva+offset, max_length=ustr_length)
        #         ustr = self.pe.get_string_at_rva(data_rva+offset)
        #         offset += ustr_length*2
        #         strings.append(ustr)
        #         print('String of length', ustr_length, 'at offset', offset)
        #
        #
        # print(strings[0].decode('ascii'))


if __name__ == '__main__':
    Read_PE().main()
