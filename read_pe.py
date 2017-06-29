"""Public module to read contents of portable exectutable."""


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

        data_rva = self.pec.directory.data.struct.OffsetToData
        data_size = self.pec.directory.data.struct.Size

        data = self.pe.get_memory_mapped_image()[data_rva:data_rva + data_size]

        return data
