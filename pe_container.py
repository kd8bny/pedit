class PE_Container(object):

    _resource_type = {
        1:  'RT_CURSOR',
        2:  'RT_BITMAP',
        3:  'RT_ICON',
        4:  'RT_MENU',
        5:  'RT_DIALOG',
        6:  'RT_STRING',
        7:  'RT_FONTDIR',
        8:  'RT_FONT',
        9:  'RT_ACCELERATOR',
        10: 'RT_RCDATA',
        11: 'RT_MESSAGETABLE',
        12: 'RT_GROUP_CURSOR',
        14: 'RT_GROUP_ICON',
        16: 'RT_VERSION',
        17: 'RT_DLGINCLUDE',
        19: 'RT_PLUGPLAY',
        20: 'RT_VXD',
        21: 'RT_ANICURSOR',
        22: 'RT_ANIICON',
        23: 'RT_HTML',
        24: 'RT_MANIFEST'}

    def __init__(self, pe):
        super(PE_Container, self).__init__()
        self.pe = pe
        # Broad containers for loaded pe
        self.entries = {}
        self.entry_directories = {}

        # Actual resource selections
        self.entry = None
        self.directory = None
        self.resource_val = ""
        self.resource_val_new = ""
