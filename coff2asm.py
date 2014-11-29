#!/usr/bin/env python3
"""
Utility to read a MIPS COFF file and dump it in an assembly language
format that can be loaded into the MARS simulator.

Ultimately derived from code taken from the NACHOS operating system
project, original C/C++ version by Tom Anderson (Berkeley),
Java port by Peter Druschel (Rice University), and subsequent rewriting
and extension by Eugene Stark (Stony Brook University). Port of tool from java
to python3 by Paul Campbell.

Copyright (c) 1992-1993 The Regents of the University of California.
Copyright (c) 1998 Rice University.
Copyright (c) 2003-2014 State University of New York at Stony Brook.
All rights reserved.  See the COPYRIGHT file for copyright notice and
limitation of liability and disclaimer of warranty provisions.

@author Paul Campbell
"""
import argparse
import sys
import os
import struct


class Section(object):

    """
    Object for storing information about the different sections in a COFF file.
    """

    def __init__(self):
        self.name = ""
        self.physical_address = 0
        self.size = 0
        self.data = []
        self.scnptr = 0


class CoffFile(object):

    MIPSELMAGIC = 0x0162
    OMAGIC = 0x107
    SOMAGIC = 0x0701

    SIZE_SHORT = 2
    SIZE_INTEGER = 4

    def __init__(self, coff_file):
        """Read in and parse a COFF file"""
        self.sections = []
        self.coff_file = coff_file
        self.parse(coff_file)

    def parse(self, input_file):
        """
        Read in and parse the COFF file format.
        @param input_file Binary file to parse.
        @return Returns True if the file was successfully parsed, else False.
        """
        exists = os.path.isfile(input_file)
        if exists:
            in_file = open(input_file, "r+b")
            # Read in COFF file header
            file_header = self.read_coff_header(in_file)
            Log.success(file_header)
            # Read in COFF OMAGIC system header
            # TODO: This pretty much validates the OMAGIC format
            omagic_header = self.read_system_header(in_file)
            Log.success(omagic_header)
            # Start reading sections
            for section in range(0, file_header['sections']):
                self.sections.append(self.read_section(in_file, section))
            # Populate section data
            for section in self.sections:
                in_file.seek(section.scnptr)
                section.data = in_file.read(section.size)

    def read_coff_header(self, input_file):
        """
        Parses the COFF file header format.

        File header
        COFF File header
        +-------------+------------------------------------------+
        |     Range   |   Meaning                                |
        +-------------+------------------------------------------+
        | [0,2)       | Machine - MIPSELMAGIC Number             |
        +-------------+------------------------------------------+
        | [2,4)       | Number of sections                       |
        +-------------+------------------------------------------+
        | [4,8)       | time & date stamp                        |
        +-------------+------------------------------------------+
        | [8,12)      | symbol table pointer; 0 if none-present  |
        +-------------+------------------------------------------+
        | [12,16)     | Number of symbols                        |
        +-------------+------------------------------------------+
        | [16,18)     | sizeof(optional header); Required for    |
        |             | executables but not .o files             |
        +-------------+------------------------------------------+
        | [18,20)     | flags                                    |
        +-------------+------------------------------------------+
        """
        # Read in the magic number
        magic_number = self.read_short(input_file)
        if magic_number != CoffFile.MIPSELMAGIC:
            Log.error("Invalid magic number: 0x{:04x}, expected 0x{:04x}"
                      .format(magic_number, CoffFile.MIPSELMAGIC))
            raise Exception("Invalid magic number: 0x{:04x}, expected 0x{:04x}"
                            .format(magic_number, CoffFile.MIPSELMAGIC))
        else:
            Log.info("MIPSEL magic number: 0x{:04x}".format(magic_number))
        # Next figure out how many sections there is
        section_count = self.read_short(input_file)
        Log.info("Coff files contains {} sections.".format(section_count))
        # Read the timestamp
        timestamp = self.read_int(input_file)
        Log.info("Timestamp: {}".format(timestamp))
        # File pointer to symbolic header
        ptr_symbol_table = self.read_int(input_file)
        Log.info("Symbol table ptr: 0x{:08x}".format(ptr_symbol_table))
        # Number of symbols in the symbol table
        number_of_symbols = self.read_int(input_file)
        Log.info("Number of symbols: {}".format(number_of_symbols))
        # Size of optional header
        sizeof_optional_header = self.read_short(input_file)
        Log.info("sizeof(optional header): {} bytes"
                 .format(sizeof_optional_header))
        # Flags
        flags = self.read_short(input_file)
        Log.info("Flags: 0x{:04x}".format(flags))
        return {'magic_number': magic_number, 'sections': section_count,
                'timestamp': timestamp, 'symbol_table_ptr': ptr_symbol_table,
                'symbols': number_of_symbols,
                'optional_hdr_size': sizeof_optional_header, 'flags': flags}

    def read_system_header(self, input_file):
        """
        Reads the optional header which is 56 bytes.

        Optional Header
        OMAGIC - Impure format (56-bytes)
        +-------------+------------------------------------------+
        |     Range   |   Meaning                                |
        +-------------+------------------------------------------+
        | [0,2)       | OMAGIC Number                            |
        +-------------+------------------------------------------+
        | [2,4)       | version number                           |
        +-------------+------------------------------------------+
        | [4,8)       | size of .text in bytes                   |
        +-------------+------------------------------------------+
        | [8,12)      | size of .data (initialized) in bytes     |
        +-------------+------------------------------------------+
        | [12,16)     | size of .bss (uninitialized) in bytes    |
        +-------------+------------------------------------------+
        | [16,20)     | entry point; runtime start address       |
        +-------------+------------------------------------------+
        | [20,24)     | Base of .text used for this file         |
        +-------------+------------------------------------------+
        | [24,28)     | Base of .data used for this file         |
        +-------------+------------------------------------------+
        | [28,32)     | Base of .bss used for this file          |
        +-------------+------------------------------------------+
        | [32,36)     | General purpose register mask            |
        +-------------+------------------------------------------+
        | [36,40)     | co-processor register mask               |
        +-------------+------------------------------------------+
        | [40,44)     | co-processor register mask               |
        +-------------+------------------------------------------+
        | [44,48)     | co-processor register mask               |
        +-------------+------------------------------------------+
        | [48,52)     | co-processor register mask               |
        +-------------+------------------------------------------+
        | [52,56)     | gp value used for this object            |
        +-------------+------------------------------------------+
        """
        # Extract the magic number
        magic_number = self.read_short(input_file)
        if magic_number != CoffFile.OMAGIC:
            Log.error("Invalid magic number: 0x{:04x}, expected 0x{:04x}"
                      .format(magic_number, CoffFile.OMAGIC))
            raise Exception("Invalid magic number: 0x{:04x}, expected 0x{:04x}"
                            .format(magic_number, CoffFile.OMAGIC))
        else:
            Log.info("OMAGIC magic number: 0x{:04x}".format(magic_number))
        # Extract the version number
        version_number = self.read_short(input_file)
        Log.info("Version number: 0x{:04x}".format(version_number))
        # Extract the text size in bytes
        text_size = self.read_int(input_file)
        Log.info(".text is {} bytes".format(text_size))
        # TODO: Just skype next 12 sections
        Log.warn("Skipping next 48 bytes (12 4-byte ints)")
        for i in range(0, 12):
            Log.info("0x{:08x}".format(self.read_int(input_file)))
        return {'magic_number': magic_number, 'version_number': version_number,
                'text_size': text_size}

    def read_section(self, input_file, section):
        """
        Section Header

        +-------------+------------------------------------------+
        |     Range   |   Meaning                                |
        +-------------+------------------------------------------+
        | [0,8)       | Section Name                             |
        +-------------+------------------------------------------+
        | [8,12)      | Physical Address                         |
        +-------------+------------------------------------------+
        | [12,16)     | Virtual Address                          |
        +-------------+------------------------------------------+
        | [16,20)     | Section size in bytes                    |
        +-------------+------------------------------------------+
        | [20,24)     | File offset to the section data          |
        +-------------+------------------------------------------+
        | [24,28)     | File offset to the Relocation table      |
        +-------------+------------------------------------------+
        | [28,32)     | File offset to the line number table     |
        +-------------+------------------------------------------+
        | [32,34)     | Number of relocation table entries       |
        +-------------+------------------------------------------+
        | [34,36)     | Number of line number table entries      |
        +-------------+------------------------------------------+
        | [36,40)     | Flags                                    |
        +-------------+------------------------------------------+
        """
        section = Section()
        # Extract the section name
        section_name = self.read_section_name(input_file)
        Log.info('Section name: {}'.format(section_name))
        # Extract the physcial address
        physical_address = self.read_int(input_file)
        Log.info('Physical address: 0x{:08x}'.format(physical_address))
        # Extract the virtual address
        virtual_address = self.read_int(input_file)
        Log.info('Virtual address: 0x{:08x}'.format(virtual_address))
        # Extract the section size
        section_size = self.read_int(input_file)
        Log.info('The {} section is {} bytes'
                 .format(section_name, section_size))
        # Extract the offset of the section data
        section_data_offset = self.read_int(input_file)
        Log.info('Section data offset: 0x{:08x}'.format(section_data_offset))
        # Extract the offset of the Relocation Table
        relocation_table_offset = self.read_int(input_file)
        Log.info('Relocation table offset: 0x{:08x}'
                 .format(relocation_table_offset))
        # Extract the offset of the line number table
        lineno_table_offset = self.read_int(input_file)
        Log.info('Line number table offset: 0x{:08x}'
                 .format(lineno_table_offset))
        # Extract the number of relocation table entries
        relocation_table_entries = self.read_short(input_file)
        Log.info('Relocation table entries: {}'
                 .format(relocation_table_entries))
        # Extract the number of relocation table entries
        lineno_table_entries = self.read_short(input_file)
        Log.info('Line number table entries: {}'
                 .format(lineno_table_entries))
        # Extract the flags
        flags = self.read_int(input_file)
        Log.info('Flags: 0x{:08x}\n'.format(flags))
        # Save everything in the section object
        section.name = section_name
        section.physical_address = physical_address
        section.size = section_size
        section.scnptr = section_data_offset
        return section

    def read_short(self, input_file):
        """Helper function for reading LE 2-byte short values"""
        return struct.unpack('<H', input_file.read(CoffFile.SIZE_SHORT))[0]

    def read_int(self, input_file):
        """Helper function for reading LE 4-byte int values"""
        return struct.unpack('<I', input_file.read(CoffFile.SIZE_INTEGER))[0]

    def read_section_name(self, input_file):
        """Helper function for reading Strings from byte values"""
        c_string = struct.unpack('8s', input_file.read(8))[0]
        section_name = ''
        for c in c_string:
            section_name += chr(c)
        return section_name


class Log(object):

    """Simple utility class for printing warnings."""

    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARN = '\033[93m'
    ERROR = '\033[91m'
    ENDC = '\033[0m'

    LOGGING_ENABELED = True

    @staticmethod
    def warn(msg):
        """Print warning message."""
        if Log.LOGGING_ENABELED:
            print("{}{}{}".format(Log.WARN, msg, Log.ENDC))

    @staticmethod
    def error(msg):
        """Print error message."""
        if Log.LOGGING_ENABELED:
            print("{}{}{}".format(Log.ERROR, msg, Log.ENDC))

    @staticmethod
    def info(msg):
        """Print info message."""
        if Log.LOGGING_ENABELED:
            print("{}{}{}".format(Log.INFO, msg, Log.ENDC))

    @staticmethod
    def success(msg):
        """Print success message."""
        if Log.LOGGING_ENABELED:
            print("{}{}{}".format(Log.SUCCESS, msg, Log.ENDC))


def main(args=None):
    Log.LOGGING_ENABELED = args.debug
    # Read in the important parts from the COFF file
    coff = CoffFile(args.coff_file)
    # Convert the information back into a .asm file
    # args.asm_file

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Coff2Asm')
    parser.add_argument('coff_file', type=str,
                        help="Input file in MIPSEL COFF format.")
    parser.add_argument('asm_file', type=str,
                        help="Generated output file in Mars MIPS assembly.")
    parser.add_argument('-d', dest='debug', action='store_true',
                        default=False, help='Enables debugging logging')
    args = parser.parse_args()
    sys.exit(main(args))
