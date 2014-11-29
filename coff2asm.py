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
                Log.success('Loading Section: {}'.format(section.name))
                in_file.seek(section.scnptr)
                section.data = in_file.read(section.size)
            # Close the input file
            in_file.close()
        else:
            Log.error('The file {} does not exist'.format(input_file))

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
            if c == 0:
                break
            section_name += chr(c)
        return section_name


class Decoder(object):

    """Decodes mips 32-bit instructions into human readable assembly"""

    regs = ['$zero', '$at', '$v0', '$v1', '$a0', '$a1', '$a2', '$a3', '$t0',
            '$t1', '$t2', '$t3', '$t4', '$t5', '$t6', '$t7', '$s0', '$s1',
            '$s2', '$s3', '$s4', '$s5', '$s6', '$s7', '$t8', '$t9', '$k0',
            '$k1', '$gp', '$sp', '$fp', '$ra']

    def __init__(self):
        # TODO: Load instruction lists and print formats
        pass

    def decode(self, instruction, output):
        """
        Parses a single MIPS instruction and writes it to file.

                +--------+--------+--------+--------+--------+--------+
        R-Type  | opcode | rs     | rt     | rd     | shamt  | func   |
                +--------+--------+--------+--------+--------+--------+
                | 6-bits | 5-bits | 5-bits | 5-bits | 5-bits | 5-bits |
                +--------+--------+--------+--------+--------+--------+

                +--------+--------+--------+--------------------------+
        I-Type  | opcode | rs     | rt     | immediate                |
                +--------+--------+--------+--------------------------+
                | 6-bits | 5-bits | 5-bits | 16-bits                  |
                +--------+--------+--------+--------------------------+

                +--------+--------------------------------------------+
        J-Type  | opcode | address                                    |
                +--------+--------------------------------------------+
                | 6-bits | 26-bits                                    |
                +--------+--------------------------------------------+

                +--------+--------+--------+--------+--------+--------+
        FR-Type | opcode | fmt    | ft     | fs     | fd     | func   |
                +--------+--------+--------+--------+--------+--------+
                | 6-bits | 5-bits | 5-bits | 5-bits | 5-bits | 6-bits |
                +--------+--------+--------+--------+--------+--------+

                +--------+--------+--------+--------------------------+
        FI-Type | opcode | fmt    | ft     | immediate                |
                +--------+--------+--------+--------------------------+
                | 6-bits | 5-bits | 5-bits | 16-bits                  |
                +--------+--------+--------+--------------------------+

        1) If the opcode is 0 the instruction is a general purpose R-type instr
        2) If the opcode is 2 or 3 the instruction is a J-type Instruction
        3) If the opcode is 17 and the fmt is 16 the instruction is fp.s - FR
        4) If the opcode is 17 and the fmt is 17 the instruction is fp.d - FR
        5) If the opcode is 17, fmt is 8, and ft is 0, or 1 - FI
        6) Otherwise it must be an I-type instruction

        There is a couple of special cases:
        Move from control: mfc0
        R-Type opcode = 10, RS = 0, func = 0

        @param instruction 32-bit MIPS instruction to decode.
        @param output The human readable assembly file to write to.
        """
        opcode = self.extractOpcode(instruction)
        if opcode == 2 or opcode == 3:
            # J-type instruction
            Log.info('{:08x} is J-Type'.format(instruction))
        elif opcode == 0 or opcode == 16:
            # R-type instruction
            Log.info('{:08x} is R-Type'.format(instruction))
        elif opcode == 17:
            fmt = self.extractFMT(instruction)
            if fmt == 8:
                Log.info('{:08x} is FI-Type'.format(instruction))
            elif fmt == 16:
                Log.info('{:08x} is FR-Type fp.s'.format(instruction))
            elif fmt == 17:
                Log.info('{:08x} is FR-Type fp.d'.format(instruction))
        else:
            # I-Type instruction
            Log.info('{:08x} is I-Type'.format(instruction))

    def extractRS(self, instruction):
        return self.extract(instruction, 21, 25)

    def extractRT(self, instruction):
        return self.extract(instruction, 16, 20)

    def extractRD(self, instruction):
        return self.extract(instruction, 11, 15)

    def extractSHAMT(self, instruction):
        return self.extract(instruction, 6, 10)

    def extractOpcode(self, instruction):
        return self.extract(instruction, 26, 31)

    def extractFmt(self, instruction):
        return self.extract(instruction, 21, 25)

    def extractFunc(self, instruction):
        return self.extract(instruction, 0, 5)

    def extractImmediate16(self, instruction):
        return self.extract(instruction, 0, 15)

    def extractImmediate26(self, instruction):
        return self.extract(instruction, 0, 25)

    def extract(self, instruction, start, end):
        mask = (1 << (end + 1 - start)) - 1
        return self.rshift(instruction, start) & mask

    def rshift(self, val, n):
        return (val % 0x100000000) >> n


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


def disassemble(output_path, coff_file):
    # Create the decoder
    decoder = Decoder()
    # Create the output file
    output = open(output_path, 'w')
    # Write comments at top of file
    output.write('# Created by Coff2Asm\n')
    output.write('# NOTE: Must be executed with delayed branching enabled in \
MARS\n')
    # Start reading the sections
    for section in coff_file.sections:
        if section.name == '.text':
            output.write('{}\n'.format(section.name))
            offset = 0
            while offset < section.size:
                # Extract the integer from the data
                instruction = struct.unpack('<I',
                                            section.data[offset:offset+4])[0]
                # Decode the instruction and write it to file
                decoder.decode(instruction, output)
                # Get the next 4 bytes
                offset += 4
        elif section.name == '.data':
            output.write('{}\n'.format(section.name))
        else:
            Log.warn('Unknown section. Unable to create.')
    output.close()


def main(args=None):
    Log.LOGGING_ENABELED = args.debug
    # Read in the important parts from the COFF file
    coff = CoffFile(args.coff_file)
    # Disassemble the coff file
    disassemble(args.asm_file, coff)

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
