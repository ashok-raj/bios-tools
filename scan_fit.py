#!/usr/bin/env python3
"""
FIT (Firmware Interface Table) Parser for BIOS Binary Files
Locates and parses FIT entries with detailed microcode header analysis
"""

import struct
import sys
import os
from typing import Optional, Tuple

class FITEntry:
    def __init__(self, data: bytes):
        """Parse FIT entry from 16 bytes of data"""
        self.address, self.size, self.version, self.type, self.checksum = \
            struct.unpack('<QLHBB', data)
    
    def is_valid(self) -> bool:
        """Check if C_V bit indicates valid entry"""
        return bool(self.type & 0x80)
    
    def get_type_code(self) -> int:
        """Get type code without C_V bit"""
        return self.type & 0x7F

class MicrocodeHeader:
    def __init__(self, data: bytes):
        """Parse microcode header from 48 bytes of data"""
        if len(data) < 48:
            raise ValueError(f"Insufficient data for microcode header: {len(data)} bytes, need 48")
        
        # Intel microcode header format: 12 32-bit fields (48 bytes total)
        fields = struct.unpack('<12L', data[:48])
        self.header_version = fields[0]
        self.update_revision = fields[1] 
        self.date = fields[2]
        self.processor_signature = fields[3]
        self.checksum = fields[4]
        self.loader_revision = fields[5]
        self.processor_flags = fields[6]
        self.data_size = fields[7]
        self.total_size = fields[8]
        self.reserved = fields[9:12]

class FITParser:
    FIT_TYPES = {
        0x00: "FIT Header",
        0x01: "Microcode Update", 
        0x02: "Startup ACM",
        0x07: "BIOS Startup Module",
        0x08: "TPM Policy",
        0x09: "BIOS Policy",
        0x0A: "TXT Policy",
        0x0B: "Key Manifest",
        0x0C: "Boot Policy Manifest",
        0x10: "CSE SecureBoot",
        0x2D: "JMP $"
    }
    
    def __init__(self, bios_data: bytes):
        self.bios_data = bios_data
        self.bios_size = len(bios_data)
    
    def get_fit_type_name(self, type_code: int) -> str:
        """Get human-readable name for FIT entry type"""
        return self.FIT_TYPES.get(type_code, "Unknown/Reserved")
    
    def find_fit_pointer(self) -> Optional[int]:
        """Find FIT pointer at standard location (64 bytes from end)"""
        if self.bios_size < 0x40:
            print("BIOS file too small to contain FIT pointer")
            return None
        
        fit_ptr_offset = self.bios_size - 0x40
        fit_address = struct.unpack('<Q', self.bios_data[fit_ptr_offset:fit_ptr_offset + 8])[0]
        
        print(f"FIT Pointer found at offset 0x{fit_ptr_offset:X}: 0x{fit_address:016X}")
        return fit_address
    
    def calculate_fit_offset(self, fit_address: int) -> Optional[int]:
        """Convert absolute FIT address to file offset"""
        # Typical mapping: 0xFFxxxxxx -> file offset (bios_size - (0x100000000 - address))
        if fit_address >= 0xFF000000:
            offset = self.bios_size - (0x100000000 - fit_address)
            if offset < self.bios_size:
                return offset
        
        # Alternative: try direct mapping for smaller addresses
        if fit_address < self.bios_size:
            return fit_address
        
        print(f"Cannot map FIT address 0x{fit_address:X} to file offset")
        return None
    
    def print_date(self, date: int) -> str:
        """Format microcode date as MM/DD/YYYY"""
        day = date & 0xFF
        month = (date >> 8) & 0xFF
        year = (date >> 16) & 0xFFFF
        return f"{month:02d}/{day:02d}/{year:04d}"
    
    def print_processor_signature(self, signature: int) -> str:
        """Decode processor signature into family, model, stepping, type"""
        stepping = signature & 0xF
        model = (signature >> 4) & 0xF
        family = (signature >> 8) & 0xF
        proc_type = (signature >> 12) & 0x3
        ext_model = (signature >> 16) & 0xF
        ext_family = (signature >> 20) & 0xFF
        
        display_family = family
        display_model = model
        
        if family == 0xF:
            display_family = family + ext_family
        if family == 0x6 or family == 0xF:
            display_model = model + (ext_model << 4)
        
        return f"Family: 0x{display_family:02X}, Model: 0x{display_model:02X}, Stepping: 0x{stepping:X}, Type: 0x{proc_type:X}"
    
    def calculate_microcode_checksum(self, offset: int, total_size: int) -> int:
        """Calculate microcode checksum (sum of all 32-bit words)"""
        if offset + total_size > self.bios_size:
            return -1
        
        checksum = 0
        dwords = total_size // 4
        
        for i in range(dwords):
            dword_offset = offset + (i * 4)
            if dword_offset + 4 <= self.bios_size:
                dword = struct.unpack('<L', self.bios_data[dword_offset:dword_offset + 4])[0]
                checksum = (checksum + dword) & 0xFFFFFFFF
        
        return checksum
    
    def dump_microcode_header(self, address: int, size: int, microcode_index: int) -> None:
        """Dump detailed microcode header information and write to file"""
        offset = self.calculate_fit_offset(address)
        
        if offset is None:
            print(f"    Cannot calculate file offset for address 0x{address:016X}")
            return
            
        if offset + 48 > self.bios_size:
            print(f"    Cannot access microcode header at offset 0x{offset:08X} (not enough data)")
            return
        
        try:
            header_data = self.bios_data[offset:offset + 48]
            header = MicrocodeHeader(header_data)
            
            print("    Microcode Header Details:")
            print(f"      File Offset:         0x{offset:08X}")
            print(f"      Header Version:      0x{header.header_version:08X}")
            print(f"      Update Revision:     0x{header.update_revision:08X}")
            print(f"      Date:                0x{header.date:08X} ({self.print_date(header.date)})")
            print(f"      Processor Signature: 0x{header.processor_signature:08X} ({self.print_processor_signature(header.processor_signature)})")
            print(f"      Checksum:            0x{header.checksum:08X}")
            print(f"      Loader Revision:     0x{header.loader_revision:08X}")
            print(f"      Processor Flags:     0x{header.processor_flags:08X}")
            print(f"      Data Size:           0x{header.data_size:08X} ({header.data_size} bytes)")
            print(f"      Total Size:          0x{header.total_size:08X} ({header.total_size} bytes)")
            
            # Use microcode header size if FIT entry size is 0
            effective_size = header.total_size if size == 0 else size
            
            # Validation checks
            if header.header_version != 0x00000001:
                print("      WARNING: Unexpected header version!")
            
            if header.total_size != size and size != 0:
                print(f"      WARNING: FIT size (0x{size:X}) doesn't match header total size (0x{header.total_size:X})")
            
            if size == 0:
                print(f"      INFO: Using microcode header total size (FIT entry size was 0)")
            
            expected_total = header.data_size + 48  # 48 bytes header size
            if header.total_size < expected_total:
                print("      WARNING: Total size smaller than header + data size")
            
            # Validate total size is reasonable
            if header.total_size == 0 or header.total_size > 0x100000:  # Max 1MB
                print(f"      WARNING: Suspicious total size: 0x{header.total_size:X}")
                return
            
            # Checksum validation (only if we have enough data)
            if offset + header.total_size <= self.bios_size:
                calc_checksum = self.calculate_microcode_checksum(offset, header.total_size)
                if calc_checksum == 0:
                    print("      Checksum:            Valid (sum = 0)")
                elif calc_checksum == -1:
                    print("      Checksum:            Cannot calculate (insufficient data)")
                else:
                    print(f"      Checksum:            Invalid (sum = 0x{calc_checksum:08X})")
            else:
                print("      Checksum:            Cannot calculate (microcode extends beyond file)")
            
            # Write microcode to file
            if (header.total_size > 0 and header.total_size <= 0x100000 and 
                offset + header.total_size <= self.bios_size):
                
                filename = f"microcode{microcode_index}.bin"
                
                try:
                    with open(filename, 'wb') as mc_file:
                        microcode_data = self.bios_data[offset:offset + header.total_size]
                        mc_file.write(microcode_data)
                    
                    print(f"      Microcode written:   {filename} ({header.total_size} bytes)")
                    
                except IOError as e:
                    print(f"      WARNING: Failed to write {filename}: {e}")
            else:
                print("      WARNING: Cannot extract microcode (invalid size or insufficient data)")
            
        except ValueError as e:
            print(f"    Error parsing microcode header: {e}")
        except Exception as e:
            print(f"    Unexpected error parsing microcode header: {e}")
        
        print()
    
    def print_fit_entry(self, index: int, entry: FITEntry, microcode_counter: list) -> None:
        """Print detailed FIT entry information"""
        print(f"Entry {index}:")
        print(f"  Address:    0x{entry.address:016X}")
        print(f"  Size:       0x{entry.size:08X} ({entry.size} bytes)")
        print(f"  Version:    0x{entry.version:04X}")
        print(f"  Type:       0x{entry.type:02X} ({self.get_fit_type_name(entry.get_type_code())})")
        print(f"  C_V bit:    {'Valid' if entry.is_valid() else 'Invalid'}")
        print(f"  Checksum:   0x{entry.checksum:02X}")
        
        # If this is a microcode update entry, dump the microcode header
        if entry.get_type_code() == 0x01:
            microcode_counter[0] += 1
            self.dump_microcode_header(entry.address, entry.size, microcode_counter[0])
        else:
            print()
    
    def calculate_checksum(self, data: bytes) -> int:
        """Calculate simple byte checksum"""
        return sum(data) & 0xFF
    
    def parse_fit_table(self) -> bool:
        """Main function to parse FIT table"""
        # Find FIT pointer
        fit_address = self.find_fit_pointer()
        if fit_address is None:
            return False
        
        # Calculate file offset for FIT table
        fit_offset = self.calculate_fit_offset(fit_address)
        if fit_offset is None or fit_offset + 16 > self.bios_size:
            print("Invalid FIT offset calculated")
            return False
        
        print(f"FIT Table located at file offset: 0x{fit_offset:X}\n")
        
        # Read FIT header
        try:
            header_data = self.bios_data[fit_offset:fit_offset + 16]
            fit_header = FITEntry(header_data)
            
            # Validate FIT header
            if fit_header.get_type_code() != 0x00:
                print(f"Invalid FIT header type: 0x{fit_header.type:02X}")
                return False
            
            # FIT header's size field contains the number of entries
            num_entries = fit_header.size
            if num_entries == 0 or num_entries > 1000:
                print(f"Invalid number of FIT entries: {num_entries}")
                return False
            
            print("FIT Table Analysis:")
            print("==================")
            print(f"Number of entries: {num_entries}\n")
            
            # Check if we have enough data for all entries
            total_fit_size = num_entries * 16
            if fit_offset + total_fit_size > self.bios_size:
                print("Not enough data for all FIT entries")
                return False
            
            # Counter for microcode files (using list for reference passing)
            microcode_counter = [0]
            
            # Parse and display each entry
            for i in range(num_entries):
                entry_offset = fit_offset + (i * 16)
                entry_data = self.bios_data[entry_offset:entry_offset + 16]
                entry = FITEntry(entry_data)
                self.print_fit_entry(i, entry, microcode_counter)
            
            # Print summary
            if microcode_counter[0] > 0:
                print(f"Summary: Extracted {microcode_counter[0]} microcode update(s)")
            
            # Verify checksum of entire FIT table
            fit_table_data = self.bios_data[fit_offset:fit_offset + total_fit_size]
            checksum = self.calculate_checksum(fit_table_data)
            print(f"FIT Table Checksum: 0x{checksum:02X} {'(Valid)' if checksum == 0 else '(Invalid)'}")
            
            return True
            
        except Exception as e:
            print(f"Error parsing FIT table: {e}")
            return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <bios.bin>")
        print("Parses FIT (Firmware Interface Table) from BIOS binary file")
        return 1
    
    filename = sys.argv[1]
    
    # Check if file exists
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return 1
    
    try:
        # Read BIOS file
        with open(filename, 'rb') as file:
            bios_data = file.read()
        
        file_size = len(bios_data)
        if file_size == 0:
            print("Error: Empty file")
            return 1
        
        print(f"BIOS file: {filename} (Size: {file_size} bytes)")
        
        # Create parser and parse FIT table
        parser = FITParser(bios_data)
        success = parser.parse_fit_table()
        
        return 0 if success else 1
        
    except IOError as e:
        print(f"Error reading file: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
