#!/usr/bin/env python3
"""
Intel Microcode Dump Tool
Reads and displays Intel microcode header information with checksum validation
"""

import struct
import sys
import os

class IntelMicrocodeHeader:
    def __init__(self, data: bytes):
        """Parse Intel microcode header from 48 bytes of data"""
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

def bcd_to_dec(bcd: int) -> int:
    """Convert BCD (Binary Coded Decimal) to decimal"""
    return ((bcd >> 4) * 10) + (bcd & 0x0F)

def parse_date(date_value: int) -> str:
    """Parse Intel microcode date format (BCD encoded)"""
    # Extract bytes from 32-bit date value
    date_bytes = [
        (date_value >> 0) & 0xFF,   # Byte 0 → YY (lo)
        (date_value >> 8) & 0xFF,   # Byte 1 → YY (hi)
        (date_value >> 16) & 0xFF,  # Byte 2 → DD
        (date_value >> 24) & 0xFF   # Byte 3 → MM
    ]
    
    month = bcd_to_dec(date_bytes[3])      # Byte 3 → MM
    day = bcd_to_dec(date_bytes[2])        # Byte 2 → DD
    year = bcd_to_dec(date_bytes[1]) * 100 + bcd_to_dec(date_bytes[0])  # Bytes 1,0 → YYYY
    
    return f"{year:04d}-{month:02d}-{day:02d}"

def print_header(header: IntelMicrocodeHeader) -> None:
    """Print formatted microcode header information"""
    total_size = header.total_size if header.total_size else 2048
    
    print("Header Version     :", f"0x{header.header_version:08X}")
    print("Update Revision    :", f"0x{header.update_revision:08X}")
    print("Date               :", parse_date(header.date))
    print("Processor Signature:", f"0x{header.processor_signature:08X}")
    print("Checksum           :", f"0x{header.checksum:08X}")
    print("Loader Revision    :", f"0x{header.loader_revision:08X}")
    print("Processor Flags    :", f"0x{header.processor_flags:08X}")
    print("Data Size (bytes)  :", header.data_size)
    print("Total Size (bytes) :", total_size)

def validate_checksum(data: bytes) -> bool:
    """Validate Intel microcode checksum (sum of all 32-bit words should be 0)"""
    if len(data) % 4 != 0:
        # Pad to 4-byte boundary if necessary
        padding = 4 - (len(data) % 4)
        data = data + b'\x00' * padding
    
    checksum = 0
    for i in range(0, len(data), 4):
        # Unpack 32-bit little-endian value
        val = struct.unpack('<L', data[i:i+4])[0]
        checksum = (checksum + val) & 0xFFFFFFFF
    
    return checksum == 0

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <microcode_file>", file=sys.stderr)
        return 1
    
    filename = sys.argv[1]
    
    # Check if file exists
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found", file=sys.stderr)
        return 1
    
    try:
        # Read microcode file
        with open(filename, 'rb') as fp:
            # Read header first
            header_data = fp.read(48)
            if len(header_data) < 48:
                print("Error: File too small to contain microcode header", file=sys.stderr)
                return 1
            
            # Parse header
            header = IntelMicrocodeHeader(header_data)
            total_size = header.total_size if header.total_size else 2048
            
            # Read entire microcode update
            fp.seek(0)
            full_data = fp.read(total_size)
            
            if len(full_data) < total_size:
                print(f"Error: File too small. Expected {total_size} bytes, got {len(full_data)}", file=sys.stderr)
                return 1
            
            # Print header information
            print_header(header)
            
            # Validate checksum
            is_valid = validate_checksum(full_data)
            print("Checksum Valid     :", "YES" if is_valid else "NO")
            
            return 0
            
    except IOError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error parsing microcode: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
