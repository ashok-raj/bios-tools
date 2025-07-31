#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct {
    uint64_t address;
    uint32_t size;
    uint16_t version;
    uint8_t  type;
    uint8_t  checksum;
} fit_entry_t;

typedef struct {
    uint32_t header_version;
    uint32_t update_revision;
    uint32_t date;
    uint32_t processor_signature;
    uint32_t checksum;
    uint32_t loader_revision;
    uint32_t processor_flags;
    uint32_t data_size;
    uint32_t total_size;
    uint32_t reserved[3];
} microcode_header_t;
#pragma pack(pop)

// FIT entry types
const char* get_fit_type_name(uint8_t type) {
    switch (type & 0x7F) {
        case 0x00: return "FIT Header";
        case 0x01: return "Microcode Update";
        case 0x02: return "Startup ACM";
        case 0x07: return "BIOS Startup Module";
        case 0x08: return "TPM Policy";
        case 0x09: return "BIOS Policy";
        case 0x0A: return "TXT Policy";
        case 0x0B: return "Key Manifest";
        case 0x0C: return "Boot Policy Manifest";
        case 0x10: return "CSE SecureBoot";
        case 0x2D: return "JMP $";
        default: return "Unknown/Reserved";
    }
}

void print_date(uint32_t date) {
    uint32_t day = date & 0xFF;
    uint32_t month = (date >> 8) & 0xFF;
    uint32_t year = (date >> 16) & 0xFFFF;
    printf("%02u/%02u/%04u", month, day, year);
}

void print_processor_signature(uint32_t signature) {
    uint32_t stepping = signature & 0xF;
    uint32_t model = (signature >> 4) & 0xF;
    uint32_t family = (signature >> 8) & 0xF;
    uint32_t type = (signature >> 12) & 0x3;
    uint32_t ext_model = (signature >> 16) & 0xF;
    uint32_t ext_family = (signature >> 20) & 0xFF;
    
    uint32_t display_family = family;
    uint32_t display_model = model;
    
    if (family == 0xF) {
        display_family = family + ext_family;
    }
    if (family == 0x6 || family == 0xF) {
        display_model = model + (ext_model << 4);
    }
    
    printf("Family: 0x%02X, Model: 0x%02X, Stepping: 0x%X, Type: 0x%X", 
           display_family, display_model, stepping, type);
}

int find_fit_pointer(const uint8_t* bios_data, size_t bios_size, uint64_t* fit_address) {
    // FIT pointer is located at 0xFFFFFFC0 (16 bytes before end of 4GB space)
    // In a typical BIOS file, this maps to offset (file_size - 0x40)
    
    if (bios_size < 0x40) {
        printf("BIOS file too small to contain FIT pointer\n");
        return 0;
    }
    
    size_t fit_ptr_offset = bios_size - 0x40;
    
    // Read the FIT pointer (8 bytes)
    memcpy(fit_address, &bios_data[fit_ptr_offset], sizeof(uint64_t));
    
    printf("FIT Pointer found at offset 0x%zX: 0x%016llX\n", 
           fit_ptr_offset, (unsigned long long)*fit_address);
    
    return 1;
}

size_t calculate_fit_offset(uint64_t fit_address, size_t bios_size) {
    // Convert absolute address to file offset
    // Typical mapping: 0xFFxxxxxx -> file offset (bios_size - (0x100000000 - address))
    
    if (fit_address >= 0xFF000000ULL) {
        size_t offset = bios_size - (0x100000000ULL - fit_address);
        if (offset < bios_size) {
            return offset;
        }
    }
    
    // Alternative: try direct mapping for smaller addresses
    if (fit_address < bios_size) {
        return (size_t)fit_address;
    }
    
    printf("Cannot map FIT address 0x%llX to file offset\n", 
           (unsigned long long)fit_address);
    return SIZE_MAX;
}

void dump_microcode_header(const uint8_t* bios_data, size_t bios_size, uint64_t address, uint32_t size, int microcode_index) {
    size_t offset = calculate_fit_offset(address, bios_size);
    
    if (offset == SIZE_MAX || offset + sizeof(microcode_header_t) > bios_size) {
        printf("    Cannot access microcode at offset 0x%zX\n", offset);
        return;
    }
    
    const microcode_header_t* header = (const microcode_header_t*)&bios_data[offset];
    
    printf("    Microcode Header Details:\n");
    printf("      File Offset:        0x%08zX\n", offset);
    printf("      Header Version:     0x%08X\n", header->header_version);
    printf("      Update Revision:    0x%08X\n", header->update_revision);
    printf("      Date:               0x%08X (", header->date);
    print_date(header->date);
    printf(")\n");
    printf("      Processor Signature: 0x%08X (", header->processor_signature);
    print_processor_signature(header->processor_signature);
    printf(")\n");
    printf("      Checksum:           0x%08X\n", header->checksum);
    printf("      Loader Revision:    0x%08X\n", header->loader_revision);
    printf("      Processor Flags:    0x%08X\n", header->processor_flags);
    printf("      Data Size:          0x%08X (%u bytes)\n", header->data_size, header->data_size);
    printf("      Total Size:         0x%08X (%u bytes)\n", header->total_size, header->total_size);
    
    // Validate header version
    if (header->header_version != 0x00000001) {
        printf("      WARNING: Unexpected header version!\n");
    }
    
    // Check size consistency
    if (header->total_size != size && size != 0) {
        printf("      WARNING: FIT size (0x%X) doesn't match header total size (0x%X)\n", 
               size, header->total_size);
    }
    
    // Validate data size
    uint32_t expected_total = header->data_size + sizeof(microcode_header_t);
    if (header->total_size < expected_total) {
        printf("      WARNING: Total size smaller than header + data size\n");
    }
    
    // Use microcode header size if FIT entry size is 0
    uint32_t effective_size = (size == 0) ? header->total_size : size;
    
    // Basic checksum validation (simplified)
    if (offset + header->total_size <= bios_size) {
        uint32_t calc_checksum = 0;
        const uint32_t* data = (const uint32_t*)&bios_data[offset];
        size_t dwords = header->total_size / 4;
        
        for (size_t i = 0; i < dwords; i++) {
            calc_checksum += data[i];
        }
        
        if (calc_checksum == 0) {
            printf("      Checksum:           Valid (sum = 0)\n");
        } else {
            printf("      Checksum:           Invalid (sum = 0x%08X)\n", calc_checksum);
        }
    }
    
    // Write microcode to file
    if (header->total_size > 0 && header->total_size <= 0x100000 && 
        offset + header->total_size <= bios_size) {
        
        char filename[32];
        snprintf(filename, sizeof(filename), "microcode%d.bin", microcode_index);
        
        FILE* mc_file = fopen(filename, "wb");
        if (mc_file) {
            size_t written = fwrite(&bios_data[offset], 1, header->total_size, mc_file);
            fclose(mc_file);
            
            if (written == header->total_size) {
                printf("      Microcode written:  %s (%u bytes)\n", filename, header->total_size);
            } else {
                printf("      WARNING: Failed to write complete microcode to %s\n", filename);
            }
        } else {
            printf("      WARNING: Failed to create file %s\n", filename);
        }
    } else {
        printf("      WARNING: Cannot extract microcode (invalid size or insufficient data)\n");
    }
    
    printf("\n");
}

void print_fit_entry(int index, const fit_entry_t* entry, const uint8_t* bios_data, size_t bios_size, int* microcode_counter) {
    printf("Entry %d:\n", index);
    printf("  Address:    0x%016llX\n", (unsigned long long)entry->address);
    printf("  Size:       0x%08X (%u bytes)\n", entry->size, entry->size);
    printf("  Version:    0x%04X\n", entry->version);
    printf("  Type:       0x%02X (%s)\n", entry->type, get_fit_type_name(entry->type));
    printf("  C_V bit:    %s\n", (entry->type & 0x80) ? "Valid" : "Invalid");
    printf("  Checksum:   0x%02X\n", entry->checksum);
    
    // If this is a microcode update entry, dump the microcode header
    if ((entry->type & 0x7F) == 0x01) {
        (*microcode_counter)++;
        dump_microcode_header(bios_data, bios_size, entry->address, entry->size, *microcode_counter);
    } else {
        printf("\n");
    }
}

uint8_t calculate_checksum(const uint8_t* data, size_t length) {
    uint8_t sum = 0;
    for (size_t i = 0; i < length; i++) {
        sum += data[i];
    }
    return sum;
}

int parse_fit_table(const uint8_t* bios_data, size_t bios_size) {
    uint64_t fit_address;
    
    // Find FIT pointer
    if (!find_fit_pointer(bios_data, bios_size, &fit_address)) {
        return 1;
    }
    
    // Calculate file offset for FIT table
    size_t fit_offset = calculate_fit_offset(fit_address, bios_size);
    if (fit_offset == SIZE_MAX || fit_offset + sizeof(fit_entry_t) > bios_size) {
        printf("Invalid FIT offset calculated\n");
        return 1;
    }
    
    printf("FIT Table located at file offset: 0x%zX\n\n", fit_offset);
    
    // Read FIT header
    const fit_entry_t* fit_header = (const fit_entry_t*)&bios_data[fit_offset];
    
    // Validate FIT header
    if ((fit_header->type & 0x7F) != 0x00) {
        printf("Invalid FIT header type: 0x%02X\n", fit_header->type);
        return 1;
    }
    
    // FIT header's size field contains the number of entries
    uint32_t num_entries = fit_header->size;
    if (num_entries == 0 || num_entries > 1000) {
        printf("Invalid number of FIT entries: %u\n", num_entries);
        return 1;
    }
    
    printf("FIT Table Analysis:\n");
    printf("==================\n");
    printf("Number of entries: %u\n\n", num_entries);
    
    // Check if we have enough data for all entries
    if (fit_offset + (num_entries * sizeof(fit_entry_t)) > bios_size) {
        printf("Not enough data for all FIT entries\n");
        return 1;
    }
    
    // Counter for microcode files
    int microcode_counter = 0;
    
    // Parse and display each entry
    for (uint32_t i = 0; i < num_entries; i++) {
        const fit_entry_t* entry = (const fit_entry_t*)&bios_data[fit_offset + (i * sizeof(fit_entry_t))];
        print_fit_entry(i, entry, bios_data, bios_size, &microcode_counter);
    }
    
    // Print summary
    if (microcode_counter > 0) {
        printf("Summary: Extracted %d microcode update(s)\n", microcode_counter);
    }
    
    // Verify checksum of entire FIT table
    uint8_t checksum = calculate_checksum(&bios_data[fit_offset], num_entries * sizeof(fit_entry_t));
    printf("FIT Table Checksum: 0x%02X %s\n", checksum, (checksum == 0) ? "(Valid)" : "(Invalid)");
    
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <bios.bin>\n", argv[0]);
        printf("Parses FIT (Firmware Interface Table) from BIOS binary file\n");
        return 1;
    }
    
    const char* filename = argv[1];
    
    // Open BIOS file
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open BIOS file");
        return 1;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0) {
        printf("Invalid file size\n");
        fclose(file);
        return 1;
    }
    
    printf("BIOS file: %s (Size: %ld bytes)\n", filename, file_size);
    
    // Allocate buffer and read file
    uint8_t* bios_data = malloc(file_size);
    if (!bios_data) {
        printf("Failed to allocate memory\n");
        fclose(file);
        return 1;
    }
    
    size_t bytes_read = fread(bios_data, 1, file_size, file);
    fclose(file);
    
    if (bytes_read != (size_t)file_size) {
        printf("Failed to read entire file\n");
        free(bios_data);
        return 1;
    }
    
    // Parse FIT table
    int result = parse_fit_table(bios_data, file_size);
    
    free(bios_data);
    return result;
}
