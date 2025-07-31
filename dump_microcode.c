#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#pragma pack(push, 1)
struct intel_microcode_header {
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
};
#pragma pack(pop)

int bcd_to_dec(uint8_t bcd) {
    return ((bcd >> 4) * 10) + (bcd & 0x0F);
}

void print_header(struct intel_microcode_header *hdr) {
    uint8_t *date_bytes = (uint8_t *)&hdr->date;

    int month = bcd_to_dec(date_bytes[3]);      // Byte 0 → MM
    int day   = bcd_to_dec(date_bytes[2]);      // Byte 1 → DD
    int year  = bcd_to_dec(date_bytes[1]) * 100 // Byte 3 → YY (hi)
              + bcd_to_dec(date_bytes[0]);      // Byte 2 → YY (lo)

    printf("Header Version     : 0x%08X\n", hdr->header_version);
    printf("Update Revision    : 0x%08X\n", hdr->update_revision);
    printf("Date               : %04d-%02d-%02d\n", year, month, day);
    printf("Processor Signature: 0x%08X\n", hdr->processor_signature);
    printf("Checksum           : 0x%08X\n", hdr->checksum);
    printf("Loader Revision    : 0x%08X\n", hdr->loader_revision);
    printf("Processor Flags    : 0x%08X\n", hdr->processor_flags);
    printf("Data Size (bytes)  : %u\n", hdr->data_size);
    printf("Total Size (bytes) : %u\n", hdr->total_size ? hdr->total_size : 2048);
}

int validate_checksum(const uint8_t *buf, size_t size) {
    uint32_t sum = 0;
    for (size_t i = 0; i < size; i += 4) {
        uint32_t val = *(uint32_t *)(buf + i);
        sum += val;
    }
    return (sum == 0);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <microcode_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    struct intel_microcode_header hdr;
    if (fread(&hdr, sizeof(hdr), 1, fp) != 1) {
        perror("fread");
        fclose(fp);
        return EXIT_FAILURE;
    }

    uint32_t total_size = hdr.total_size ? hdr.total_size : 2048;
    uint8_t *buf = malloc(total_size);
    if (!buf) {
        perror("malloc");
        fclose(fp);
        return EXIT_FAILURE;
    }

    fseek(fp, 0, SEEK_SET);
    if (fread(buf, total_size, 1, fp) != 1) {
        perror("fread full update");
        free(buf);
        fclose(fp);
        return EXIT_FAILURE;
    }

    print_header(&hdr);
    printf("Checksum Valid     : %s\n", validate_checksum(buf, total_size) ? "YES" : "NO");

    free(buf);
    fclose(fp);
    return EXIT_SUCCESS;
}

