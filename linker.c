#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char payload_message[] = ">>> linker payload executed! <<<\n";

static uint64_t align_up(uint64_t value, uint64_t alignment) {
	if (alignment <= 1) {
		return value;
	}
	uint64_t remainder = value % alignment;
	if (remainder == 0) {
		return value;
	}
	return value + (alignment - remainder);
}

static void bail(const char *message) {
	if (errno) {
		perror(message);
	} else {
		fprintf(stderr, "%s\n", message);
	}
	exit(EXIT_FAILURE);
}

static unsigned char *ref(const char *path, size_t *out_size) {
	FILE *f = fopen(path, "rb");
	if (!f) {
		bail("failed to open input");
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		bail("seek input");
	}
	long signed_size = ftell(f);
	if (signed_size < 0) {
		bail("ftell");
	}
	size_t size = (size_t)signed_size;
	if (fseek(f, 0, SEEK_SET) != 0) {
		bail("rewind input");
	}
	unsigned char *buffer = malloc(size);
	if (!buffer) {
		bail("malloc input");
	}
	if (fread(buffer, 1, size, f) != size) {
		bail("read input");
	}
	fclose(f);
	*out_size = size;
	return buffer;
}

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "usage: %s <in.o> <out.elf>\n", argv[0]);
		return EXIT_FAILURE;
	}
	const char *input_path = argv[1];
	const char *output_path = argv[2];
	size_t file_size = 0;
	unsigned char *input = ref(input_path, &file_size);
	if (file_size < sizeof(Elf64_Ehdr)) {
		free(input);
		bail("input too small to be ELF64");
	}
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)input;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		free(input);
		bail("input is not an ELF file");
	}
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		free(input);
		bail("ELF is not 64-bit");
	}
	if (ehdr->e_machine != EM_X86_64) {
		free(input);
		bail("ELF is not for x86_64");
	}
	if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) {
		free(input);
		bail("ELF missing program headers");
	}
	if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
		free(input);
		bail("unexpected program header size");
	}
	size_t ph_table_size = (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr);
	if (ehdr->e_phoff + ph_table_size > file_size) {
		free(input);
		bail("program headers truncated");
	}
	Elf64_Phdr *phdrs = (Elf64_Phdr *)(input + ehdr->e_phoff);
	uint64_t max_file_end = 0;
	uint64_t max_vaddr_end = 0;
	uint64_t max_align = 0x1000;
	for (int i = 0; i < ehdr->e_phnum; ++i) {
		Elf64_Phdr *ph = &phdrs[i];
		if (ph->p_type != PT_LOAD) {
			continue;
		}
		uint64_t file_end = ph->p_offset + ph->p_filesz;
		uint64_t vaddr_end = ph->p_vaddr + ph->p_memsz;
		if (file_end > file_size) {
			free(input);
			bail("segment extends beyond end of file");
		}
		if (file_end > max_file_end) {
			max_file_end = file_end;
		}
		if (vaddr_end > max_vaddr_end) {
			max_vaddr_end = vaddr_end;
		}
		if (ph->p_align > max_align) {
			max_align = ph->p_align;
		}
	}
	if (max_file_end == 0 || max_vaddr_end == 0) {
		free(input);
		bail("no loadable segments in ELF");
	}
	if (max_align < 0x1000) {
		max_align = 0x1000;
	}
	uint32_t message_len = (uint32_t)(sizeof(payload_message) - 1);
	const size_t stub_code_size = 3/* pushes */ + 7 + 5 + 7 + 5 + 2 + 3 /* pops */ + 10 + 2 + 3;
	size_t payload_size = stub_code_size + message_len;
	uint64_t payload_size_u = (uint64_t)payload_size;
	uint64_t base_file_extent = file_size > max_file_end ? file_size : max_file_end;
	uint64_t payload_offset = align_up(base_file_extent, max_align);
	uint64_t payload_vaddr = align_up(max_vaddr_end, max_align);
	if (payload_offset > UINT64_MAX - payload_size_u ||
	    payload_vaddr > UINT64_MAX - payload_size_u) {
		free(input);
		bail("payload placement overflow");
	}
	if (payload_offset > SIZE_MAX || payload_offset + payload_size_u > SIZE_MAX) {
		free(input);
		bail("payload exceeds host address space");
	}
	unsigned char *payload = malloc(payload_size);
	if (!payload) {
		free(input);
		bail("malloc payload");
	}
	size_t cursor = 0;
	/* preserve entry registers expected by crt1 */
	payload[cursor++] = 0x57;/* push rdi */
	payload[cursor++] = 0x56;/* push rsi */
	payload[cursor++] = 0x52;/* push rdx */
	/* mov rax, 1 (SYS_write) */
	payload[cursor++] = 0x48;
	payload[cursor++] = 0xC7;
	payload[cursor++] = 0xC0;
	payload[cursor++] = 0x01;
	payload[cursor++] = 0x00;
	payload[cursor++] = 0x00;
	payload[cursor++] = 0x00;
	/* mov edi, 1 (stdout) */
	payload[cursor++] = 0xBF;
	payload[cursor++] = 0x01;
	payload[cursor++] = 0x00;
	payload[cursor++] = 0x00;
	payload[cursor++] = 0x00;
	/* lea rsi, [rip + message] */
	size_t lea_offset = cursor;
	payload[cursor++] = 0x48;
	payload[cursor++] = 0x8D;
	payload[cursor++] = 0x35;
	cursor += 4;/* reserve disp32 */
	/* mov edx, message_len */
	payload[cursor++] = 0xBA;
	memcpy(payload + cursor, &message_len, sizeof(message_len));
	cursor += sizeof(message_len);
	/* syscall */
	payload[cursor++] = 0x0F;
	payload[cursor++] = 0x05;
	/* restore registers */
	payload[cursor++] = 0x5A;/* pop rdx */
	payload[cursor++] = 0x5E;/* pop rsi */
	payload[cursor++] = 0x5F;/* pop rdi */
	uint64_t original_entry = ehdr->e_entry;
	/* movabs r11, original_entry */
	payload[cursor++] = 0x49;
	payload[cursor++] = 0xBB;
	memcpy(payload + cursor, &original_entry, sizeof(original_entry));
	cursor += sizeof(original_entry);
	/* xor eax, eax to match ABI expectations */
	payload[cursor++] = 0x31;
	payload[cursor++] = 0xC0;
	/* jmp r11 */
	payload[cursor++] = 0x41;
	payload[cursor++] = 0xFF;
	payload[cursor++] = 0xE3;
	size_t message_offset = cursor;
	memcpy(payload + message_offset, payload_message, message_len);
	cursor += message_len;
	if (cursor != payload_size) {
		free(payload);
		free(input);
		bail("payload assembly mismatch");
	}
	uint64_t lea_base = payload_vaddr + lea_offset + 7;
	uint64_t message_addr = payload_vaddr + message_offset;
	int64_t disp = (int64_t)message_addr - (int64_t)lea_base;
	if (disp < INT32_MIN || disp > INT32_MAX) {
		free(payload);
		free(input);
		bail("payload message out of range");
	}
	int32_t disp32 = (int32_t)disp;
	memcpy(payload + lea_offset + 3, &disp32, sizeof(disp32));
	uint16_t new_phnum = ehdr->e_phnum + 1;
	size_t new_phdr_table_size = (size_t)new_phnum * sizeof(Elf64_Phdr);
	uint64_t payload_file_end = payload_offset + payload_size_u;
	uint64_t new_phoff = align_up(payload_file_end, sizeof(Elf64_Phdr));
	uint64_t final_file_size_u = new_phoff + new_phdr_table_size;
	if (final_file_size_u > SIZE_MAX) {
		free(payload);
		free(input);
		bail("final file too large");
	}
	size_t final_file_size = (size_t)final_file_size_u;
	unsigned char *output = calloc(final_file_size, 1);
	if (!output) {
		free(payload);
		free(input);
		bail("calloc output");
	}
	memcpy(output, input, file_size);
	memcpy(output + payload_offset, payload, payload_size);
	Elf64_Ehdr *out_ehdr = (Elf64_Ehdr *)output;
	*out_ehdr = *ehdr;
	out_ehdr->e_entry = payload_vaddr;
	out_ehdr->e_phoff = new_phoff;
	out_ehdr->e_phnum = new_phnum;
	Elf64_Phdr *out_phdrs = (Elf64_Phdr *)(output + new_phoff);
	memcpy(out_phdrs, phdrs, ehdr->e_phnum * sizeof(Elf64_Phdr));
	Elf64_Phdr *payload_ph = &out_phdrs[ehdr->e_phnum];
	memset(payload_ph, 0, sizeof(*payload_ph));
	payload_ph->p_type = PT_LOAD;
	payload_ph->p_flags = PF_R | PF_X;
	payload_ph->p_offset = payload_offset;
	payload_ph->p_vaddr = payload_vaddr;
	payload_ph->p_paddr = payload_vaddr;
	uint64_t segment_span = (new_phoff + new_phdr_table_size) - payload_offset;
	payload_ph->p_filesz = segment_span;
	payload_ph->p_memsz = segment_span;
	payload_ph->p_align = max_align;
	FILE *fout = fopen(output_path, "wb");
	if (!fout) {
		free(output);
		free(payload);
		free(input);
		bail("failed to open output");
	}
	if (fwrite(output, 1, final_file_size, fout) != final_file_size) {
		fclose(fout);
		free(output);
		free(payload);
		free(input);
		bail("write output");
	}
	fclose(fout);
	free(output);
	free(payload);
	free(input);
	printf("injected payload at 0x%lx <file offset 0x%lx>\n",
	       (unsigned long)payload_vaddr, (unsigned long)payload_offset);
	printf("original entry: 0x%lx -> new entry: 0x%lx\n",
	       (unsigned long)original_entry, (unsigned long)payload_vaddr);
	return EXIT_SUCCESS;
}
