/*
 * main.c
 *
 *  Created on: Mar 28, 2012
 *      Author: Sebastian Vogl <vogls@sec.in.tum.de>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <elf.h>
#include <stdarg.h>
#include <getopt.h>

/*
 * TYPEDEFS
 */
typedef unsigned long long int u64;
typedef unsigned long int u32;
typedef unsigned char u8;

/*
 * CONFIG
 */
const char *wrapper_path          = "../wrapper/linux64/";
const char *wrapper_file          = "wrapper.txt";
const char *extension             = ".inject";
const char *init_function         = NULL;
const char *default_init_function = "module_init";

/*
 * STRUCTS
 */
struct scn_array {
	u32 next_free_entry;
	u32 max_entries;
	u32 *elf_scn_index_array;
};

struct symbol {
	u8 resolve;
	u64 str_len;
	char *str;
	u64 target_addr;
	u64 value;
	u64 addend;
	u64 offset;
	u32 type;
	u8 function;
};


struct wrapper {
	u32 size;
	char **wrapper;
};

static struct option options[] = {
	{"wrapper-file", optional_argument, 0, 'w'},
	{"wrapper-dir",  optional_argument, 0, 'd'},
	{"extension",    optional_argument, 0, 'e'},
	{"init-function",optional_argument, 0, 'i'},
	{"output",       optional_argument, 0, 'o'},
	{0, 0, 0, 0}
};

struct embedded_binary {
	void *start;
	void *end;
};

/*
 * GLOBALS
 */

// shellcode generated by nasm
extern void *_binary_shellcode_bin_start[];
extern void *_binary_shellcode_bin_end[];

extern void *_binary_printf_shellcode_bin_start[];
extern void *_binary_printf_shellcode_bin_end[];

struct embedded_binary shellcode;
struct embedded_binary printf_shellcode;

// An array for the rel scn pointer
struct scn_array rel_scns;
// An array for the rela scn pointer
struct scn_array rela_scns;
// The index of the symtab scn
u32 symtab_scn = 0;

// Count of entries within the sections
u32 rela_count = 0;
u32 rel_count = 0;

// Final Data
struct symbol *symbols = NULL;
u32 symbol_count = 0;
u64 entry_point = 0;

// Section Table Index
size_t shstrndx;

// Have to be global for whatever reason.
// Otherwise shit hits the fan.
Elf *elf;
// Global TMP var for  scns. May be used and overwritten within functions.
Elf_Scn *scn;
// Scn for parseRela, parseRel, resolveSym, and resolveSec.
// Do not use outside of this functions.
Elf_Scn *scn_rela, *scn_rel, *scn_sym, *scn_sec;
// Global TMP var for SHDRs. May be used and overwritten within functions.
GElf_Shdr shdr;
Elf32_Ehdr *elf_header;         /* ELF header */
Elf_Kind ek;
GElf_Ehdr ehdr;                 /* Elf header */
int fd;                 // File Descriptor
char *base_ptr;         // ptr to our object in memory

/*
 * FUNCTIONS
 */
void error(const char *msg, ...) {
	va_list va;
	va_start(va, msg);

	// Format String right here. Enjoy!
	printf(msg, va);
	exit(-1);
}

/**
 * write a embedded binary blob to a given file.
 */
int write_binary_blob(FILE *destination, struct embedded_binary *source) {
	size_t write_size = (size_t)source->end - (size_t)source->start;
	printf("\t\t -> Writing binary blob (%lu bytes)...", write_size);

	printf(" (embedded data: %p -> %p)", source->start, source->end);
	size_t i = fwrite (source->start, 1, write_size, destination);
	if (i == write_size) {
		printf(" OK!\n");
		return 0;
	}
	else {
		error(" Error!\n");
		return 1;
	}
}

/**
 * get the size of a binary blob.
 */
size_t binblob_size(struct embedded_binary *data) {
	return (size_t)data->end - (size_t)data->start + 1;
}

/*
 * Increase the size of the scn array
 */
void incScnArray(struct scn_array *a) {
	int i = 0;
	u32 *tmp = (u32 *)malloc(sizeof(u32) * (a->max_entries + 10));

	if (!tmp) {
		error("Could not allocate memory to increase Scn Array size!\n");
	}

	// Copy
	for (i = 0; i < a->next_free_entry; i++) {
		tmp[i] = a->elf_scn_index_array[i];
	}

	// Free
	free(a->elf_scn_index_array);

	// Update
	a->max_entries += 10;
	a->elf_scn_index_array = tmp;
}

void addScnToArray(struct scn_array *a, u32 index) {
	// Array full?
	if(a->max_entries == a->next_free_entry)
	{
		incScnArray(a);
	}

	// Set
	a->elf_scn_index_array[a->next_free_entry] = index;
	a->next_free_entry++;
}

u64 getSectionOffsetByName(const char *sec_name) {
	// Reset scn
	scn = NULL;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		// Get Header
		gelf_getshdr(scn, &shdr);

		if (strcmp(sec_name, elf_strptr(elf, shstrndx, shdr.sh_name)) == 0) {
			return shdr.sh_offset;
		}
	}

	printf("Could not find Section '%s'\n", sec_name);
	return 0;
}

u64 getSectionAddr(const char *sec_name) {
	// Reset scn
	scn = NULL;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		// Get Header
		gelf_getshdr(scn, &shdr);

		if (strcmp(sec_name, elf_strptr(elf, shstrndx, shdr.sh_name)) == 0) {
			return shdr.sh_addr;
		}
	}

	printf("Could not find Section '%s'\n", sec_name);
	return 0;
}

u64 getSymbolOffsetByName(const char *name) {
	GElf_Sym sym;
	char *str;
	Elf_Data *edata;
	u64 entries;
	u64 i;

	// Get Sym scn
	scn_sym = elf_getscn(elf, symtab_scn);

	// Header
	gelf_getshdr(scn_sym, &shdr);

	// Get edata
	edata = elf_getdata(scn_sym, NULL);

	// Get the number of entries
	entries = shdr.sh_size / shdr.sh_entsize;

	for (i = 0; i < entries; i++) {
		// Get symbol
		gelf_getsym(edata, i, &sym);

		// Get Name
		str = elf_strptr(elf, shdr.sh_link, sym.st_name);

		//if (str)
		//	printf("SYMBOL: %s\n", str);

		if(str && strcmp(name, str) == 0)
			return sym.st_value;
	}

	return -1;
}

/*
 * Resolve the symbols with the given index.
 * Note: This function will modify the global vars SHDR and edata!
 */
void resolveSymbol(u32 index, struct symbol *my_sym) {
	GElf_Sym sym;
	char *str;
	Elf_Data *edata;

	// Get Sym scn
	scn_sym = elf_getscn(elf, symtab_scn);

	// Header
	gelf_getshdr(scn_sym, &shdr);

	// Get edata
	edata = elf_getdata(scn_sym, NULL);

	// Get symbol
	gelf_getsym(edata, index, &sym);

	// Get Name
	str = elf_strptr(elf, shdr.sh_link, sym.st_name);

	// Get String if any
	if (str) {
		my_sym->str_len = strlen(str);

		// Reserve space for str.
		my_sym->str = malloc(sizeof(char) * (my_sym->str_len + 1));

		if (!my_sym->str) {
			error("Could not allocate memory for string!");
		}

		// Copy
		strcpy(my_sym->str, str);
		my_sym->str[my_sym->str_len] = '\0';
	}
	else {
		my_sym->str_len = 0;
		my_sym->str = NULL;
	}

	// Is the symbol a function
	if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC)
		my_sym->function = 1;
	else
		my_sym->function = 0;

	// Is this an external symbol?
	if (sym.st_shndx != SHN_UNDEF) {
		// This symbol points to an offset within a section that needs to be replaced.
		my_sym->resolve = 0;

		// Get Sym scn
		scn = elf_getscn(elf, sym.st_shndx);

		// Get Header
		gelf_getshdr(scn, &shdr);

		// Set Offset
		my_sym->value = shdr.sh_offset + sym.st_value;

		// Get name of the section if the symbol has no name yet
		if(!my_sym->str_len) {
			str = elf_strptr(elf, shstrndx, shdr.sh_name);

			my_sym->str_len = strlen(str);

			// Reserve space for str.
			my_sym->str = malloc(sizeof(char) * (my_sym->str_len + 1));

			if (!my_sym->str) {
				error("Could not allocate memory for string!");
			}

			// Copy
			strcpy(my_sym->str, str);
			my_sym->str[my_sym->str_len] = '\0';
		}
	}
	else {
		my_sym->resolve = 1;
	}
}

void parseRelaSections() {
	int i, j = 0;
	int count = 0;
	Elf_Data *edata;
	GElf_Rela rela;
	char *str, *str_copy;
	u32 str_len;

	// Do we have to do anything?
	if (rela_scns.next_free_entry == 0)
		return;

	// Reserve memory?
	if (!symbols) {
		symbols = malloc(sizeof(struct symbol) * (rel_count + rela_count));
		symbol_count = 0;

		if (!symbols) {
			error("Could not reserve memory for symbols!\n");
		}
	}


	printf("Parsing %lu RELA sections...", rela_scns.next_free_entry);

	for (i = 0; i < rela_scns.next_free_entry; i++) {
		printf(" %d", i + 1);

		// Get Scn
		scn_rela = elf_getscn(elf, rela_scns.elf_scn_index_array[i]);

		// Header
		gelf_getshdr(scn_rela, &shdr);

		// Get Edata
		edata = elf_getdata(scn_rela, NULL);

		// Count
		count = shdr.sh_size / shdr.sh_entsize;

		// Set target addr
		symbols[symbol_count].target_addr = 0;

		for (j = 0; j < count; j++) {
			// Get Rela
			gelf_getrela(edata, j, &rela);

			// Resolve Symbol
			resolveSymbol(ELF64_R_SYM(rela.r_info), &symbols[symbol_count]);

			// Save type
			symbols[symbol_count].type = ELF64_R_TYPE(rela.r_info);

			// Do we need to resolve this symbol within the shellcode?
			if (!symbols[symbol_count].resolve) {
				// No. Add the necessary offset to the value.
				symbols[symbol_count].value += rela.r_addend;
				symbols[symbol_count].addend = rela.r_addend;
			}
			else
				symbols[symbol_count].addend = rela.r_addend;

			// Lookup the section offset of the target addr.
			gelf_getshdr(scn_rela, &shdr); // Just to be sure, may have been used.

			// Get Section name
			str = elf_strptr(elf, shstrndx, shdr.sh_name);

			// Copy string to make sure it is not overwritten
			if (str)
				str_len = strlen(str);
			else
				error("Found RELA section with no name!\n");

			str_copy = malloc(sizeof(char) * (str_len + 1));

			if (!str_copy) {
				error("Could not allocate memory for string copy!\n");
			}

			strcpy(str_copy, str);
			str_copy[str_len] = '\0';

			// Look for ".rela", since we have to remove that part
			str_len = strlen(".rela");

			if (strncmp(str_copy, ".rela", str_len) == 0) {
				// Remove .rela
				str_copy += str_len;
			}

			symbols[symbol_count].target_addr = getSectionOffsetByName(str_copy);
			symbols[symbol_count].target_addr += rela.r_offset;
			symbols[symbol_count].offset = rela.r_offset;

			//free(str_copy);

			/*
			  if(symbols[symbol_count].resolve)
			  printf("\n %s -> 0x%llx\n", symbols[symbol_count].str, symbols[symbol_count].target_addr);
			  else
			  printf("\n 0x%llx -> 0x%llx\n", symbols[symbol_count].value, symbols[symbol_count].target_addr);
			*/

			// Increase Symbol count
			symbol_count++;
		}
	}

	printf(" OK!\n");
}

void writeIntReverse(FILE *fp, u64 data) {
	char tmp[8];
	u64 copy = data;
	int i = 0;

	// Prepare
	for (i = 0; i < 8; i++) {
		tmp[i] = copy & 0xff;
		copy = copy >> 8;
	}

	// Write
	i = fwrite (tmp, 1, 8, fp);
	if (i != 8)
		error("An error occurred while writing an integer in reverse.\n");


}

/*
 * Get the offset within the text section of the kernel_esp variable.
 * We thereby assume kernel_esp is the first variable within .text.
 */
u64 getKernelEspOffset(char *filename)
{
	FILE *wrapper;
	char cmd[2048];
	u64 result = 0;

	// Build command
	sprintf(cmd, "objdump -h %s | grep .text | awk '{print $6}'", filename);

	// Execute
	wrapper = popen(cmd, "r");

	// Check
	if (!wrapper) {
		error("Could not execute command %s\n", cmd);
	}

	// Read data
	if (fscanf(wrapper, "%llx", &result) <= 0) {
		error("Could not obtain the location of the kernel_esp variable!\n");
		return 0;
	}
	else
		return result;
}

struct wrapper *getWrapperNames(void)
{
	u32 i = 0;
	char line[1024];
	char *current_wrapper = NULL;
	FILE *f = fopen(wrapper_file, "r");
	struct wrapper *w = malloc(sizeof(struct wrapper));

	if (!w)
		error("Could not allocate memory for the wrapper structure!\n");

	if (!f) {
		printf("Could not open wrapper file ('%s')!\n", wrapper_file);
		error("");
	}

	// Get the number of lines
	w->size = 0;

	while (fgets(line, 1024, f))
		w->size++;

	// Allocate memory
	w->wrapper = malloc(w->size * sizeof(char *));

	if (!w->wrapper)
		error("Could not allocate memory for the wrapper array!\n");

	// Get each wrapper
	fseek (f, 0, SEEK_SET);

	while (fgets(line, 1024, f)) {
		// Copy wrapper
		current_wrapper = malloc(sizeof(char) * strlen(line) + 1);

		if (!current_wrapper)
			error("Could not allocate memory for an individual wrapper!\n");

		strcpy(current_wrapper, line);

		// Replace newline character if there is one
		if (current_wrapper[strlen(line) - 1] == '\n')
			current_wrapper[strlen(line) - 1] = '\0';

		// Add
		w->wrapper[i] = current_wrapper;
		i++;
	}

	return w;
}

void generateShellcode(const char *input_filename, const char *out_filename, u64 elf_size,
                       u64 system_map_begin, u64 system_map_end) {
	int i, j;
	u64 resolve_num = 0;
	u64 strlen_resolve_syms = 0;
	u64 patch_num = 0;
	u64 esp_patch_num = 0;
	u32 shellcode_complete_offset = 0;
	FILE *inject_file = NULL;
	FILE *inject_mcount_file = NULL;
	FILE *inject_wrapper_file = NULL;
	char *out_mcount_file = NULL;
	char *out_wrapper_file = NULL;
	char *tmp = NULL;
	char nop[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"; //10
	char orig_data[elf_size];

	u32 wrapper_size = 0;
	char *wrapper_tmp_name = NULL;
	char *wrapper_tmp_file = NULL;
	int wrapper_fd = 0;
	struct stat wrapper_stats;
	u64 *wrapper_esp_addresses = NULL;
	u64 *wrapper_patch_addresses_value = NULL;
	u64 *wrapper_patch_addresses_target = NULL;
	u32 wrapper_number = 0;
	u64 wrapper_esp_offset = 0;
	struct wrapper *w = NULL;

	size_t printf_shellcode_size = binblob_size(&printf_shellcode);

	// Go!
	printf("Generating Injection File...\n");

	// Parse wrapper
	printf("\t -> Parsing wrapper names from '%s'... ", wrapper_file);
	w = getWrapperNames();
	printf("Found %lu wrappers!\n", w->size);

	// Get the number of patch and resolve symbols
	for (i = 0; i < symbol_count; i++) {
		if (symbols[i].resolve && strcmp(symbols[i].str, "printk") != 0) {
			// Ignore "mcount"
			if (strcmp(symbols[i].str, "mcount") == 0) {
				continue;
			}

			// Resolve symbols
			resolve_num++;
			strlen_resolve_syms += (symbols[i].str_len + 1);

			// Check for wrapper function
			for (j = 0; j < w->size; ++j) {
				if (strcmp(symbols[i].str, w->wrapper[j]) == 0) {
					esp_patch_num++;
					// Mark symbol as function
					symbols[i].function = 1;
					break;
				}
			}
		}
		else {
			// Ignore "init_module" && "cleanup_module"
			if(strcmp(symbols[i].str, "cleanup_module") != 0
			   && strcmp(symbols[i].str, "init_module") != 0) {
				patch_num++;
			}
		}
	}

	// Generate Filename
	tmp = strrchr(input_filename, '.');

	if (!tmp)
		tmp = strlen(input_filename) + (char *)input_filename;

	// Temporary outfile for mcount fix
	out_mcount_file = malloc(sizeof(char) * (tmp - input_filename + 1 + strlen(".inject.mcount") + 1));
	strncpy(out_mcount_file, input_filename, tmp - input_filename);
	strncpy(out_mcount_file + (tmp - input_filename), ".inject.mcount", strlen(".inject.mcount"));
	out_mcount_file[tmp - input_filename + 1 + strlen(".inject.mcount")] = '\0';

	// Temorary ouftile for wrapper
	out_wrapper_file = malloc(sizeof(char) * (tmp - input_filename + 1 + strlen(".inject.wrapper") + 1));
	strncpy(out_wrapper_file, input_filename, tmp - input_filename);
	strncpy(out_wrapper_file + (tmp - input_filename), ".inject.wrapper", strlen(".inject.wrapper"));
	out_wrapper_file[tmp - input_filename + 1 + strlen(".inject.wrapper")] = '\0';

	printf("\t -> Outfile will be %s\n", out_filename);

	// Calulcate Shellcode offsets
	printf("\t -> Calculating Offsets...\n");

	/*
	 * Entry Point                      8
	 * PATCH SYM COUNT                  8 = x
	 * Per PATCH Symbol                 x *
	 *      Target Addr                     8
	 *      Value                           8
	 * ESP PATCH SYMS COUNT             8 = e
	 * Per ESP PATCH SYM                e *
	 *      Target Addr                 8
	 *
	 * Systemmap Begin                  8
	 * Systemmap End                    8
	 * RESOLVE SYMS COUNT               8 = y
	 * Per RESOLVE Symbol               y *
	 *      Length of String                8
	 *      String Variable Length          z
	 *      Target Addr                     8
	 *                                      =
	 *                                      y * 16 + z1 + z2 ... zN
	 *
	 *  TOTAL: 8 + 8 + x * 16 + 8 + 8  + e * 8 + 8 + 8 + 8 + y * 16 + z1 + z2 ... zN
	 */

	// Patch Syms
	shellcode_complete_offset = 8 + 8 + ((patch_num + esp_patch_num) * (8 + 8));
	// ESP Patch Syms
	shellcode_complete_offset += (8 + (esp_patch_num * 8));
	// Resolve
	shellcode_complete_offset += 8 + 8 + 8 + (resolve_num * (8 + 8)) + strlen_resolve_syms;
	printf("\t\t # COMPLETE shellcode offset is 0x%lx\n", shellcode_complete_offset);

	// Write file
	printf("\t -> Creating File %s...", out_filename);
	inject_file = fopen(out_filename, "wb+");

	if (!inject_file) {
		printf(" Could not open file '%s'\n", out_filename);
		error("");
	}
	printf(" OK!\n");

	// Shellcode first
	printf("\t -> Writing Shellcode ...\n");

	if (0 != write_binary_blob(inject_file, &shellcode)) {
		error("An error occurred while writing the shellcode.\n");
	}

	// Entry Point
	printf("\t -> Calculating NEW Entry Point...");
	// Resolve sym 2 DW - Begin Map, End Map 2 DW - Count 1 DW - Strlen Syms
	entry_point += shellcode_complete_offset;
	printf("OK! Entry Point @ 0x%llx\n", entry_point);

	printf("\t -> Writing Entry Point... ");
	writeIntReverse(inject_file, entry_point);
	printf("OK!\n");


	// ESP Patch syms
	// Must be considered first to be able to write the correct patch symbols
	if (esp_patch_num > 0) {
		printf("\t -> Generating WRAPPER file '%s' for %llu external function(s)...\n", out_wrapper_file, esp_patch_num);

		// Reserve space
		wrapper_esp_addresses = (u64 *)malloc(sizeof(u64) * esp_patch_num);
		wrapper_patch_addresses_value = (u64 *)malloc(sizeof(u64) * esp_patch_num);
		wrapper_patch_addresses_target = (u64 *)malloc(sizeof(u64) * esp_patch_num);

		if (!wrapper_esp_addresses || !wrapper_patch_addresses_value || !wrapper_patch_addresses_target)
			error("\nERROR: Could not reserve memory for the wrapper addresses!\n");
	}
	else
		printf("\t -> No external functions detected. No wrappers necessary.\n");



	// Open wrapper file
	inject_wrapper_file = fopen(out_wrapper_file, "wb");

	if (!inject_wrapper_file) {
		printf("Could not open wrapper file '%s'!\n", out_wrapper_file);
		error("");
	}

	for (i = 0; i < symbol_count; i++) {
		if (symbols[i].resolve &&
		    symbols[i].function &&
		    strcmp(symbols[i].str, "mcount") != 0 &&
		    strcmp(symbols[i].str, "printk") != 0) {
			printf("\t\t # Trying to find a WRAPPER for '%s'...\n", symbols[i].str);

			// Try to find wrapper
			// Reserve space for name: wrapper_path/sym_name/sym_name\0
			wrapper_tmp_name = (char *)malloc(sizeof(char) * (strlen(symbols[i].str) * 2 + strlen(wrapper_path) + 2));

			// Build name
			strcpy(wrapper_tmp_name, wrapper_path);
			strcat(wrapper_tmp_name, symbols[i].str);
			strcat(wrapper_tmp_name, "/");
			strcat(wrapper_tmp_name, symbols[i].str);

			if ((wrapper_fd = open(wrapper_tmp_name, O_RDONLY)) < 0) {
				printf("\nERROR: Could not open file '%s'\n", wrapper_tmp_name);
				error("");
			}

			printf("\t\t\t <> Found Wrapper '%s'...\n", wrapper_tmp_name);

			if ((fstat(wrapper_fd, &wrapper_stats))) {
				close(wrapper_fd);
				printf("\nERROR: Could not open file '%s'\n", wrapper_tmp_name);
				error("");
			}

			if ((wrapper_tmp_file = (char *) malloc(wrapper_stats.st_size)) == NULL) {
				close(wrapper_fd);
				error("\nERROR: Could not reserve memory to store wrapper file.\n");
			}

			printf("\t\t\t <> Reading Wrapper...\n");

			if ((read(wrapper_fd, wrapper_tmp_file, wrapper_stats.st_size)) < wrapper_stats.st_size) {
				close(fd);
				free(wrapper_tmp_name);
				free(wrapper_tmp_file);
				error("Could not read file %s\n");
			}

			printf("\t\t\t <> Writing Wrapper...\n");

			// copy original file
			j = fwrite (wrapper_tmp_file, 1, wrapper_stats.st_size, inject_wrapper_file);

			if (j != wrapper_stats.st_size)
				error("\nERROR: Wrapper write was incomplete!\n");

			// Get esp offset
			wrapper_esp_offset = getKernelEspOffset(wrapper_tmp_name);
			printf("\t\t\t <> Found Kernel ESP Offset @ 0x%llx...\n", wrapper_esp_offset);

			// Add address to esp patch symbols
			printf("\t\t\t <> Kernel Stack address will be written to 0x%llx...\n", (shellcode_complete_offset + elf_size + printf_shellcode_size + wrapper_size + wrapper_esp_offset));

			wrapper_esp_addresses[wrapper_number] = shellcode_complete_offset + elf_size + printf_shellcode_size+ wrapper_size + wrapper_esp_offset;

			// Substitute the original call within the module with the call to the wrapper
			printf("\t\t\t <> '%s' @ 0x%llx will be set to 0x%llx...\n", symbols[i].str,
			       symbols[i].target_addr + shellcode_complete_offset,
			       shellcode_complete_offset + elf_size + printf_shellcode_size + wrapper_size + wrapper_esp_offset + 0x10);

			wrapper_patch_addresses_target[wrapper_number] = symbols[i].target_addr + shellcode_complete_offset;
			wrapper_patch_addresses_value[wrapper_number] = shellcode_complete_offset + elf_size + printf_shellcode_size + wrapper_size + wrapper_esp_offset + 0x10;

			// Fix Target address - We assume a fixed offset here - Ignore complete offset,
			// by the resolve offset part
			symbols[i].target_addr = elf_size + printf_shellcode_size + wrapper_size + wrapper_esp_offset + 8;

			// Update wrapper size
			wrapper_size += wrapper_stats.st_size;

			// Update wrapper counter
			wrapper_number++;

			// free data
			free(wrapper_tmp_name);
			free(wrapper_tmp_file);
		}
	}

	fclose(inject_wrapper_file);

	// Patch Symbols
	printf("\t -> Writing Patch Symbols (%llu)... \n", patch_num + esp_patch_num);
	writeIntReverse(inject_file, patch_num + esp_patch_num); // Count

	for (i = 0; i < symbol_count; i++) {
		if (!symbols[i].resolve &&
		   strcmp(symbols[i].str, "cleanup_module") != 0 &&
		   strcmp(symbols[i].str, "init_module") != 0) {
			// Output
			if (symbols[i].addend)
				printf("\t\t # PATCH 0x%llx (offset 0x%llx) will be set to '%s + 0x%llx' (0x%llx)\n",
				       symbols[i].target_addr + shellcode_complete_offset,
				       symbols[i].offset,
				       symbols[i].str, symbols[i].addend,
				       symbols[i].value + shellcode_complete_offset);
			else
				printf("\t\t # PATCH 0x%llx (offset 0x%llx) will be set to '%s' (0x%llx)\n",
				       symbols[i].target_addr + shellcode_complete_offset,
				       symbols[i].offset,
				       symbols[i].str,
				       symbols[i].value + shellcode_complete_offset);

			// Write
			writeIntReverse(inject_file, symbols[i].target_addr + shellcode_complete_offset);
			writeIntReverse(inject_file, symbols[i].value + shellcode_complete_offset);
		}
		else if(strcmp(symbols[i].str, "printk") == 0) {
			printf("\t\t # FUNCTION PATCH printk @ 0x%llx (offset 0x%llx) will be set to 0x%llx\n",
			       symbols[i].target_addr + shellcode_complete_offset,
			       symbols[i].offset,
			       elf_size + shellcode_complete_offset);

			writeIntReverse(inject_file, symbols[i].target_addr + shellcode_complete_offset);
			writeIntReverse(inject_file, elf_size + shellcode_complete_offset);
		}
	}

	// Write the addresses of the wrappers
	for (i = 0; i < esp_patch_num; i++) {
		printf("\t\t # Setting Function @ 0x%llx to call Wrapper @ 0x%llx...\n",
		       wrapper_patch_addresses_target[i],
		       wrapper_patch_addresses_value[i]);

		writeIntReverse(inject_file, wrapper_patch_addresses_target[i]);
		writeIntReverse(inject_file, wrapper_patch_addresses_value[i]);
	}

	// Write the ESP_PATCH data
	printf("\t -> Writing ESP Patch Symbols (%llu)... \n", esp_patch_num);
	writeIntReverse(inject_file, esp_patch_num); // Count

	// Write addresses
	for(i = 0; wrapper_esp_addresses && i < esp_patch_num; i++)
	{
		printf("\t\t # Kernel ESP will be written to 0x%llx...\n", wrapper_esp_addresses[i]);
		writeIntReverse(inject_file, wrapper_esp_addresses[i]);
	}

	// free wrapper addresses
	free(wrapper_esp_addresses);
	free(wrapper_patch_addresses_target);
	free(wrapper_patch_addresses_value);

	// Symmap
	printf("\t -> Writing Symmap begin... 0x%08llx ", system_map_begin);
	writeIntReverse(inject_file, system_map_begin);
	printf("OK!\n");

	printf("\t -> Writing Symmap end... 0x%08llx ", system_map_end);
	writeIntReverse(inject_file, system_map_end);
	printf("OK!\n");

	// Resolve Symbols
	printf("\t -> Writing Resolve Symbols (%llu)... \n", resolve_num);
	writeIntReverse(inject_file, resolve_num); // Count

	for(i = 0; i < symbol_count; i++)
	{
		if(symbols[i].resolve &&
		   strcmp(symbols[i].str, "mcount") != 0 &&
		   strcmp(symbols[i].str, "printk") != 0)
		{
			printf("\t\t # RESOLVE %s @ 0x%llx must be resolved...\n", symbols[i].str,
			       symbols[i].target_addr + shellcode_complete_offset);

			writeIntReverse(inject_file, (symbols[i].str_len + 1)); // Str Len
			fwrite(symbols[i].str, 1, symbols[i].str_len + 1, inject_file); // Str
			writeIntReverse(inject_file, symbols[i].target_addr + shellcode_complete_offset); // Target
		}
		else if(symbols[i].resolve && strcmp(symbols[i].str, "mcount") == 0)
		{
			if(!inject_mcount_file)
			{
				// Open mcount
				inject_mcount_file = fopen(out_mcount_file, "wb");

				if(!inject_mcount_file)
				{
					printf("Could not open mcount file '%s' for writing\n", out_mcount_file);
					error("");
				}

				// copy original file
				j = fwrite (base_ptr, 1, elf_size, inject_mcount_file);

				if(j != elf_size)
					error("An error occurred while writing the binary.\n");

				fclose(inject_mcount_file);
			}

			// Open file for read and update
			inject_mcount_file = fopen(out_mcount_file, "rb+");

			if(!inject_mcount_file)
			{
				printf("Could not open mcount file '%s' for updating\n", out_mcount_file);
				error("");
			}

			if(fseek(inject_mcount_file, (symbols[i].target_addr - 1), SEEK_SET)) {
				error("Could not seek to position in mcount file!\n");
			}

			if(symbols[i].type == R_X86_64_64)
			{
				// 8 byte + call
				fwrite(nop, 1, 9, inject_mcount_file);
			}
			else
			{
				// 4 byte + call
				fwrite(nop, 1, 5, inject_mcount_file);
			}

			printf("\t\t # RESOLVE patching mcount @ 0x%llx...\n", symbols[i].target_addr);

			fclose(inject_mcount_file);
		}
	}

	// Write Binary
	printf("\t -> Writing Binary... ");

	//try to open mcount file, otherwise just copy the original kernel module contents
	if ((inject_mcount_file = fopen(out_mcount_file, "rb")) == NULL) {
		printf(" copying original kernel module contents... ");
		i = fwrite (base_ptr, 1, elf_size, inject_file);
	}
	else {
		printf(" using mcount file as kernel module source: %s... ", out_mcount_file);

		i = fread (orig_data, 1, elf_size, inject_mcount_file);

		if(i != elf_size)
			error("An error occurred while reading the mcount file.\n");

		fclose(inject_mcount_file);

		// Write data
		i = fwrite (orig_data, 1, elf_size, inject_file);

		if(i == elf_size)
			printf("OK!\n");
		else
			error("An error occurred while writing the binary.\n");
	}
	printf("OK!\n");

	// PrintK
	printf("\t -> Writing 'printk' Wrapper...\n");

	if(0 != write_binary_blob(inject_file, &printf_shellcode)) {
		error("An error occurred while writing the printk wrapper.\n");
	}

	// Open and write wrapper file
	if(esp_patch_num > 0)
	{
		printf("\t -> Writing Remaining Wrapper Section... ");
		inject_wrapper_file = fopen(out_wrapper_file, "rb");

		if(!inject_wrapper_file)
		{
			printf("\nERROR: Could not open wrapper file '%s' for copying\n", out_wrapper_file);
			error("");
		}

		if((wrapper_tmp_file = (char *) malloc(wrapper_size * sizeof(char))) == NULL)
		{
			error("\nERROR: Could not reserve memory to store wrapper file.\n");
		}

		i = fread (wrapper_tmp_file, 1, wrapper_size, inject_wrapper_file);

		if(i != wrapper_size)
			error("\nERROR: An error occurred while reading the wrapper file.\n");

		fclose(inject_wrapper_file);

		i = fwrite (wrapper_tmp_file, 1, wrapper_size, inject_file);

		if(i == wrapper_size)
			printf("OK!\n");
		else
			error("\nERROR: An error occurred while writing the wrapper section.\n");
	}

	fclose(inject_file);
}

void printUsage(char *argv[])
{
	printf("\nUsage: %s [<options>] <kernelmodule>\n", argv[0]);
	printf("\n\t <kernelmodule>        The complete path to the Linux kernel module (*.ko) that should be parsed.\n\n");
	printf("\t Options:\n");
	printf("\t\t -i, --init-function\tThe name of the function that should be executed when the module is loaded.\n");
	printf("\t\t                    \tDEFAULT = '%s'\n", init_function);
	printf("\t\t -w, --wrapper-file \tThe path to the text file that contains all functions that are substituted by a wrapper.\n");
	printf("\t\t                    \tDEFAULT = '%s'\n", wrapper_file);
	printf("\t\t -d, --wrapper-path \tThe path to the directory that contains the wrapper functions.\n");
	printf("\t\t                    \tDEFAULT = '%s'\n", wrapper_path);
	printf("\t\t -e, --extension    \tThe extension of the transformed module. It's name will be equal to the module name.\n");
	printf("\t\t                    \tDEFAULT = '%s'\n\n", extension);
	printf("\t\t -o, --output       \t");
	printf("\t\t                    \tDEFAULT = '<kernelmodule>.inject'\n\n");
}

int main(int argc, char *argv[])
{

	const char *input_file_name = 0;   // filename
	char *generated_output_file_name = NULL;
	const char *output_file_name = NULL;

	struct stat elf_stats;  // fstat struct
	int count = 0;
	int i = 0;
	int option_index = 0;
	int option = 0;

	//TODO: remove hardcoding
	u64 sysmap_begin = 0xffffffff8175e010;  //__start___ksymtab
	u64 sysmap_end   = 0xffffffff81775f50;  //__stop___ksymtab_gpl

	// Parse options
	while ((option = getopt_long (argc, argv, "hw:d:e:i:o:", options, &option_index)) != -1)
	{
		switch (option) {
		case 'w':
			wrapper_file = optarg;
			break;
		case 'd':
			wrapper_path = optarg;
			break;
		case 'e':
			extension = optarg;
			break;
		case 'i':
			init_function = optarg;
			break;
		case 'o':
			output_file_name = optarg;
			break;
		case '?':
			// Never returns
			printUsage(argv);
			break;
		default:
			// Never returns
			printUsage(argv);
			return 10;
		}
	}

	// Get file name
	if (argc < 2 || optind >= argc) {
		// Never returns
		printUsage(argv);
		return 10;
	}
	else {
		input_file_name = argv[optind];
	}

	// Generate Filename
	char *extension_offset = strrchr(input_file_name, '.');

	//generate output file name from input file name
	//if the output is not given as argument
	if (output_file_name == NULL) {
		size_t output_str_len = ((extension_offset - input_file_name + 1) + strlen(extension) + 1);
		printf("output str len: %d\n", output_str_len);
		generated_output_file_name = (char *)malloc(sizeof(char) * output_str_len);

		if (generated_output_file_name == NULL) {
			printf("fail trying to alloc mem for output filename.\n");
			return 1;
		}

		strncpy(generated_output_file_name, input_file_name, extension_offset - input_file_name);
		strncpy(generated_output_file_name + (extension_offset - input_file_name), extension, strlen(extension));

		generated_output_file_name[extension_offset - input_file_name + 1 + strlen(extension)] = '\0';

		output_file_name = generated_output_file_name;
	}


	shellcode.start        = _binary_shellcode_bin_start;
	shellcode.end          = _binary_shellcode_bin_end;
	printf_shellcode.start = _binary_printf_shellcode_bin_start;
	printf_shellcode.end   = _binary_printf_shellcode_bin_end;


	// Print settings
	printf("\n\t X-TIER Linux Kernel Module Parser\n");
	printf("\t\t |_ Processing File:           '%s'\n", input_file_name);

	if (init_function) {
		printf("\t\t |_ Init Function:             '%s'\n", init_function);
	}
	printf("\t\t |_ Wrappers are specified in: '%s'\n", wrapper_file);
	printf("\t\t |_ Wrappers are located at:   '%s'\n", wrapper_path);
	printf("\t\t |_ Resulting file will be:    '%s'\n\n", output_file_name);

	if((fd = open(input_file_name, O_RDONLY)) < 0)
		error("Could not open file '%s'\n", input_file_name);

	if((fstat(fd, &elf_stats)))
	{
		close(fd);
		error("Could not fstat file\n");
	}

	if((base_ptr = (char *) malloc(elf_stats.st_size)) == NULL)
	{
		close(fd);
		error("Could not reserve memory\n");
	}

	if((read(fd, base_ptr, elf_stats.st_size)) < elf_stats.st_size)
	{
		close(fd);
		free(base_ptr);
		error("Could not read file\n");
	}



	/* Check libelf version first */
	if(elf_version(EV_CURRENT) == EV_NONE)
		error("LIBELF initialization failed!\n");


	elf_header = (Elf32_Ehdr *) base_ptr;   // point elf_header at our object in memory
	elf = elf_begin(fd, ELF_C_READ, NULL);  // Initialize 'elf' pointer to our file descriptor


	ek = elf_kind(elf);

	printf("Checking for ELF Executable Object... ");

	if (ek != ELF_K_ELF)
		error("This does not seem to be an ELF binary!\n");

	printf("OK! Seems to be executable\n");

	printf("Checking Class... ");
	gelf_getehdr(elf, &ehdr);
	elf_getshdrstrndx(elf, &shstrndx);
	i = gelf_getclass(elf);

	if (i ==  ELFCLASS32)
		error("32-Bit Binary detected. Only 64-Bit is supported as of now.");

	printf("OK! 64-Bit binary found\n");


	printf("Obtaining necessary sections...\n");

	while((scn = elf_nextscn(elf, scn)) != NULL)
	{
		gelf_getshdr(scn, &shdr);

		switch(shdr.sh_type)
		{
		case SHT_REL:
			count = shdr.sh_size / shdr.sh_entsize;
			rel_count += count;

			if(count > 1)
				printf("\t -> Found REL section '%s' containing %d entries\n", elf_strptr(elf, shstrndx, shdr.sh_name), count);
			else
				printf("\t -> Found REL section '%s' containing %d entry\n", elf_strptr(elf, shstrndx, shdr.sh_name), count);

			addScnToArray(&rel_scns, elf_ndxscn(scn));
			break;
		case SHT_RELA:
			count = shdr.sh_size / shdr.sh_entsize;
			rela_count += count;

			if(count > 1)
				printf("\t -> Found RELA section '%s' containing %d entries\n", elf_strptr(elf, shstrndx, shdr.sh_name), count);
			else
				printf("\t -> Found RELA section '%s' containing %d entry\n", elf_strptr(elf, shstrndx, shdr.sh_name), count);

			addScnToArray(&rela_scns, elf_ndxscn(scn));
			break;
		case SHT_SYMTAB:
			count = shdr.sh_size / shdr.sh_entsize;
			printf("\t -> Found '.symtab' section cotaining %d symbols\n", count);

			symtab_scn = elf_ndxscn(scn);

			break;
		default:
			break;
		}

	}

	if(!symtab_scn)
		error("Could not find symbol table!\n");

	// Parse Sections
	parseRelaSections();

	// Find entry Point
	entry_point = 0;
	printf("Looking for entry point...\n");

	// Find entry point
	if(init_function && (entry_point = getSymbolOffsetByName(init_function)) != -1)
	{
		entry_point = entry_point - getSectionAddr(".text") + getSectionOffsetByName(".text");
		printf("\t -> Found entry function '%s' @ 0x%llx\n", init_function,  entry_point);
	}
	else if(argc == 3)
	{
		// Could not find entry function
		printf("\n! WARNING WARNING WARNING WARNING !\n");
		printf("WARNING could not find entry function '%s' will use init...\n", init_function);
		printf("\n! WARNING WARNING WARNING WARNING !\n");
	}

	// Could not find the entry_function or none given
	if(entry_point == 0)
	{
		if(ehdr.e_entry)
			entry_point = ehdr.e_entry - getSectionAddr(".text") + getSectionOffsetByName(".text");
		else
			entry_point = getSectionOffsetByName(".init.text");
	}

	printf("\t -> Entry Point @ 0x%llx\n", entry_point);

	// Go for it
	generateShellcode(input_file_name, output_file_name, elf_stats.st_size, sysmap_begin, sysmap_end);

	printf("\n\nDONE.\n");

	return 0;
}
