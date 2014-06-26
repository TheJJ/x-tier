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

#include "../../../tmp/sysmap.h"


#define ERROR(fmt, ...) \
	printf(fmt, ##__VA_ARGS__); \
	exit(1); \


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
const char *wrapper_filename      = "wrapper.txt";
const char *extension             = ".inject";
const char *init_function         = NULL;
const char *default_init_function = "module_init";
const char *wrapper_suffix        = ".elf";

/*
 * STRUCTS
 */
struct scn_array {
	u32 next_free_entry;
	u32 max_entries;
	u32 *elf_scn_index_array;
};

struct symbol {
	u8    resolve;
	u64   str_len;
	char *str;
	u64   target_addr;
	u64   value;
	u64   addend;
	u64   offset;
	u32   type;
	u8    function;
};


struct wrappers {
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

struct input_elf_file {
	int               fd;
	u64               size;
	struct stat       stats;
	Elf              *elf;
	Elf_Kind          kind;
	Elf64_Ehdr       *header;
	char             *data;
	size_t            section_string_idx;
	u32               symtab_section_idx;
	u32               rel_count; //0
	struct scn_array  rel_scns;
	u32               rela_count; //0
	struct scn_array  rela_scns;
	u64               entry_point; //0
	struct symbol    *symbols;
	u32               symbol_count; //0
};

struct wrapper_patch {
	u64 esp_address;
	u64 address_value;
	u64 address_target;
	char *function_name;
};

// An array for the rel scn pointer
//struct scn_array rel_scns;
// An array for the rela scn pointer
//struct scn_array rela_scns;
// The index of the symtab scn
//u32 symtab_scn = 0;

// Count of entries within the sections
//u32 rela_count = 0;
//u32 rel_count = 0;
// Section Table Index
//size_t shstrndx;
//Elf        *elf;
//Elf_Scn    *scn;
//Elf32_Ehdr *elf_header;
//Elf64_Shdr  shdr;
//Elf_Kind    ek;
//Elf64_Ehdr  ehdr;
//int         fd;
//char       *base_ptr;           // ptr to our object in memory


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


void parse_rela_sections(struct input_elf_file *f);

/*
 * size extension for section array
 */
void array_increase_size(struct scn_array *a) {
	u32 *tmp = (u32 *)malloc(sizeof(u32) * (a->max_entries + 10));

	if (!tmp) {
		ERROR("Could not allocate memory to increase Scn Array size!\n");
	}

	// Copy
	for (int i = 0; i < a->next_free_entry; i++) {
		tmp[i] = a->elf_scn_index_array[i];
	}

	// Free
	free(a->elf_scn_index_array);

	// Update
	a->max_entries += 10;
	a->elf_scn_index_array = tmp;
}


void array_add_section_idx(struct scn_array *a, u32 index) {
	// Array full?
	if(a->max_entries == a->next_free_entry) {
		array_increase_size(a);
	}

	// Set
	a->elf_scn_index_array[a->next_free_entry] = index;
	a->next_free_entry++;
}


struct input_elf_file init_elf_file(const char *filename) {
	struct input_elf_file ret = {
		.size               = 0,
		.elf                = NULL,
		.kind               = -1,
		.header             = NULL,
		.data               = NULL,
		.section_string_idx = -1,
		.symtab_section_idx = -1,
		.rel_count          = 0,
		.rela_count         = 0,
		.entry_point        = 0,
		.symbols            = NULL,
		.symbol_count       = 0,
	};

	if ((ret.fd = open(filename, O_RDONLY)) < 0) {
		ERROR("Could not open input file '%s'\n", filename);
	}

	struct stat *kmod_file_stats = &ret.stats;

	if ((fstat(ret.fd, kmod_file_stats))) {
		close(ret.fd);
		ERROR("Could not fstat file '%s'\n", filename);
	}

	ret.size = kmod_file_stats->st_size;

	if ((ret.data = (char *) malloc(ret.size)) == NULL) {
		close(ret.fd);
		ERROR("Could not reserve memory for file '%s'\n", filename);
	}

	if ((read(ret.fd, ret.data, ret.size)) < ret.size) {
		close(ret.fd);
		free(ret.data);
		ERROR("Could not read file '%s'\n", filename);
	}

	ret.header = (Elf64_Ehdr *) ret.data;

	printf("\t\t => initialized libelf for '%s'\n", filename);

	return ret;
}

void parse_elf_file(struct input_elf_file *f) {
	f->elf  = elf_begin(f->fd, ELF_C_READ, NULL);
	f->kind = elf_kind(f->elf);

	if (f->kind != ELF_K_ELF) {
		ERROR("This does not seem to be an ELF binary!\n");
	}

	gelf_getehdr(f->elf, f->header);
	elf_getshdrstrndx(f->elf, &f->section_string_idx);
	int n = gelf_getclass(f->elf);

	if (n ==  ELFCLASS32) {
		ERROR("32-Bit Binary detected. Only 64-Bit is supported as of now.");
	}

	Elf_Scn *section = NULL;

	while ((section = elf_nextscn(f->elf, section)) != NULL) {
		Elf64_Shdr section_header;
		gelf_getshdr(section, &section_header);

		int count = 0;
		if (section_header.sh_entsize > 0) {
			count = section_header.sh_size / section_header.sh_entsize;
		} else {
			continue;
		}

		const char *section_type_name = "";

		int print_section_stats = 1;

		switch(section_header.sh_type) {
		case SHT_REL:
			f->rel_count += count;
			section_type_name = "REL";
			array_add_section_idx(&f->rel_scns, elf_ndxscn(section));
			break;

		case SHT_RELA:
			f->rela_count += count;
			section_type_name = "RELA";
			array_add_section_idx(&f->rela_scns, elf_ndxscn(section));
			break;

		case SHT_SYMTAB:
			f->symtab_section_idx = elf_ndxscn(section);
			break;

		default:
			break;
		}

		if (print_section_stats) {
			const char *entry_plural = "";

			if (count > 1) {
				entry_plural = "entries";
			}
			else {
				entry_plural = "entry";
			}

			printf("\t -> %s section '%s' with %d %s\n",
			       section_type_name,
			       elf_strptr(f->elf,
			                  f->section_string_idx,
			                  section_header.sh_name),
			       count,
			       entry_plural);
		}
	}

	if (!f->symtab_section_idx) {
		ERROR("Could not find symbol table section!\n");
	}

	parse_rela_sections(f);
}


/**
 * get the size of a binary blob.
 */
size_t binblob_size(struct embedded_binary *data) {
	return (size_t)data->end - (size_t)data->start;
}

/**
 * write a embedded binary blob to a given file.
 */
int write_binary_blob(FILE *destination, struct embedded_binary *source) {
	size_t write_size = binblob_size(source);
	printf("\t\t -> Writing binary blob (%lu = 0x%lx bytes)...", write_size, write_size);

	printf(" (embedded data: %p -> %p)", source->start, source->end);
	size_t i = fwrite (source->start, 1, write_size, destination);
	if (i == write_size) {
		printf(" OK!\n");
		return 0;
	}
	else {
		ERROR(" Error!\n");
		return 1;
	}
}

Elf64_Shdr get_elf_section_header(struct input_elf_file *f, const char *sec_name) {
	//current section to try:
	Elf_Scn *scn = NULL;

	//search all sections for the desired one.
	while ((scn = elf_nextscn(f->elf, scn)) != NULL) {
		//header of this section:
		Elf64_Shdr shdr;
		gelf_getshdr(scn, &shdr);

		const char *current_section_name = elf_strptr(f->elf, f->section_string_idx, shdr.sh_name);

		if (0 == strcmp(sec_name, current_section_name)) {
			return shdr;
		}
	}

	ERROR("Could not find Section '%s'\n", sec_name);
}

u64 get_section_offset_by_name(struct input_elf_file *f, const char *sec_name) {
	Elf64_Shdr shdr = get_elf_section_header(f, sec_name);
	return shdr.sh_offset;
}

u64 get_section_address(struct input_elf_file *f, const char *sec_name) {
	Elf64_Shdr shdr = get_elf_section_header(f, sec_name);
	return shdr.sh_addr;
}

u64 get_symbol_offset_by_name(struct input_elf_file *f, const char *name) {
	Elf_Scn *symbol_section = elf_getscn(f->elf, f->symtab_section_idx);

	Elf64_Shdr section_header;
	gelf_getshdr(symbol_section, &section_header);

	//const char *symbol_section_name = elf_strptr(f->elf, f->section_string_idx, section_header.sh_name);

	if (section_header.sh_entsize == 0) {
		ERROR("symbol section header entry size is 0!\n");
	}

	// Get the number of entries
	int entries = section_header.sh_size / section_header.sh_entsize;
	Elf_Data *edata = elf_getdata(symbol_section, NULL);

	for (int i = 0; i < entries; i++) {
		GElf_Sym sym;

		// Get symbol
		gelf_getsym(edata, i, &sym);

		// Get Name
		const char *str = elf_strptr(f->elf, section_header.sh_link, sym.st_name);

		if (str && 0 == strcmp(name, str)) {
			return sym.st_value;
		}
	}

	ERROR("\t=> could not find offset for symbol '%s'\n", name);
	return -1;
}

/*
 * Resolve the symbols with the given index.
 */
void resolve_symbol(struct input_elf_file *f, u32 index, struct symbol *my_sym) {
	// query section in which the symbol is in
	Elf_Scn *symbol_section = elf_getscn(f->elf, f->symtab_section_idx);

	// Header
	Elf64_Shdr shdr;
	gelf_getshdr(symbol_section, &shdr);

	// Get edata
	Elf_Data *edata = elf_getdata(symbol_section, NULL);

	// Get symbol
	GElf_Sym  sym;
	gelf_getsym(edata, index, &sym);

	// Get Name
	const char *sym_name = elf_strptr(f->elf, shdr.sh_link, sym.st_name);

	// Get String if any
	if (sym_name) {
		my_sym->str_len = strlen(sym_name);

		// Reserve space for str.
		my_sym->str = malloc(sizeof(char) * (my_sym->str_len + 1));

		if (!my_sym->str) {
			ERROR("Could not allocate memory for string!");
		}

		// Copy
		strncpy(my_sym->str, sym_name, my_sym->str_len);
		my_sym->str[my_sym->str_len] = '\0';
	}
	else {
		my_sym->str_len = 0;
		my_sym->str = NULL;
	}

	// Is the symbol a function
	if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC) {
		my_sym->function = 1;
	}
	else {
		my_sym->function = 0;
	}

	// Is this an external symbol?
	if (sym.st_shndx != SHN_UNDEF) {
		// This symbol points to an offset within a section that needs to be replaced.
		my_sym->resolve = 0;

		// Get Sym scn
		Elf_Scn *symbol_section = elf_getscn(f->elf, sym.st_shndx);

		// Get Header
		Elf64_Shdr symbol_section_header;
		gelf_getshdr(symbol_section, &symbol_section_header);

		// Set Offset
		my_sym->value = symbol_section_header.sh_offset + sym.st_value;

		// Get name of the section if the symbol has no name yet
		if (!my_sym->str_len) {
			const char *sym_section_name = elf_strptr(f->elf, f->section_string_idx, symbol_section_header.sh_name);

			my_sym->str_len = strlen(sym_section_name);

			// Reserve space for str.
			my_sym->str = malloc(sizeof(char) * (my_sym->str_len + 1));

			if (!my_sym->str) {
				ERROR("Could not allocate memory for string!");
			}

			// Copy
			strcpy(my_sym->str, sym_section_name);
			my_sym->str[my_sym->str_len] = '\0';
		}
	}
	else {
		my_sym->resolve = 1;
	}
}

void parse_rela_sections(struct input_elf_file *f) {
	int count = 0;
	Elf_Data *edata;
	char *str, *str_copy;
	u32 str_len;

	// Do we have to do anything?
	if (f->rela_scns.next_free_entry == 0) {
		return;
	}

	// Reserve memory?
	if (!f->symbols) {
		f->symbols = malloc(sizeof(struct symbol) * (f->rel_count + f->rela_count));
		f->symbol_count = 0;

		if (!f->symbols) {
			ERROR("Could not reserve memory for symbols!\n");
		}
	}

	printf("\t -> Parsing %lu RELA sections...", f->rela_scns.next_free_entry);

	for (int i = 0; i < f->rela_scns.next_free_entry; i++) {
		printf(" %d", i + 1);

		Elf_Scn *section_rela;
		section_rela = elf_getscn(f->elf, f->rela_scns.elf_scn_index_array[i]);

		// Header
		Elf64_Shdr shdr;
		gelf_getshdr(section_rela, &shdr);
		edata = elf_getdata(section_rela, NULL);
		count = shdr.sh_size / shdr.sh_entsize;

		// Set target addr
		f->symbols[f->symbol_count].target_addr = 0;

		for (int j = 0; j < count; j++) {
			// Get Rela
			GElf_Rela rela;
			gelf_getrela(edata, j, &rela);

			// Resolve Symbol
			resolve_symbol(f, ELF64_R_SYM(rela.r_info), &f->symbols[f->symbol_count]);

			// Save type
			f->symbols[f->symbol_count].type = ELF64_R_TYPE(rela.r_info);

			// Do we need to resolve this symbol within the shellcode?
			if (!f->symbols[f->symbol_count].resolve) {
				// No. Add the necessary offset to the value.
				f->symbols[f->symbol_count].value += rela.r_addend;
				f->symbols[f->symbol_count].addend = rela.r_addend;
			}
			else {
				f->symbols[f->symbol_count].addend = rela.r_addend;
			}

			// Lookup the section offset of the target addr.
			gelf_getshdr(section_rela, &shdr); // Just to be sure, may have been used.

			// Get Section name
			str = elf_strptr(f->elf, f->section_string_idx, shdr.sh_name);

			// Copy string to make sure it is not overwritten
			if (str) {
				str_len = strlen(str);
			}
			else {
				ERROR("Found RELA section with no name!\n");
			}

			str_copy = malloc(sizeof(char) * (str_len + 1));

			if (!str_copy) {
				ERROR("Could not allocate memory for string copy!\n");
			}

			strcpy(str_copy, str);
			str_copy[str_len] = '\0';

			// Look for ".rela", since we have to remove that part
			str_len = strlen(".rela");

			if (strncmp(str_copy, ".rela", str_len) == 0) {
				// Remove .rela
				str_copy += str_len;
			}

			f->symbols[f->symbol_count].target_addr  = get_section_offset_by_name(f, str_copy);
			f->symbols[f->symbol_count].target_addr += rela.r_offset;
			f->symbols[f->symbol_count].offset       = rela.r_offset;

			// Increase Symbol count
			f->symbol_count += 1;
		}
	}

	printf(" OK!\n");
}

/**
 * endianess is our friend!
 */
u64 write_int_reversed(FILE *fp, u64 data) {
	char tmp[8];
	u64 copy = data;
	u64 write_position = ftell(fp);

	// Prepare
	for (int i = 0; i < 8; i++) {
		tmp[i] = copy & 0xff;
		copy = copy >> 8;
	}

	// Write
	int n = fwrite (tmp, 1, 8, fp);
	if (n != 8) {
		ERROR("An error occurred while writing an integer in reverse.\n");
	}

	return write_position;
}

/**
 * Get the offset within the text section of the kernel_esp variable.
 * We thereby assume kernel_esp is the first variable within .text.
 */
/*
u64 getKernelEspOffset(const char *filename)
{
	FILE *wrapper;
	char cmd[2048];
	u64 result = 0;

	//TODO: kernel esp offset calculation: .text + (sym.kernel_esp - .text)

	// Build command
	//TODO: max filename length...
	sprintf(cmd, "objdump -h %s | grep .text | awk '{print $6}'", filename);

	// Execute
	wrapper = popen(cmd, "r");

	// Check
	if (!wrapper) {
		ERROR("Could not execute command %s\n", cmd);
	}

	// Read data
	if (fscanf(wrapper, "%llx", &result) <= 0) {
		ERROR("Could not obtain the location of the kernel_esp variable!\n");
		return 0;
	}
	else {
		return result;
	}
}
*/

struct wrappers get_wrapper_names(const char *filename) {
	u32 i = 0;
	char line[1024];
	char *current_wrapper = NULL;
	struct wrappers w;

	w.size = 0;

	FILE *f = fopen(filename, "r");
	if (!f) {
		ERROR("Could not open wrapper file ('%s')!\n", filename);
	}

	// max 1024 wrappers atm
	while (fgets(line, 1024, f)) {
		w.size++;
	}

	// Allocate memory
	w.wrapper = malloc(w.size * sizeof(char *));

	if (!w.wrapper) {
		ERROR("Could not allocate memory for the wrapper array!\n");
	}

	// Get each wrapper
	fseek (f, 0, SEEK_SET);

	while (fgets(line, 1024, f)) {
		// Copy wrapper
		current_wrapper = malloc(sizeof(char) * strlen(line) + 1);

		if (!current_wrapper) {
			ERROR("Could not allocate memory for an individual wrapper!\n");
		}

		strcpy(current_wrapper, line);

		// Replace newline character if there is one
		if (current_wrapper[strlen(line) - 1] == '\n') {
			current_wrapper[strlen(line) - 1] = '\0';
		}

		// Add
		w.wrapper[i] = current_wrapper;
		i++;
	}

	return w;
}

void generate_shellcode(struct input_elf_file *f,
                        const char *input_filename,
                        const char *out_filename,
                        u64 system_map_begin,
                        u64 system_map_end) {

	u64     resolve_num           = 0;
	u64     strlen_resolve_syms   = 0;
	u64     patch_count           = 0;
	u64     esp_patch_count       = 0;
	size_t  shellcode_data_length = 0;
	FILE   *inject_file           = NULL;
	FILE   *inject_wrapper_file   = NULL;
	char   *out_wrapper_file      = NULL;
	char   *tmp                   = NULL;

	u32   wrapper_size       = 0;
	char *wrapper_tmp_name   = NULL;
	char *wrapper_tmp_file   = NULL;
	u32   wrapper_number     = 0;
	u64   wrapper_esp_offset = 0;

	struct wrapper_patch *patches = NULL;

	u64 n = 0;

	size_t printf_shellcode_size = binblob_size(&printf_shellcode);

	// Go!
	printf("\t => Generating injection file containing its own loader...\n");

	printf("\t -> elf kernel module size: %llu\n", f->size);
	printf("\t -> printk shelcode size: %zu\n", printf_shellcode_size);

	// Parse wrapper
	printf("\t -> Parsing wrapper names from '%s'... ", wrapper_filename);
	struct wrappers w = get_wrapper_names(wrapper_filename);
	printf("Found %lu wrappers!\n", w.size);

	// Get the number of patch and resolve symbols
	for (int i = 0; i < f->symbol_count; i++) {
		if (f->symbols[i].resolve
		    && strcmp(f->symbols[i].str, "printk") != 0) {
			// Ignore "mcount"
			if (strcmp(f->symbols[i].str, "mcount") == 0) {
				continue;
			}

			// Resolve symbols
			resolve_num++;
			strlen_resolve_syms += (f->symbols[i].str_len + 1);

			// Check for wrapper function
			for (int j = 0; j < w.size; ++j) {
				if (strcmp(f->symbols[i].str, w.wrapper[j]) == 0) {
					esp_patch_count++;
					// Mark symbol as function
					f->symbols[i].function = 1;
					break;
				}
			}
		}
		else {
			// Ignore "init_module" && "cleanup_module"
			if (strcmp(f->symbols[i].str, "cleanup_module") != 0
			    && strcmp(f->symbols[i].str, "init_module") != 0) {
				patch_count++;
			}
		}
	}

	printf("\t -> Outfile will be %s\n", out_filename);

	// Generate Filename
	tmp = strrchr(input_filename, '.');

	if (!tmp) {
		tmp = strlen(input_filename) + (char *)input_filename;
	}

	// Temporary output file for wrappers
	const char *wrapper_tmpfile_suffix = ".inject.wrapper";
	out_wrapper_file = malloc(sizeof(char) * (tmp - input_filename + 1 + strlen(wrapper_tmpfile_suffix) + 1));
	strncpy(out_wrapper_file, input_filename, tmp - input_filename);
	strncpy(out_wrapper_file + (tmp - input_filename), wrapper_tmpfile_suffix, strlen(wrapper_tmpfile_suffix));
	out_wrapper_file[tmp - input_filename + 1 + strlen(wrapper_tmpfile_suffix)] = '\0';

	// Calulcate Shellcode offsets
	printf("\t -> Calculating shellcode data length...\n");

	/*
	 * Layout of the shellcode data.
	 *
	 * this will be read by the shellcode and contains all the loading information
	 * for the injected code.
	 *
	 * Entry Point                      8
	 * PATCH SYM COUNT                  8 = x
	 * Per PATCH Symbol                 x * (
	 *      Target Addr                     8
	 *      Value                           8
	 *                                      )
	 * ESP PATCH SYMS COUNT             8 = e
	 * Per ESP PATCH SYM                e * (
	 *      Target Addr                     8
	 *                                      )
	 *
	 * Systemmap Begin                  8
	 * Systemmap End                    8
	 * RESOLVE SYMS COUNT               8 = y
	 * Per RESOLVE Symbol               y * (
	 *      Length of String                8
	 *      String Variable Length          z
	 *      Target Addr                     8
	 *                                      )
	 *
	 *                                    = y * 16 + z1 + z2 ... zN
	 *
	 *  TOTAL: 8 + 8 + x * 16 + 8 + 8  + e * 8 + 8 + 8 + 8 + y * 16 + z1 + z2 ... zN
	 */

	// Patch symbols
	shellcode_data_length = 8 + 8 + ((patch_count + esp_patch_count) * (8 + 8));

	// ESP Patch symbols
	shellcode_data_length += (8 + (esp_patch_count * 8));

	// Resolve symbols
	shellcode_data_length += 8 + 8 + 8 + (resolve_num * (8 + 8)) + strlen_resolve_syms;

	// we calculated the data length.
	printf("\t\t # COMPLETE shellcode offset/length is 0x%lx = %lu\n", shellcode_data_length, shellcode_data_length);

	// Write file
	printf("\t -> Creating File %s...", out_filename);
	inject_file = fopen(out_filename, "wb+");

	if (!inject_file) {
		ERROR(" Could not open file '%s'\n", out_filename);
	}
	printf(" OK!\n");

	// Shellcode first
	printf("\t -> Writing Shellcode ...\n");

	if (0 != write_binary_blob(inject_file, &shellcode)) {
		ERROR("An error occurred while writing the shellcode.\n");
	}

	printf("\t -> Generating shellcode data now...\n");

	// move entry point address behind shellcode data
	printf("\t -> Calculating NEW Entry Point...");
	// Resolve sym 2 DW - Begin Map, End Map 2 DW - Count 1 DW - Strlen Syms
	f->entry_point += shellcode_data_length;
	printf("OK! Entry Point @ 0x%llx\n", f->entry_point);

	printf("\t -> Writing code entry point... ");
	u64 entry_point_offset = write_int_reversed(inject_file, f->entry_point);
	printf("OK, wrote @0x%llx\n", entry_point_offset);


	// ESP Patch syms
	// Must be considered first to be able to write the correct patch symbols
	if (esp_patch_count > 0) {
		printf("\t -> Generating wrapper file '%s' for %llu external function(s)...\n", out_wrapper_file, esp_patch_count);

		// Reserve space
		patches = (struct wrapper_patch *)malloc(sizeof(struct wrapper_patch) * esp_patch_count);

		if (!patches) {
			ERROR("\nERROR: Could not reserve memory for the wrapper addresses!\n");
		}
	}
	else {
		printf("\t -> No external functions detected. No wrappers necessary.\n");
	}

	// Open wrapper file
	inject_wrapper_file = fopen(out_wrapper_file, "wb");

	if (!inject_wrapper_file) {
		ERROR("Could not open wrapper file '%s'!\n", out_wrapper_file);
	}

	for (int i = 0; i < f->symbol_count; i++) {
		if (f->symbols[i].resolve
		    && f->symbols[i].function
		    && 0 != strcmp(f->symbols[i].str, "mcount")
		    && 0 != strcmp(f->symbols[i].str, "printk")) {
			const char *func_name = f->symbols[i].str;

			printf("\t\t # Trying to open wrapper for function '%s'...\n", func_name);

			// Try to find wrapper
			// Reserve space for wrapper file name
			wrapper_tmp_name = (char *)malloc(sizeof(char) * (strlen(wrapper_path) + strlen(func_name) + strlen(wrapper_suffix) + 1));

			// Build name
			strcpy(wrapper_tmp_name, wrapper_path);
			strcat(wrapper_tmp_name, func_name);
			strcat(wrapper_tmp_name, wrapper_suffix);

			struct input_elf_file wrapper_file = init_elf_file(wrapper_tmp_name);
			printf("\t\t\t -> parsing wrapper elf...\n");
			parse_elf_file(&wrapper_file);

			printf("\t\t\t <> Writing Wrapper...");

			// copy original file
			n = fwrite(wrapper_file.data, 1, wrapper_file.size, inject_wrapper_file);

			if (n != wrapper_file.size) {
				ERROR("\nERROR: Wrapper write was incomplete!\n");
			} else {
				printf(" Ok!\n");
			}

			// store function name for this patch
			patches[wrapper_number].function_name = (char *)malloc(sizeof(char) * (strlen(func_name) + 1));
			strcpy(patches[wrapper_number].function_name, func_name);

			// get offset of variable kernel_esp, where the shellcode will write the kernel esp
			printf("\t\t\t -> getting patching position for 'kernel_esp' variable...\n");
			wrapper_esp_offset = get_symbol_offset_by_name(&wrapper_file, "kernel_esp");
			printf("\t\t\t <> Found variable for kernel ESP offset @ 0x%llx...\n", wrapper_esp_offset);

			//current writing position
			n = (shellcode_data_length + f->size + printf_shellcode_size + wrapper_size);

			u64 esp_write_pos = n + wrapper_esp_offset;

			// Add address to esp patch symbols
			printf("\t\t\t <> Kernel Stack address will be written to 0x%llx...\n", esp_write_pos);
			patches[wrapper_number].esp_address = esp_write_pos;

			u64 subst_call_destination = n + get_symbol_offset_by_name(&wrapper_file, func_name);

			// Substitute the original call within the module with the call to the wrapper
			printf("\t\t\t <> function '%s' @ 0x%llx will be set to call 0x%llx...\n",
			       func_name,
			       f->symbols[i].target_addr + shellcode_data_length, subst_call_destination);

			patches[wrapper_number].address_target = f->symbols[i].target_addr + shellcode_data_length;
			patches[wrapper_number].address_value  = subst_call_destination;

			// Fix Target address - We assume a fixed offset here - Ignore complete offset,
			// by the resolve offset part
			f->symbols[i].target_addr = f->size + printf_shellcode_size + wrapper_size + wrapper_esp_offset + 8;

			// Update wrapper size
			wrapper_size += wrapper_file.size;

			// Update wrapper counter
			wrapper_number++;

			// free data
			free(wrapper_tmp_name);
			free(wrapper_tmp_file);
		}
	}

	fclose(inject_wrapper_file);

	// Patch Symbols
	printf("\t -> Writing patch symbols (%llu)... \n", patch_count + esp_patch_count);
	u64 patch_count_offset = write_int_reversed(inject_file, patch_count + esp_patch_count);  // patch count
	printf("\t -> wrote patch+esppatch count to 0x%llx\n", patch_count_offset);

	for (int i = 0; i < f->symbol_count; i++) {
		if (!f->symbols[i].resolve
		    && 0 != strcmp(f->symbols[i].str, "cleanup_module")
		    && 0 != strcmp(f->symbols[i].str, "init_module")) {

			if (f->symbols[i].addend) {
				printf("\t\t # PATCH 0x%llx (offset 0x%llx) will be set to '%s + 0x%llx' (0x%llx)\n",
				       f->symbols[i].target_addr + shellcode_data_length,
				       f->symbols[i].offset,
				       f->symbols[i].str, f->symbols[i].addend,
				       f->symbols[i].value + shellcode_data_length);
			}
			else {
				printf("\t\t # PATCH 0x%llx (offset 0x%llx) will be set to '%s' (0x%llx)\n",
				       f->symbols[i].target_addr + shellcode_data_length,
				       f->symbols[i].offset,
				       f->symbols[i].str,
				       f->symbols[i].value + shellcode_data_length);
			}

			// Write
			write_int_reversed(inject_file, f->symbols[i].target_addr + shellcode_data_length);
			write_int_reversed(inject_file, f->symbols[i].value + shellcode_data_length);
		}
		else if(strcmp(f->symbols[i].str, "printk") == 0) {
			printf("\t\t # FUNCTION PATCH printk @ 0x%llx (offset 0x%llx) will be set to 0x%llx\n",
			       f->symbols[i].target_addr + shellcode_data_length,
			       f->symbols[i].offset,
			       f->size + shellcode_data_length);

			write_int_reversed(inject_file, f->symbols[i].target_addr + shellcode_data_length);
			write_int_reversed(inject_file, f->size + shellcode_data_length);
		}
	}

	// Write the addresses of the wrappers
	for (int i = 0; i < esp_patch_count; i++) {
		printf("\t\t # Setting function %s @ 0x%llx to call Wrapper @ 0x%llx...\n",
		       patches[i].function_name,
		       patches[i].address_target,
		       patches[i].address_value);

		write_int_reversed(inject_file, patches[i].address_target);
		write_int_reversed(inject_file, patches[i].address_value);
	}

	// Write the ESP_PATCH data
	printf("\t -> writing ESP patch symbols (need %llu)... \n", esp_patch_count);
	write_int_reversed(inject_file, esp_patch_count);

	// Write addresses
	for (int i = 0; i < esp_patch_count; i++) {
		printf("\t\t # Kernel ESP will be updated @ 0x%llx...", patches[i].esp_address);
		u64 esp_patch_position = write_int_reversed(inject_file, patches[i].esp_address);
		printf(" Ok. wrote @0x%llx\n", esp_patch_position);
	}


	// free patches containing wrapper addresses and function names
	for (int i = 0; i < esp_patch_count; i++) {
		free(patches[i].function_name);
	}
	free(patches);

	// Symmap
	printf("\t -> Writing Symmap begin... 0x%016llx ", system_map_begin);
	write_int_reversed(inject_file, system_map_begin);
	printf("OK!\n");

	printf("\t -> Writing Symmap end...   0x%016llx ", system_map_end);
	write_int_reversed(inject_file, system_map_end);
	printf("OK!\n");

	// Resolve Symbols
	printf("\t -> Writing Resolve Symbols (%llu)... \n", resolve_num);
	write_int_reversed(inject_file, resolve_num); // Count

	for(int i = 0; i < f->symbol_count; i++) {
		if(f->symbols[i].resolve
		   && 0 != strcmp(f->symbols[i].str, "printk"))
		{
			printf("\t\t # RESOLVE %s @ 0x%llx must be resolved...\n", f->symbols[i].str,
			       f->symbols[i].target_addr + shellcode_data_length);

			write_int_reversed(inject_file, (f->symbols[i].str_len + 1)); // Str Len
			fwrite(f->symbols[i].str, 1, f->symbols[i].str_len + 1, inject_file); // Str
			write_int_reversed(inject_file, f->symbols[i].target_addr + shellcode_data_length); // Target
		}
	}

	// Write Binary
	printf("\t -> Writing Binary... ");

	printf(" copying original kernel module contents... ");
	n = fwrite (f->data, 1, f->size, inject_file);

	if (n != f->size) {
		ERROR("error!\n");
	} else {
		printf("OK!\n");
	}

	printf("\t -> Writing 'printk' Wrapper...\n");

	if (0 != write_binary_blob(inject_file, &printf_shellcode)) {
		ERROR("An error occurred while writing the printk wrapper.\n");
	}

	// Open and write wrapper file
	if (esp_patch_count > 0) {
		printf("\t -> Writing remaining wrapper section... ");
		inject_wrapper_file = fopen(out_wrapper_file, "rb");

		if (!inject_wrapper_file) {
			ERROR("\nERROR: Could not open wrapper file '%s' for copying\n", out_wrapper_file);
		}

		if ((wrapper_tmp_file = (char *) malloc(wrapper_size * sizeof(char))) == NULL) {
			ERROR("\nERROR: Could not reserve memory to store wrapper file.\n");
		}

		n = fread (wrapper_tmp_file, 1, wrapper_size, inject_wrapper_file);

		if (n != wrapper_size) {
			ERROR("\nERROR: An error occurred while reading the wrapper file.\n");
		}

		fclose(inject_wrapper_file);

		n = fwrite(wrapper_tmp_file, 1, wrapper_size, inject_file);

		if (n == wrapper_size) {
			printf("OK!\n");
			unlink(out_wrapper_file);
		}
		else {
			ERROR("\nERROR: An error occurred while writing the wrapper section.\n");
		}
	}

	free(out_wrapper_file);

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
	printf("\t\t                    \tDEFAULT = '%s'\n", wrapper_filename);
	printf("\t\t -d, --wrapper-path \tThe path to the directory that contains the wrapper functions.\n");
	printf("\t\t                    \tDEFAULT = '%s'\n", wrapper_path);
	printf("\t\t -e, --extension    \tThe extension of the transformed module. It's name will be equal to the module name.\n");
	printf("\t\t                    \tDEFAULT = '%s'\n\n", extension);
	printf("\t\t -o, --output       \t");
	printf("\t\t                    \tDEFAULT = '<kernelmodule>.inject'\n\n");
}

int main(int argc, char *argv[]) {

	const char *input_file_name = 0;   // filename
	char *generated_output_file_name = NULL;
	const char *output_file_name = NULL;

	int option_index = 0;
	int option = 0;

	u64 sysmap_begin = lnx___start___ksymtab;     //0xffffffff8175e250;
	u64 sysmap_end   = lnx___stop___ksymtab_gpl;  //0xffffffff81776190;

	// Parse options
	while ((option = getopt_long (argc, argv, "hw:d:e:i:o:", options, &option_index)) != -1) {
		switch (option) {
		case 'w':
			wrapper_filename = optarg;
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
		printf("output str len: %zu\n", output_str_len);
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
	printf("\t\t |_ Input File:                '%s'\n", input_file_name);

	if (init_function) {
		printf("\t\t |_ Init Function:             '%s'\n", init_function);
	}

	printf("\t\t |_ Wrappers are specified in: '%s'\n", wrapper_filename);
	printf("\t\t |_ Wrappers are located at:   '%s'\n", wrapper_path);
	printf("\t\t |_ Resulting file will be:    '%s'\n\n", output_file_name);


	if (elf_version(EV_CURRENT) == EV_NONE) {
		ERROR("LIBELF initialization failed!\n");
	}

	struct input_elf_file input_ko = init_elf_file(input_file_name);
	printf("=> parsing input elf file...\n");
	parse_elf_file(&input_ko);

	// Find entry Point
	printf("=> Looking for entry point...\n");

	// Find entry point
	if (init_function) {
		input_ko.entry_point = get_symbol_offset_by_name(&input_ko, init_function);
		if (input_ko.entry_point != -1) {
			input_ko.entry_point = input_ko.entry_point - get_section_address(&input_ko, ".text") + get_section_offset_by_name(&input_ko, ".text");
			printf("-> Found entry function '%s' @ 0x%llx\n", init_function,  input_ko.entry_point);
		}
		else {
			// Could not find entry function
			ERROR("FAIL: could not find entry function '%s'!\n", init_function);
		}
	}

	// Could not find the entry_function or none given
	if (input_ko.entry_point == 0) {
		if (input_ko.header->e_entry) {
			input_ko.entry_point = input_ko.header->e_entry - get_section_address(&input_ko, ".text") + get_section_offset_by_name(&input_ko, ".text");
		}
		else {
			input_ko.entry_point = get_section_offset_by_name(&input_ko, ".init.text");
		}
	}

	printf("-> Entry Point @ 0x%llx\n", input_ko.entry_point);

	// Go for it
	generate_shellcode(
		&input_ko,
		input_file_name,
		output_file_name,
		sysmap_begin,
		sysmap_end);

	printf("\n\nDONE!\n");

	return 0;
}
