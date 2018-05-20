// this code is from the book "analysing malware"

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>

void xor_encoder(unsigned char *start, unsigned int size, BYTE encoder)
{
	unsigned int	cnt=0;

	printf("Start Xor Encode by '0x%X'\n", encoder);
	for(cnt=0; cnt<size; cnt++){
		start[cnt] ^= encoder;
	}
	printf("Encode Done\n");
}

unsigned char decode_stub[] = {
	0x60,				// pushad
	0xBE,0xFF,0xFF,0xFF,0xFF,	// mov esi, decode_start
	0xB9,0xFF,0xFF,0xFF,0xFF,	// mov ecx, decode_size
	0x81,0xC6,0xFF,0xFF,0xFF,0xFF,	// add esi, base_addr 
	0xB0,0xFF,			// mov al, decoder
	0x30,0x06,			// xor byte ptr [esi], al (LOOP)
	0x46,				// inc esi
	0x49,				// dec ecx
	0x75,0xFA,			// jnz LOOP
	0x61,				// popad
	0xE9,0xFF,0xFF,0xFF,0xFF	// jmp OEP
};
unsigned int decode_start_offset = 2;
unsigned int decode_size_offset  = 7;
unsigned int base_address_offset = 13;
unsigned int decoder_offset      = 18;
unsigned int jmp_oep_addr_offset = 27;

void create_decode_stub(unsigned int code_vaddr, unsigned int code_vsize,
		unsigned int base_addr, BYTE decoder, unsigned int oep)
{
	int	cnt=0;
	int	jmp_len_to_oep=0;

	jmp_len_to_oep = oep - (code_vaddr + code_vsize + sizeof(decode_stub));

	printf("start   : 0x%08X\n", code_vaddr);
	printf("size    : 0x%08X\n", code_vsize);
	printf("decoder : 0x%02X\n", decoder);
	printf("oep     : 0x%08X\n", oep);
	printf("jmp len : 0x%08X\n", jmp_len_to_oep);

	memcpy(&decode_stub[decode_start_offset], &code_vaddr, sizeof(DWORD));
	memcpy(&decode_stub[decode_size_offset],  &code_vsize, sizeof(DWORD));
	memcpy(&decode_stub[base_address_offset],  &base_addr, sizeof(DWORD));
	memcpy(&decode_stub[decoder_offset],  &decoder, sizeof(BYTE));
	memcpy(&decode_stub[jmp_oep_addr_offset],  &jmp_len_to_oep, sizeof(DWORD));

	return;

}

IMAGE_NT_HEADERS* get_nt_header(unsigned char *buf)
{
	IMAGE_DOS_HEADER	*dos_header=NULL;
	IMAGE_NT_HEADERS	*nt_header=NULL;

	dos_header = (IMAGE_DOS_HEADER *)buf;
	if( dos_header->e_magic != IMAGE_DOS_SIGNATURE ){
		fprintf(stderr, "non MZ file\n");
		nt_header = NULL;
		goto END;
	}

	nt_header = (IMAGE_NT_HEADERS *)(buf + dos_header->e_lfanew);
	if( nt_header->Signature != IMAGE_NT_SIGNATURE ){
		fprintf(stderr, "non PE file\n");
		nt_header = NULL;
		goto END;
	}

END:
	return nt_header;
}

IMAGE_SECTION_HEADER *search_oep_include_section_header(IMAGE_NT_HEADERS *nt_header, unsigned int oep)
{
	int			section_num;
	int			cnt=0;
	IMAGE_SECTION_HEADER	*section_header;
	IMAGE_SECTION_HEADER	*oep_section_header=NULL;
	unsigned int		section_vaddr;
	unsigned int		section_vsize;


	section_num = nt_header->FileHeader.NumberOfSections;
	section_header = (IMAGE_SECTION_HEADER *)((unsigned int)nt_header + sizeof(IMAGE_NT_HEADERS));
	
	for(cnt=0; cnt<section_num; cnt++){
		section_vaddr = section_header->VirtualAddress;
		section_vsize = section_header->Misc.VirtualSize;
		//printf("%s vaddr:0x%08X vsize:0x%08X oep:0x%08x\n", section_header->Name, section_vaddr, section_vsize, oep);
		if(section_vaddr <= oep && oep < section_vaddr + section_vsize && section_header->Characteristics & (IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE)){
			printf("oep section found\n");
			oep_section_header = section_header;
			break;
		}
		*section_header++;

	}

	return oep_section_header;

}

int main(int argc, char **argv)
{
	int			ret=0;
	char			*target_filename;
	char			*packed_filename;
	IMAGE_NT_HEADERS	*nt_header=NULL;
	IMAGE_SECTION_HEADER	*oep_section_header=NULL;
	BYTE			encoder;
	unsigned int		base_addr;
	unsigned int		oep=0;
	unsigned int		section_vaddr;
	unsigned int		section_vsize;
	unsigned int		section_raddr;
	unsigned int		section_rsize;
	HANDLE			hTargetBin=NULL;
	unsigned char		*lpTargetBinBuffer=NULL;
	DWORD			dwTargetBinSize=0;
	DWORD			dwReadSize=0;
	DWORD			dwWriteSize=0;
	BOOL			bRslt;
	HANDLE			hPackedBin=NULL;

	target_filename = argv[1];
	packed_filename = argv[2];

	/////////////////////////////////////////////////////////
	// read orig buffer
	hTargetBin = CreateFile(target_filename, GENERIC_READ, 0, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hTargetBin == INVALID_HANDLE_VALUE){
		fprintf(stderr, "CreateFile() failed.\n");
		ret = -1;
		goto END;
	}

	dwTargetBinSize = GetFileSize(hTargetBin, NULL);
	if(dwTargetBinSize==-1){
		fprintf(stderr, "GetFileSize() failed.\n");
		ret = -1;
		goto END;
	}
		
	lpTargetBinBuffer = (unsigned char*)malloc(
			sizeof(unsigned char) * dwTargetBinSize);
	if(lpTargetBinBuffer==NULL){
		fprintf(stderr, "malloc() failed.\n");
		ret = -1;
		goto END;
	}

	bRslt = ReadFile(hTargetBin, lpTargetBinBuffer, dwTargetBinSize, &dwReadSize, NULL);
	if(!bRslt && dwTargetBinSize != dwReadSize){
		fprintf(stderr, "ReadFile() failed.\n");
		ret = -1;
		goto END;
	}

	/////////////////////////////////////////////////////////
	// get pe header values
	nt_header = get_nt_header(lpTargetBinBuffer);
	oep = nt_header->OptionalHeader.AddressOfEntryPoint;
	base_addr = nt_header->OptionalHeader.ImageBase;

	// search code section
	oep_section_header = search_oep_include_section_header(nt_header, oep);
	if(oep_section_header==NULL){
		printf("OEP include section search failed.\n");
		goto END;
	}

	// get oep include section values
	section_vaddr = oep_section_header->VirtualAddress;
	section_vsize = oep_section_header->Misc.VirtualSize;
	section_raddr = oep_section_header->PointerToRawData;
	section_rsize = oep_section_header->SizeOfRawData;

	/////////////////////////////////////////////////////////
	// Xor encode
	encoder=0xFF;
	xor_encoder((unsigned char*)(oep_section_header->PointerToRawData + lpTargetBinBuffer),
			oep_section_header->Misc.VirtualSize, encoder);

	/////////////////////////////////////////////////////////
	// create xor decoder
	create_decode_stub(section_vaddr, section_vsize, base_addr, encoder, oep);
	// add xor decoder stub
	memcpy((unsigned char*)(section_raddr + section_vsize + lpTargetBinBuffer), decode_stub, sizeof(decode_stub));


	/////////////////////////////////////////////////////////
	// change PE header
	// extend code space
	oep_section_header->Misc.VirtualSize = section_rsize;
	// change oep
	nt_header->OptionalHeader.AddressOfEntryPoint = section_vaddr + section_vsize;
	// add write attr to code section
	oep_section_header->Characteristics |= IMAGE_SCN_MEM_WRITE;

	/////////////////////////////////////////////////////////
	// dump packed binary
	hPackedBin = CreateFile(packed_filename, GENERIC_WRITE, 0, NULL,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hPackedBin == INVALID_HANDLE_VALUE){
		fprintf(stderr, "CreateFile() failed.\n");
		ret = -1;
		goto END;
	}

	bRslt = WriteFile(hPackedBin, lpTargetBinBuffer, dwTargetBinSize, &dwWriteSize, NULL);
	if(!bRslt && dwTargetBinSize != dwWriteSize){
		fprintf(stderr, "ReadFile() failed.\n");
		ret = -1;
		goto END;
	}

END:
	if(hTargetBin!=INVALID_HANDLE_VALUE){
		CloseHandle(hTargetBin);
	}

	if(lpTargetBinBuffer){
		free(lpTargetBinBuffer);
		lpTargetBinBuffer = NULL;
	}

	return ret;

}

