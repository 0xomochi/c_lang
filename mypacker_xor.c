// This is the code of my first packer.
// The code from the book named  "Analyzing Malware".

#define _CRT_SECURE_NO_WARNINGS

# include <stdio.h>
# include <windows.h>

void xor_encoder(unsigned char *start, unsigned int size, BYTE encoder){
  unsigned int cnt = 0;

  ptintf("Start Xor Encode by '0x%X'\n", encoder);
  for(cnt = 0; cnt < size; cnt++){
    start[cnt] ^= encoder;
  }
  printf("Encode Done\n");
}

unsigned char decode_stub[] = {
  0x60
  0xBE, 0xFF, 0xFF, 0xFF, 0xFF,
  0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 
  0x81, 0xC6, 0xFF, 0xFF, 0xFF, 0xFF, 
  0xB0, 0xFF,
  0x30, 0x06,
  0x46,
  0x49,
  0x75, 0xFA,
  0x61,
  0xE9, 0xFF, 0xFF, 0xFF, 0xFF
};

unsigned int decode_start_offset      = 2;
unsigned int decode_size_offset       = 7;
unsigned int base_address_offset      = 13;
unsigned int decoder_offset          = 18;
unsigned int jmp_oep_addr_offset      = 27;

void create_decode_stub(unsigned int code_vaddr, unsigned int code_vsize,
     unsigned int base_vaddr, unsigned int decoder, unsigned int oep){

  int cnt = 0;
  int jmp_len_to_oep = 0;

  jmp_len_to_oep = oep - (code_vaddr + code_vsize + sizeof(decode_stub));

  printf("start   : 0x%08X\n", code_vaddr);
  printf("size    : 0x%08X\n", code_vsize);
  printf("decoder : 0x%02X\n", decoder);
  printf("oep     : 0x%08X\n", oep);
  printf("jmp len : 0x%08X\n", jmp_len_to_oep);

  memcpy(&decode_stub[decode_start_offset], &code_vaddr, sizeof(DWORD));
  memcpy(&decode_stub[decode_size_offset], &code_vsize, sizeof(DWORD));
  memcpy(&decode_stub[base_address_offset], &base_addr, sizeof(DWORD));
  memcpy(&decode_stub[jmp_oep_addr_offset], &jmp_len_to_oep, sizeof(DWORD)):
  
  return;
}

IMAGE_NT_HEADERS* get_nt_header(unsigned char *buf){
  IMAGE_DOS_HEADER  *dos_header = NULL;
  IMAGE_DOS_HEADER  *nt_header = NULL;

  dos_header = (IMAGE_DOS_HEADER *)buf;
  if(dos_header -> e_magic != IMAGE_DOS_SIGNATURE){
    fprintf(stderr, "non MZ file\n");
    nt_header = NULL;
    goto END;
  }

  nt_header = (IMAGE_NT_HEADERS *)(buf + dos_header -> e_lfanew);
  if(nt_header -> Signature != IMAGE_NT_SIGNATURE){
    fprintf(stderr, "non PE file\n");
    nt_header = NULL;
    goto END;
  }

END:
  return nt_header;
}

IMAGE_SECTION_HEADER *search_oep_include_section_header(IMAGE_NT_HEADERS *nt_header, unsigned int oep){
  int section_num;
  int cnt = 0;
  IMAGE_SECTION_HEADER *section_header;
  IMAGE_SECTION_HEADER *oep_section_header = NULL;
  unsigned int  section_vaddr;
  unsigned int  section_vsize;

  section_num = nt_header -> FileHeader.NumberOfSections;
  section_header = (IMAGE_SECTION_HEADER *)((unsigned int)nt_header + sizeof(IMAGE_NT_HEADERS));

  for(cnt = 0; cnt < section_num; cnt++){
    section_vaddr = section_header -> VirtualAddress;
    section_vsize = section_header -> Misc.VirtualSize;

    if(section_vaddr <= oep && oep < section_vaddr + section_vsize && section_header -> Characteristics & (IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE)){
      printf("oep section found\n");
      oep_section_header = section_header;
      break;
    }
    *section_header++;
  }

  return oep_section_header;
}

int main(int argc, char **argv){
  int     ret = 0;
  char    *target_filename;
  char    *packed_filename;
  IMAGE_NT_HEADERS        *nt_header = NULL;
  IMAGE_SECTION_HEADER    *oep_section_header = NULL;
  BYTE    encoder;
  unsigned int    base_addr;
  unsigned int    oep = 0;
  unsigned int    section_vaddr;
  unsigned int    section_vsize;
  unsigned int    section_raddr;
  unsigned int    section_rsize;
  HANDLE          hTargetBin = NULL;
  unsigned char   *lpTargetBinBuffer = NULL;
  DWORD           dwTargetBinBuffer = NULL;
  DWORD           dwReadSize = 0;
  DWORD           dwWriteSize = 0;
  BOOL            bRslt;
  HANDLE          hPackedBin = NULL;

  target_filename = argv[1];
  packed_filename = argv[2];


// Loading the program will be packed (read orig buffer)
  hTargetBin = CreateFile(target_filename, GENERIC_READ, 0, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if(hTargetBin == INVALID_HANDLE_VALUE){
    fprintf(stderr, "CreateFile() failed.\n");
    ret = -1;
    goto END;
  }

  lpTargetBinSize = GetFileSize(hTargetBin, NULL);
  if(dwTargetBinSize == -1){
    fprintf(stderr, "GetFileSize() failed.\n");
    ret = -1;
    goto END;
  }

// get PE header values
  nt_header = get_nt_header(lpTargetBinBuffer);
  oep = nt_header -> OptionalHeader.AddressOfEntryPoint;
  base_addr = nt_header -> OptionalHeader.ImageBase;

// Searching the code section includint entry point (search code section)
  oep_section_header = search_oep_incluse_secion_header(nt_header, oep);
  if(oep_section_header == NULL){
    printf("OEP include section search faild.\n");
    goto END;
  }


// Getting the address and size of codesection (get oep include section values)
  section_vaddr = oep_section_header -> VirtualAddress;
  section_vaddr = oep_section_header -> Misc.VirtualSize;
  section_vaddr = oep_section_header -> PointerToRawData;
  section_vaddr = oep_section_header -> SizeOfRawData;

// Encoding the code area (XOR encode)
encoder = 0xFF
xor_encoder((unsigned char*)(oep_section_header -> PointerToRawData + IpTargetBinBuffer), oep_section_header -> Misc.VirtualSize, encoder);


// create XOR decoder (Make expantion routine)
create_decode_stub(section_vaddr, section_vsize, base_addr, encoder, oep);

// add XOR decoder stub (Add expantion routine)
memcpy((unsigned char*)(section_raddr + section_vsize + IpTargetBinBuffer), decode_stub, sizeof(decode_stub));



// change PE header
//extend code space
  oep_section_header -> Misc.VirtualSize = section_rsize;

// change oep
  nt_header -> OptionalHeader.AddressOfEntryPoint = section_vaddr + section_vsize;

//Add write attribution to code section
  oep_section_header -> Characteristics |= IMAGE_SCN_MEM_WRITE;

// dump packed binary (Make a list of packed program)
  hPackedBin = CreateFile(packed_filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hpackedBin == INVALID_HANDLE_VALUE){
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

  returen ret;
}





