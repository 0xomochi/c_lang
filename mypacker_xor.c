// This is the code of my first packer.
// The code from the book named  "Analyzing Malware"

# include <stdio.h>
# include <windows.h>

// ???

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

void create_decode_stub(
  unsigned int code_vaddr, unsigned int code_vsize,
  unsigned int base_vaddr, unsigned int decoder, unsigned int oep)
{
  int cnt = 0;
  int jmp_len_to_oep = 0;

  jmp_len_to_oep = oep - (code_vaddr + code_vsize + sizeof(decode_stub));

  memcpy(&decode_stub[decode_start_offset], &code_vaddr, sizeof(DWORD));
  memcpy(&decode_stub[decode_size_offset], &code_vsize, sizeof(DWORD));
  memcpy(&decode_stub[base_address_offset], &base_addr, sizeof(DWORD));
  memcpy(&decode_stub[jmp_oep_addr_offset], &jmp_len_to_oep, sizeof(DWORD)):
  
  return;
}

void xor_encoder(unsigned char *start, unsigned int size, BYTE encoder}{
    
    unsigned int    cnt = 0;

    for(cnt = 0; cnt < size; cnt++){
        start[cnt] ^= encoder;
    }
}

int main(int argc, char **argv){

  // ???

  target_filename = argv[1];
  packed_filename = argv[2];

// Loading the program will be packed
hTargetBin = CreateFile(target_filename, GENERIC_READ, 0, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
if(hTargetBin == INVALID_HANDLE_VALUE){

// ???

}

dwTargetBinSize = GetFileSize(hTargetBin, NULL);
if(dwTargetBinSize == -1){

  // ???

}

IpTargetBinBuffer =
 (unsigned char*)malloc(sizeof(unsigned char) * dwTargetBinSize);
if(IpTargetBinBuffer == NULL){

  // ???
}

bRslt = ReadFile(hTargetBin, IpTargetBinBuffer,
                 dwTargetBinSize != dwReadSize){
  // ???
}

// Collecting information of PE headers
nt_header = get_nt_header(IpTargetBinBuffer);
oep = nt_header -> OptionalHeader.AddressOfEntryPoint;
base_addr = nt_header -> OptionalHeader.ImageBase;

// Searching the code section includint entry point
oep_section_header = search_oep_incluse_secion_header(nt_header, oep);
if(oep_section_header == NULL){
    printf("OEP include section search faild.\n");
    goto END;
}


// Getting the address and size of codesection
section_vaddr = oep_section_header -> VirtualAddress;
section_vaddr = oep_section_header -> Misc.VirtualSize;
section_vaddr = oep_section_header -> PointerToRawData;
section_vaddr = oep_section_header -> SizeOfRawData;

// Encoding the code area
encoder = 0xFF
