// This is the code of my first packer.

# include <stdio.h>
# include <windows.h>

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
unsigned int bdecoder_offset          = 18;
unsigned int jmp_oep_addr_offset      = 27;

void create_decode_stub(
  unsigned int code_vaddr, unsigned int code_vsize,
  unsigned int base_vaddr, unsigned int decoder, unsigned int oep)
{
  int cnt = 0;
  int jmp_len_to_oep = 0;

  jmp_len_to_oep = oep -
                  (code_vaddr + code_vsize + sizeof(decode_stub));
  memcpy(&decode_stub[decode_start_offset], &code_vaddr, sizeof(DWORD));

