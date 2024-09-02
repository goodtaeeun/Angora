/*
  Test:
  Test for tainted pointer address
 */
#include "stdio.h"
#include "stdint.h"
#include "stdlib.h"
#include "string.h"

int main () {
  int buf[20];

  FILE* fp = fopen("pointer_arith_fp/args", "rb");

    for (int i =0; i < 10; i ++)
        buf[i] = fgetc(fp) - '0';
//   fread(buf, sizeof *buf, 6, fp);

// fclose(fp);

    int* ptr = buf;
    int idx = buf[3];
    ptr += idx;
    int content = *ptr;
    printf("Reading from idx: %d\n", idx);
    printf("%d\n", *ptr);
    printf("%d\n", content);

}

