/*
  Test:
  Angora supports stdin.
*/
#include <stdio.h>

int main () {
  int ch[12];

  for (int i = 0; i < 12; i++) {
    ch[i] = getchar();
  }

  for (int i = 0; i < 12; i+=3) {
    int c=0; c += (ch[i] + 3);
    printf("%d", c);
  }

  int x;
  x = 3;
  if (ch[0] == 'a') {
    x = ch[1] + ch[2];
    printf("%d\n", x);
  }

  printf("%d\n", x);

}
