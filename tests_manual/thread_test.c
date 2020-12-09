#include <stdio.h>
#include <pthread.h>

void start1() {
  int i = 100;
  for (int i = 0; i < 2; i++) { printf("t1 %d\n", i); sleep(1); }
}

void start2() {
  int i = 200;
  for (int i = 0; i < 2; i++) { printf("t2 %d\n", i); sleep(1); }
}

int main() {
  pthread_t t1, t2;
  pthread_create(&t1, NULL, start1, NULL);
  pthread_create(&t2, NULL, start2, NULL);
  pthread_join(t1, NULL);
}

