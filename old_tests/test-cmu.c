void foo (int *p, int q) { *p = q + 42; }
int main(void) {
int y = 10;
int x = 84;
foo(&x, y);
return 0;
}