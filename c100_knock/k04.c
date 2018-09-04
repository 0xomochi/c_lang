//0xomochi
//k04.c
//整数値を入力させ、その入力値を三倍した計算結果を表示するプログラム

# include <stdio.h>

int main(){
    int a;
    int b = 3;
    int c;
    printf("put your number here:");
    scanf("%d", &a);
    c = a * b;
    printf("your number is %d\n", c);
}
