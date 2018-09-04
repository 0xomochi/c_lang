//0xomochi
//k08.c
//整数値を入力させ、値が正であれば(0は正に含まない)"positive"と表示するプログラム

# include <stdio.h>

int main(){
    int a;
    printf("input number:");
    scanf("%d", &a);
    if (a >= 1)
        printf("positive\n");
}
