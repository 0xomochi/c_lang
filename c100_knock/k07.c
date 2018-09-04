//0xomochi
//k07.c
//整数値を入力させ、値が0なら"zero"、0でなければ"not zero"と表示するプログラム

# include <stdio.h>

int main(){
    int a;
    printf("input number:");
    scanf("%d", &a);
    if(a==0)
        printf("zero\n");
    else
        printf("not zero\n");
}
