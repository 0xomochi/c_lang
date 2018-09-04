//0xomochi
//k09.c
//整数値を入力させ、値が正であれば"positive"、負であれば"negative"、0であれば"zero"と表示するプログラム

# include <stdio.h>

int main(){
    int a;
    printf("input number:");
    scanf("%d", &a);
    if(a>=1)
        printf("positive\n");
    else if(a==0)
        printf("zero\n");
    else if(a<=-1)
        printf("negative\n");
}
