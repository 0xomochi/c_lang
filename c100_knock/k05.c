//0xomochi
//k05.c
//整数値を二つ入力してそれらの値の和、差、積、商と余りを求めるプログラム

# include <stdio.h>

int main(){
    int a, b, c, d, e, f, g;

    printf("input 1st number:");
    scanf("%d", &a);
    printf("input 2nd number:");
    scanf("%d", &b);

    //addition
    c = a + b;
    printf("sum: %d\n", c);
    
    //subtraction
    d = a - b;
    printf("difference: %d\n", d);
    
    //multiplication
    e = a * b;
    printf("product: %d\n", e);
    
    //division
    f = a / b;
    g = a % b;
    printf("quotient: %d",f);
    printf(", remainder: %d\n", g);
}
