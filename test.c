#include <stdio.h>

int main() {
    double a = 1.1, b = 2.1, res;
    // __asm__ __volatile__("fldl %1\n\t"
    //                      "fldl %2\n\t"
    //                      "faddp \n\t"
    //                      "fstpl %0\n\t"
    //                      : "=m"(res)
    //                      : "m"(a), "m"(b));
    __asm__ __volatile__("fldl %1\n\t"
                         "fstpl %0\n\t"
                         : "=m"(res)
                         : "m"(a));
    // printf("result = %f\n", a);
    // printf("result = %f\n", res);
    if (res == a)
        printf("ok1\n");
    else
        printf("no1\n");
    if (res >= a)
        printf("ok2\n");
    else
        printf("no2\n");
    if (res != a)
        printf("no3\n");
    else
        printf("ok3\n");
    if (res > a)
        printf("no4\n");
    else
        printf("ok4\n");
    return 0;
}
