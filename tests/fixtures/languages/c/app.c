#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char name[256];
    double balance;
} Account;

Account* create_account(int id, const char* name) {
    Account* acc = malloc(sizeof(Account));
    if (!acc) return NULL;
    acc->id = id;
    strncpy(acc->name, name, sizeof(acc->name) - 1);
    acc->balance = 0.0;
    return acc;
}

void deposit(Account* acc, double amount) {
    if (amount > 0) {
        acc->balance += amount;
    }
}

int main(int argc, char* argv[]) {
    Account* acc = create_account(1, "Alice");
    deposit(acc, 500.0);
    printf("Account: %s, Balance: %.2f\n", acc->name, acc->balance);
    free(acc);
    return 0;
}