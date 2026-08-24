#include <iostream>
#include <vector>
#include <string>
#include <memory>

template <typename T>
T max_value(T a, T b) {
    return (a > b) ? a : b;
}

class BankAccount {
public:
    BankAccount(int id, std::string name, double balance)
        : id_(id), name_(std::move(name)), balance_(balance) {}

    int id() const { return id_; }
    std::string name() const { return name_; }
    double balance() const { return balance_; }

    void deposit(double amount) {
        if (amount > 0) balance_ += amount;
    }

    bool withdraw(double amount) {
        if (amount > 0 && amount <= balance_) {
            balance_ -= amount;
            return true;
        }
        return false;
    }

private:
    int id_;
    std::string name_;
    double balance_;
};

std::vector<BankAccount> load_accounts(const std::string& path) {
    std::vector<BankAccount> accounts;
    accounts.emplace_back(1, "Alice", 500.0);
    accounts.emplace_back(2, "Bob", 250.0);
    return accounts;
}

int main() {
    auto accounts = load_accounts("/data/accounts.csv");
    for (const auto& acc : accounts) {
        std::cout << acc.id() << ": " << acc.name() << " ($" << acc.balance() << ")\n";
    }
    return 0;
}