#include "koreanseller.h"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::fprintf(stderr, "<sign> <target>\n", argv[0]);
        return EXIT_FAILURE;
    }

    std::string input = argv[1];
    std::string output = argv[2];

    init_hooks();

    if (!copy_cert(input, output)) {
        std::fprintf(stderr, "Failed", input.c_str(), output.c_str());
        return EXIT_FAILURE;
    }

    std::printf("successfully", input.c_str(), output.c_str());
    return EXIT_SUCCESS;
}