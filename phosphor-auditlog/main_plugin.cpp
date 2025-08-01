#include <phosphor-logging/lg2.hpp>

int main(int /*argc*/, char* /*argv*/[])
{
    lg2::info("An audit event was received");

    return 0;
}
