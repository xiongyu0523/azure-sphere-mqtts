// This minimal Azure Sphere app prints "High Level Application" to the debug
// console and exits with status 0.

#include <applibs/log.h>

int main(void)
{
    // Please see the extensible samples at: https://github.com/Azure/azure-sphere-samples
    // for examples of Azure Sphere platform features
    Log_Debug("High Level Application\n");
    return 0;
}
