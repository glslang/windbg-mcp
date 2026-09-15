/* Standalone upstream ARM64 decoder regression. See docs/clrbhb-native-validation.md. */
#include "decode.h"
#include "format.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    const uint32_t words[] = {0xd50322df, 0xd503201f, 0xd503229f};
    const enum Operation operations[] = {ARM64_CLRBHB, ARM64_NOP, ARM64_CSDB};
    const char *names[] = {"clrbhb", "nop", "csdb"};
    int failures = 0;
    for (unsigned i = 0; i < 3; ++i) {
        Instruction instruction = {0};
        char text[128] = {0};
        int decode = aarch64_decompose(words[i], &instruction, 0x1000);
        int format = decode == 0 ? aarch64_disassemble(&instruction, text, sizeof(text)) : -1;
        int passed = decode == 0 && format == 0 && instruction.operation == operations[i]
            && strncmp(text, names[i], strlen(names[i])) == 0;
        printf("{\"word\":\"%08x\",\"decode\":%d,\"format\":%d,\"text\":\"%s\",\"passed\":%s}\n",
               words[i], decode, format, text, passed ? "true" : "false");
        failures += !passed;
    }
    return failures ? 1 : 0;
}
