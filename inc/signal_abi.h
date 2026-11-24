#pragma once

/* Minimum alternate signal stack accepted by the current x86-64 signal ABI.
 * Keep exec's AT_MINSIGSTKSZ and sigaltstack's validation in agreement. */
#define MINSIGSTKSZ_AXON 2048u
