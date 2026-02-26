# ZONEFAST - fast zone file parser

## Abstract

(This project is halfway complete -- don't pay attention to it).

This project is for parsing **DNS zonefiles** faster, using a 
number of techniques including **SIMD**.

Over a decade ago, my `robdns` zonefile parser ran at about
0.4-GB/s. Last year, a paper `simdzone` was published that used SIMD,
getting 0.8-GB/s (on the x86 Ice Lake CPU).

I have some other ideas on how to use SIMD to parse zonefiles, which
I'm building in this project.

I'm currently getting 1.0-GB/s on my MacBook Air M3 on the same test
(`se.` TLD), and think I get can get closer to 1.5-GB/s with a bit
more work optimization.

## Vibe SIMD

This project is heavily "vibe coded" using AI.

Specifically, it's writing all the SIMD for me. This allows me to
support simultaneously ARM, x86, and RISC-V CPUs without having
to pay attention to the details.

## `simdzone`

There are a numbe of issues I have with that paper.

First of all, I'm not sure `simdjson` is the best model. Parsing JSON
means skipping through a lot of filler tokens, like spaces, braces,
brackets, equals, and so on

In contrast, with zonefiles, the only filler is a spaces between
tokens. I'm doing some of the JSON parsing techniques, but largely,
I don't think there's a benefit applying them everywhere.

Instead, the major benefit is just smarter parsing of the tokens,
like smart parsing of DNS names, faster integer parsing, type
name lookups, and so fort.

The one thing where I think SIMD could speed things up is `BASE64` and
`HEX` parsing, like in `RRSIG` and `DS` records. I've gotten a pretty
substantial speed improvement using SIMD BASE64 (`Turbo-BASE64` library).
This is something that could be easily retrofitted on any existing DNS
zonefile parser without much effort.

But `simdzone` doesn't use SIMD for BASE64 or HEX, and that's a little
wierd. I need to benchmark their scalar decoders -- maybe their scalar
decoders are equivelent in speed to the library I've chosen. That library
is ass -- to use it, I first need to pre-parse the string to find it's
length. This cut the speed in half, having to effectively parse the `RRSIG`
contents twice.

So far, I'm finding about half the time I do something better, easier,
or clearly than the `simdzone` project. The other half of the time, I
find that they do something really clever that I learn from.


## Running

Just run the program on an existing zonefile, such as:

```
   zonefast se.zone
```

This will report the number of **gigabytes-per-second** and number
of **records-per-second** that it parses.

This project wwas developed with the Swedish TLD zone `se.`
as it's publicly available -- just do a zone transfer from their
servers.


## Building

Just type `make` or `gcc src/*.c`.

```
git clone https://github.com/robertgraham.com/zonefast.git
cd zonefast
gcc -O3 -g -o bin/zonefast src/*.c
```

It's standard C and seems to compile on Windows, macOS, and Linux.

Right now, it's 64-bit and little-endian, but this be fixed
eventually.

Right now it supports x86, ARM, and RISCV-V, though I intend
to add POWER AltiVec2 and Longsoon to match other papers like
`simdjson`. It's just that I need to find systems to compile
and test on.

## Reading the code

FYI: Easiest way to browse the code is to run a profiler to see
where it's executing stuff. That applies to anything, but paritcularly
this project.

I put a prefix on the filenames instead of putting them in directories.

- `main.c` - contains `main()`
- `util-...` - contain utility functions not dependent on this project,
  often copied from other projects.
- `zone-scan-...` - the thread that scans the input file tracking
  state, chopping it up into chunks.
- `zone-parse...` - the code that parses the chunks. Can also simply
  be given an entire file -- you can effectively delete z`one-scan...`
  from this project and still have a working parser -- just single
  threaded.
- `zone-atom-...` - a subcomponent of the parers dealing with individual
  fields with records, like integers, TXT strings, IP addresses,
  BASE64, and so on.
  
Throughout the code each sub-module will have an `init` and `quicktest`
function.

```c
void zone_parse_init(int backend);
int zone_parse_quicktest(void);
```

The `init` function sets which SIMD kernel/backend we'll be using.

The `quicktest` function runs a quick/minimal regression/unit test.

## Testing

Most of the files contain a `...quicktest()` that does a short regression
test of that unit. The program runs this regression test at startup,
before it starts parsing the file, and will exit if there's a failure.

You can therefore put a breakpoint (in a debugger) on any line of code
and run the program with no arguments in order to execute that line of
code.
