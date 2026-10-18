# SilkShield on IBM LinuxONE

## Objective

Demonstrate that SilkShield's security analysis workload can run on IBM
LinuxONE.

The verified host environment reported during the event (`lscpu`):

``` text
Architecture:                s390x
  CPU op-mode(s):            32-bit, 64-bit
  Byte Order:                Big Endian
CPU(s):                      3
  On-line CPU(s) list:       0-2
Vendor ID:                   IBM/S390
  Model name:                -
    Machine type:            9175
    Thread(s) per core:      1
    Core(s) per socket:      1
    CPU dynamic MHz:         5508
    CPU static MHz:          5508
    BogoMIPS:                28901.00
    Dispatching mode:        horizontal
Virtualization features:
  Hypervisor:                z/VM 7.3.0
  Hypervisor vendor:         IBM
  Virtualization type:       full
Caches:
  L1d:                       384 KiB (3 instances)
  L1i:                       384 KiB (3 instances)
  L2:                        108 MiB (3 instances)
  L3:                        360 MiB
NUMA:
  NUMA node(s):              1
  NUMA node0 CPU(s):         0-2
Hardware Acceleration Flags:
  msa (CPACF crypto assist), nnpa (Telum AI assist), sort, dflt, sie
```

## Deployment Target

Primary runtime:

``` text
IBM LinuxONE
s390x
Linux
```

## Deployment Priorities

1.  Application starts successfully.
2.  `/health` works.
3.  `/analyze` works.
4.  ML inference works.
5.  AI layer works or has a clearly labelled fallback.
6.  Demo UI can reach the backend.

## Benchmark

Collect simple measurements:

-   average analysis latency
-   number of analyses in a test run
-   successful requests
-   CPU usage
-   memory usage

Example:

``` text
Test cases: 50
Successful: 50
Average latency: XX ms
P95 latency: XX ms
CPU: XX%
Memory: XX MB
```

Do not fabricate benchmark numbers. Record actual measurements.

## IBM Z Story

The presentation should explain why the platform matters:

-   enterprise-oriented compute
-   secure workload environment
-   scalable processing
-   ability to run AI/ML workloads on IBM architecture
-   direct use of LinuxONE in the prototype

Avoid claiming platform capabilities that were not actually tested.

## Deployment Notes

Keep secrets out of source control.

Use:

``` text
.env
```

locally and:

``` text
.env.example
```

for documentation.

## Demo Requirement

The final demo should visibly show that the backend is running on the
IBM LinuxONE environment.
