# SilkShield on IBM LinuxONE

## Objective

Demonstrate that SilkShield's security analysis workload can run on IBM
LinuxONE.

The available environment reported during the event includes:

``` text
Architecture: s390x
CPU(s): 3
Hypervisor: z/VM 7.3.0
Vendor: IBM/S390
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
