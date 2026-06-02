# Profiling

## CPU profiling
As part of profiling the node binary, we would like to know _where_ the node is spending CPU cycles, or _CPU time_. This helps us determine what part of the codebase we might have bottlenecks, and showing hot spots in our application that can be worth optimizing.

For example a blocking system call will consume CPU time, but not CPU cycles.

The node binary has a monitoring web server in, [crates/node/src/profiler/web_server.rs](../crates/node/src/profiler/web_server.rs), which allows outside clients to send requests to it and get back pprof profiles which shows CPU usage. The port the node hosts this web server on is part of the node config, `pprof_bind_address`, and by default is set to `34001`.

For the node to generate a pprof profile, it will have to take a sample at the specified sampling rate (default is 1000hz), where each sample collects a stack trace by walking the stack. Since collecting a CPU sample consumes non negligible CPU cycles, (~2-5% CPU, depends on the CPU), we don't want to have this endpoint public.

For that reason we have the firewall 
[scripts/update-mpc-node.sh](../scripts/update-mpc-node.sh:45)


### Why not Perf?
perf is a system level profiling tool which requires root access to run. Given that our production nodes run inside CVMs, and the security we want to enforce inside those enclaves, we don't want operators to run commands inside the enclave with sudo access, which is necessary for perf.

## Memory profiling