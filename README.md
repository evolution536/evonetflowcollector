# Evo Netflow Collector

This is a command line Netflow collector application that collects and dumps Netflow traffic that is sent via UDP. Can dump Netflow to standard output or a file. More options are to come. Currently supports Netflow v5 and runs on Windows and Linux.

## Getting it to run on Windows

The project was created in Windows using Visual Studio 2013. You can open the solution file in Windows, select *Release* compilation mode and build the project.

## Getting it to run on Linux

It can be built on Linux using autoconf. Go to the *EvoNetflowCollector* subdirectory and execute the following commands (The default installation directory is /opt/evonetflowcollector. It can be changed with ./configure --prefix=/<otherdir>):

```
autoreconf -vif
./configure
make
make install
```