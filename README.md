# Evo Netflow Collector

This is a command line Netflow collector application that collects and dumps Netflow traffic that is sent via UDP. Can dump Netflow to standard output or a file. More options are to come. Currently supports Netflow v1, v5, v7, v9 and v10 (IPFIX) and runs on Windows and Linux.

The project was created with TheIDE, part of U++ (http://www.ultimatepp.org/). This development framework can be downloaded on Windows or Linux, and installed. The command-line builder UMK or the IDE itself can be used to build EvoNetflowCollector.

## Getting it to run using UMK

*EvoNetflowCollector* can be built in release mode with UMK by:

```
umk MyApps EvoNetflowCollector GCC -r +MT,SSE2,NOI18N EvoNetflowCollector
```

It can also be built in debug mode by:

```
umk MyApps EvoNetflowCollector GCC -d +MT,SSE2,NOI18N EvoNetflowCollector
```

## Getting it to run using TheIDE

In a graphical environment, TheIDE can be used to compile and debug EvoNetflowCollector. Follow the installation steps of the IDE, load the project and build it however you like it!
