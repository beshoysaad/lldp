# HON LLDP Agent

This project implements a skeleton for a minimal LLDP agent in Python.

The finished LLDP agent is able to announce information about itself as well as receive information from neightboring
systems.

## Python Version

Please be aware that the LLDP agent require at least Python version 3.6. The agent and unit tests will not work with
lower Python versions.

## Project Tasks

Before starting this project you should refamiliarize yourself with the LLDP protocol using the lecture slides.
The slides give you a basic description of the LLDP protocol and its message format. Detailed information is given along
with the class definitions in the agent skeleton.

If you are unsure about where functionality has to be implemented look for comments marking a "TODO:" or
the "NotImplemented" class/type.

We advise you to start by implementing the TLVs (in the files in the `lldp/tlv` directory) and work your way up from
there.

To pass the project your code will have to **pass all the unit tests** provided.
You are not allowed to use any third-party python packages. 

## Unit Tests

The skeleton comes with a set of unit tests. These allow you to validate (parts of) your implementation early on,
without having to implement all of the functionality in one go and are located in the `test/` directory.

To run the unit tests you can issue the following command in the project root:

    python3.6 -m unittest test

To only run a subset of the unit tests you can specify the specific test case (i.e. class) to run.
If you e.g. want to run only the tests for TTL TLVs (in test/ttl_tlv.py), you can use the following command:

    python3.6 -m unittest test.TTLTLV

To find out more about using unit tests in Python, check out https://docs.python.org/3.6/library/unittest.html or
run the command

    python3.6 -m unittest --help

Unit tests may also be run from an IDE like PyCharm.

Feel free to write some tests of your own.

## Running the Agent

Once you finished your implementation you can e.g. test the LLDP agent on your local network.
When running the LLDP agent be aware, that it needs to be able to send raw Ethernet frames to the network, which
requires the agent to run with root priviliges.

From the project root directory you can use the following command:
 
    sudo ./main.py
    
To run the agent on a specific network interface simply append the interface name:

    sudo ./main.py eth1