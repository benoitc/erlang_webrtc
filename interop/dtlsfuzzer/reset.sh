#!/bin/bash
# Run by DTLS-Fuzzer before each test: the SUT forgets every connection.
# The fuzzer takes this process for the SUT, so it stays up until the
# fuzzer stops it at the end of the test.
printf reset > /dev/udp/127.0.0.1/${1:-20001}
exec sleep 86400
