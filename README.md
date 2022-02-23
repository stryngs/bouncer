# bouncer
Knowing the direction of packets in an environment is crucial where you are trying to tune a product based on I/O operations that are dynamic in nature and can change based on many variables.

In a perfect world packets per second would be consistent.  In the real world the input you expect to something such as a SIEM can change rapidly.  This shift can throw off a baseline if unaccounted for.  Depending on the factors involved with your infrastructure, the very act of monitoring can produce cascading failures because it became the straw and the camel's back was already under too much load.

bouncer tries to walk that thin line between monitoring and monitoring in a way that can noticeably change expected inputs over time.

### Getting started
```
python3 ./bouncer.py
```
This runs bouncer using 1000 packets as the baseline to count against; bouncer will continue to run until crtl+c is invoked.  stdout for bouncer is abbreviated as such:
```
packets per second | time to achieve baseline | filter if any | baseline | iteration
```

### Interpreting the reader (-r)
```
port | count
```

### It doesn't do that
bouncer was made to be hacked, make it do just that; sharing is caring.
