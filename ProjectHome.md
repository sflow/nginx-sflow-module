# Description #
nginx module to implement logging using sFlow (http://www.sflow.org).  The purpose is for continuous, real-time monitoring of large web clusters.  The sFlow mechanism allows for a random 1-in-N sample of the URL transactions to be reported,  along with a periodic snapshot of the most important counters,  all using sFlow's efficient XDR-encoded UDP "push" model.   There is no limit to the number of web-servers that can be sending to a single sFlow collector.

This is designed to work together with sFlow monitoring in switches, routers, servers, hypervisors and load-balancers.  For details and examples,  see:

http://blog.sflow.com/2011/04/nginx.html


# Download Latest Version #

```
svn checkout http://nginx-sflow-module.googlecode.com/svn/tags/release-0.9.10 nginx-sflow-module-0.9.10
```

Then consult README for build instructions.

(Have to do it this way because Google Code no longer supports downloads)

# Dependencies #

Requires [Host-sFlow daemon](http://host-sflow.sourceforge.net)

# Related Projects #

  * [Open vSwitch](http://openvswitch.org) exports network flows and v-port counters.
  * [jmx-sflow-agent](http://jmx-sflow-agent.googlecode.com) exports Java virtual machine metrics.
  * [mod-sflow](http://mod-sflow.googlecode.com) exports HTTP metrics from Apache.
  * [tomcat-sflow-valve](http://tomcat-sflow-valve.googlecode.com) exports HTTP metrics from Tomcat.
  * [node-sflow-module](http://node-sflow-module.googlecode.com) exports HTTP metrics from node.js.
  * [sflow/haproxy](https://github.com/sflow/haproxy) exports HTTP metrics from HAProxy.
  * [sflow/memcached](https://github.com/sflow/memcached) exports Memcache metrics from Memcached.