# mod_rrd
Apache httpd module to render RRD graphs via a webserver.

Depends on rrdtool from https://oss.oetiker.ch/rrdtool/.

Example config:

    <IfModule mod_rrd.c>
    <Directory "/var/lib/collectd/rrd">
      Require all granted
    </Directory>
    Alias /rrd /var/lib/collectd/rrd
    <Location /rrd>
      RRDGraph on
      RRDGraphEnv METHODS %{REQUEST_METHOD}
      RRDGraphOption title :%{SERVER_NAME}
      RRDGraphElement DEF:ifOutOctets=monitor*.rrd:ifOutOctets:AVERAGE
      RRDGraphElement VDEF:ifOutOctetsmax=ifOutOctets,MAXIMUM
      RRDGraphElement CDEF:combined=ifOutOctets,1,+
      RRDGraphElement LINE1:ifOutOctets#00ff00:Out+Octets :%{SERVER_NAME}
      RRDGraphElement AREA:ifOutOctets#00ff00:Out+Octets :%{SERVER_NAME}
      RRDGraphElement TICK:ifOutOctets#00ff00:1.0:Failures :%{SERVER_NAME}
      RRDGraphElement "VRULE:0#FF0000:dashed line:dashes" :%{SERVER_NAME}
      RRDGraphElement "HRULE:0#FF0000:dashed line:dashes" :%{SERVER_NAME}
      RRDGraphElement "COMMENT:Foo" %{env:METHODS}
    </Location>
    </IfModule>

