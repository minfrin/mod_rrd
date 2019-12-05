# mod_rrd
Apache httpd module to render RRD graphs via a webserver.

Depends on rrdtool from https://oss.oetiker.ch/rrdtool/.

## Highlights
- All files referred to by DEF elements are subject to [Apache httpd's
  access control](https://httpd.apache.org/docs/2.4/howto/access.html) mechanism.
- DEF elements support *wilcards*. Each matching file generates a
  matching DEF element, along with matching LINE/AREA/TICK elements,
  with corresponding PRINT and GPRINT elements.
- DEF elements support [Apache httpd expression syntax](https://httpd.apache.org/docs/2.4/expr.html) within the
  path component, allowing paths to be constructed dynamically based
  on matching URLs.
- All legends support [Apache httpd expression syntax](https://httpd.apache.org/docs/2.4/expr.html), allowing text
  to be dynamically inserted from the URL or the request.

Example config:

    <IfModule mod_rrd.c>
    <Directory "/var/lib/collectd/rrd">
      Require all granted
    </Directory>
    Alias /rrd /var/lib/collectd/rrd
    <Location /rrd>
      RRDGraph on
      RRDGraphEnv METHODS %{MATCH_METHOD}
      RRDGraphOption title :%{SERVER_NAME}
      RRDGraphElement DEF:ifOutOctets=monitor*.rrd:ifOutOctets:AVERAGE "optional/expression/monitor*.rrd" "/optional/path/prefix/"
      RRDGraphElement VDEF:ifOutOctetsmax=ifOutOctets,MAXIMUM
      RRDGraphElement CDEF:combined=ifOutOctets,1,+
      RRDGraphElement LINE1:ifOutOctets#00ff00: %{SERVER_NAME}
      RRDGraphElement AREA:ifOutOctets#00ff00: %{SERVER_NAME}
      RRDGraphElement TICK:ifOutOctets#00ff00:1.0: %{SERVER_NAME}
      RRDGraphElement "VRULE:0#FF0000::dashes" %{SERVER_NAME}
      RRDGraphElement "HRULE:0#FF0000::dashes" %{SERVER_NAME}
      RRDGraphElement "COMMENT:" %{env:METHODS}
    </Location>
    </IfModule>

