# dns
toy recursive DNS resolver that does its own parsing and socket communication, just for fun

implements some of [rfc 1035](https://datatracker.ietf.org/doc/html/rfc1035) (only does A and MX records)

there's like a million of these out there, and this one is not particularly good, but,

```
$ ./dns.py
A twitter.com: 104.244.42.65
MX google.com: alt1.aspmx.l.google.com.
```

inspired by
* https://jvns.ca/blog/2022/02/01/a-dns-resolver-in-80-lines-of-go/
* https://blog.adamchalmers.com/nom-dns/
