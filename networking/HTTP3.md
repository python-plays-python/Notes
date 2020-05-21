## HTTP/1.0

It all started back in 1996 with the publication of the HTTP/1.0 specification which defined the basic HTTP textual wire format as we know it today (for the purposes of this post I’m pretending HTTP/0.9 never existed). In HTTP/1.0 a new TCP connection is created for each request/response exchange between clients and servers, meaning that all requests incur a latency penalty as the TCP and TLS handshakes are completed before each request.

Worse still, rather than sending all outstanding data as fast as possible once the connection is established, TCP enforces a warm-up period called “slow start”, which allows the TCP congestion control algorithm to determine the amount of data that can be in flight at any given moment before congestion on the network path occurs, and avoid flooding the network with packets it can’t handle. But because new connections have to go through the slow start process, they can’t use all of the network bandwidth available immediately.

## HTTP/1.1

The HTTP/1.1 revision of the HTTP specification tried to solve these problems a few years later by introducing the concept of “keep-alive” connections, that allow clients to reuse TCP connections, and thus amortize the cost of the initial connection establishment and slow start across multiple requests. But this was no silver bullet: while multiple requests could share the same connection, they still had to be serialized one after the other, so a client and server could only execute a single request/response exchange at any given time for each connection.

## HTTP/2

Finally, more than a decade later, came SPDY and then HTTP/2, which, among other things, introduced the concept of HTTP “streams”: an abstraction that allows HTTP implementations to concurrently multiplex different HTTP exchanges onto the same TCP connection, allowing browsers to more efficiently reuse TCP connections.

But, yet again, this was no silver bullet! HTTP/2 solves the original problem — inefficient use of a single TCP connection — since multiple requests/responses can now be transmitted over the same connection at the same time. However, all requests and responses are equally affected by packet loss (e.g. due to network congestion), even if the data that is lost only concerns a single request

## HTTP/3

This is where HTTP/3 comes into play: instead of using TCP as the transport layer for the session, it uses QUIC, a new Internet transport protocol, which, among other things, introduces streams as first-class citizens at the transport layer. QUIC streams share the same QUIC connection, so no additional handshakes and slow starts are required to create new ones, but QUIC streams are delivered independently such that in most cases packet loss affecting one stream doesn't affect others. This is possible because QUIC packets are encapsulated on top of UDP datagrams.

Using UDP allows much more flexibility compared to TCP, and enables QUIC implementations to live fully in user-space — updates to the protocol’s implementations are not tied to operating systems updates as is the case with TCP. With QUIC, HTTP-level streams can be simply mapped on top of QUIC streams to get all the benefits of HTTP/2 without the head-of-line blocking.

QUIC also combines the typical 3-way TCP handshake with TLS 1.3's handshake. Combining these steps means that encryption and authentication are provided by default, and also enables faster connection establishment. In other words, even when a new QUIC connection is required for the initial request in an HTTP session, the latency incurred before data starts flowing is lower than that of TCP with TLS.