// Package useragent holds the one User-Agent bk sends, so every HTTP path in
// the factory sends the same one.
//
// It exists because they did not. `versions` set it — with a comment naming the
// host that forced it — and `fetch` did not, because `fetch` used http.Get
// verbatim. So bk could LIST a project's versions and then fail to DOWNLOAD the
// tarball it had just found:
//
//	libisl.sourceforge.io 0.28 — build failed:
//	  fetch: GET https://libisl.sourceforge.io/isl-0.28.tar.bz2: 403 Forbidden
//
// Measured against that host, from a machine that could reach it:
//
//	User-Agent: Go-http-client/2.0   403      ← Go's default
//	User-Agent: bk                   200
//	User-Agent: curl/8.7.1           200
//	no User-Agent at all             200
//
// The 403 is not about the file, the format or the network — sourceforge
// rejects Go's default agent by name. A constant in one place is what stops the
// next HTTP path from learning that again.
package useragent

// String identifies bk to the hosts it fetches from. It names the project so an
// operator reading their logs can find out who is asking, which is the whole
// social contract behind a User-Agent.
const String = "zpkb (+https://github.com/go-zpkg/zpkb)"
