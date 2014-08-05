*Status: DEV*

A Secured PINF JavaScript Loader
================================

A [PINF JavaScript Loader](https://github.com/pinf/pinf-loader-js) Sandbox
and middleware that polices bundles and resources to allow only declared
and known assets into a sandbox.

Uses the [Stanford Javascript Crypto Library](https://github.com/bitwiseshiftleft/sjcl)
and [eccjs](https://github.com/jpillora/eccjs) to verify checksums and signatures.

The weight of the client sandbox security layer currently comes in at
around **25KB minified and gzipped**. With some optimization this *may* be
reduced to 20KB.


Install
-------

**TODO**


Usage
-----

**TODO**


Development
-----------

NOTE: The development environment for this project is implemented using
PINF conventions and libraries and serves as a reference implementation
for how to code portable bundles using PINF technology. Expect changes.

Install:

    npm install

Run:

    node workspace/server.js
    open http://localhost:3000/
    # Look for 'Hello World' in console


License
=======

[UNLICENSE](http://unlicense.org/)
