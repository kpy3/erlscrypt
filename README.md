erlscrypt
=========

[![Build Status](https://github.com/kpy3/erlscrypt/workflows/Test/badge.svg)](https://github.com/kpy3/erlscrypt/actions?query=branch%3Amaster+workflow%3A"Test") [![Erlang Versions](https://img.shields.io/badge/Supported%20Erlang%2FOTP-21.0%20to%2023.0-blue)](http://www.erlang.org)


An Erlang NIF for Colin Percival's "scrypt" function.

General information can be found in [these slides (PDF)](http://www.tarsnap.com/scrypt/scrypt-slides.pdf)
and [Colin Percival's page on scrypt](http://www.tarsnap.com/scrypt.html).

This library uses code from scrypt [1.3.1](https://github.com/Tarsnap/scrypt/tree/1.3.1).

Using the library
-----
Add library as dependency in `rebar.config` 

    {deps, [
        {erlscrypt, "1.0.0"}
        ...
    ]}.

Add `scrypt` as application dependency

    {application, app,
         [
          {applications, [
                          ...
                          scrypt
                         ]},
          ...
         ]}. 

Use `scrypt:scrypt/6` for encrypting data.
