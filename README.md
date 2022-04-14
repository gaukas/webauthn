# WebAuthn Library

[![GoDoc](https://godoc.org/github.com/Gaukas/webauthn?status.svg)](https://godoc.org/github.com/Gaukas/webauthn)
![Build Status](https://github.com/Gaukas/webauthn/workflows/Go/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/Gaukas/webauthn)](https://goreportcard.com/report/github.com/Gaukas/webauthn)


This library is meant to handle [Web Authentication](https://w3c.github.io/webauthn) for Go apps that wish to implement a passwordless solution for users. While the specification is currently in Candidate Recommendation, this library conforms as much as possible to 
the guidelines and implementation procedures outlined by the document.

See pinned issues for to-do features. 

## Quickstart

`go get github.com/Gaukas/webauthn` and initialize it in your application with basic configuration values. 

Make sure your `user` model is able to handle the interface functions laid out in `webauthn/user.go`. This means also supporting the storage and retrieval of the credential and authenticator structs in `webauthn/credential.go` and `webauthn/authenticator.go`, respectively.

## Acknowledgements

This project is majorly based on the original version of WebAuthn Library developed and published by [duo-labs](https://github.com/duo-labs/webauthn)

## Original Acknowledgements

I could not have made this library without the work of [Jordan Wright](https://twitter.com/jw_sec) and the designs done for our demo site by [Emily Rosen](http://www.emiroze.design/). When I began refactoring this library in December 2018, [Koen Vlaswinkel's](https://github.com/koesie10) Golang WebAuthn library really helped set me in the right direction. A huge thanks to [Alex Seigler](https://github.com/aseigler) for his continuing work on this WebAuthn library and many others. Thanks to everyone who submitted issues and pull requests to help make this library what it is today!
