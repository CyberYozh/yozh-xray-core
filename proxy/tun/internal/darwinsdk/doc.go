// Package darwinsdk exposes, for tests only, sizes, field offsets and macro
// values exactly as the C compiler sees them in the macOS SDK headers.
//
// Go does not allow cgo in _test.go files, so the tests of package tun that
// check the utun address-request layouts against the SDK import this package
// instead. Nothing outside tests imports it, so the engine binary does not link
// cgo. Its values exist only when building for darwin with cgo enabled.
package darwinsdk
