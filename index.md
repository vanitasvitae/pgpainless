PGPainless is a wrapper around [Bouncycastle](https://www.bouncycastle.org/), which provides an easy to use, intuitive,
but also powerful API for OpenPGP ([RFC4880](https://datatracker.ietf.org/doc/html/rfc4880)).

Its primary functionality is encrypting, signing, decrypting and verifying data, as well as generating and modifying keys.

## Why should I use it?

There are a bunch of reasons why you should consider switching to PGPainless:

### Easy to use API

One main focus of the project is ease of use.
Using Bouncycastle can be a hassle, since simple tasks require a substantial amount of boilerplate code and small
mistakes are easily made.
PGPainless aims at providing a simple interface to get the job done quickly, while not trading away functionality or
correctness.

For examples about how to use the API, see the projects 
[readme](https://github.com/pgpainless/pgpainless/blob/master/README.md).

### Complementing Bouncycastle

**PGPainless has Bouncycastle truly figured out!**

If you already use BC in your code, PGPainless is a perfect complement!
It allows you to remove many lines of boilerplate code and offers you the certitude of a dedicated JUnit test suite.

Furthermore PGPainless is scoring *second place* on the very extensive [Sequoia OpenPGP Interoperability Test Suite](https://tests.sequoia-pgp.org).

We have studied BC intensively, identified its shortcomings and came up with solutions to those:

Contrary to vanilla BC and some other BC-based OpenPGP libraries, PGPainless does signature verification **the right way**.
It not only checks for signature *correctness*, but goes the extra mile to also check signature *validity* by taking into consideration key expiration dates, revocations, signature structures, etc.

Take a look at [this blog post](https://blog.jabberhead.tk/2021/04/03/why-signature-verification-in-openpgp-is-hard/) to get an idea of how complex signature verification with OpenPGP truly is.

### Android Support
PGPainless is designed to work on Android versions down to [API level 10](https://developer.android.com/about/versions/android-2.3.3) (Gingerbread).
This makes PGPainless a good choice for implementing OpenPGP encryption in your Android app.

Compatibility with certain Android APIs is ensured through [Animalsniffer](http://www.mojohaus.org/animal-sniffer/).

## Releases
PGPainless is released on the maven central repository. Including it in your project is simple:

Maven:
```xml
<dependency>
    <groupId>org.pgpainless</groupId>
    <artifactId>pgpainless-core</artifactId>
    <version>0.2.0</version>
</dependency>
```

Gradle:
```gradle
repositories {
	mavenCentral()
}

dependencies {
	compile 'org.pgpainless:pgpainless-core:0.2.0'
}
```

There are [snapshot releases](https://oss.sonatype.org/content/repositories/snapshots/org/pgpainless/pgpainless-core/) available as well.

## Command Line Interface

PGPainless provides an implementation of the [Stateless OpenPGP Command Line Interface](https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-stateless-cli-01) 
in the `pgpainless-sop` module.
This allows PGPainless to be used as a command line application for encryption/decryption and signature creation/validation.

More importantly though, this allows to plug PGPainless into the [Sequoia OpenPGP Interoperability Test Suite](https://tests.sequoia-pgp.org/).
This extensive test suite demonstrates how closely PGPainless is following the standard, especially when it comes to signature verification.

## Forever Free Software

PGPainless is licensed under the Apache License 2.0 and this will never change.

**Free Libre Open Source Software Rocks!**

## About
PGPainless was created [during a Google Summer of Code project](https://blog.jabberhead.tk/summer-of-code-2018/),
for which an easy to use OpenPGP API for Java and Android was needed.

Originally we looked into forking [bouncy-gpg](https://github.com/neuhalje/bouncy-gpg),
but since support for lower Android versions was a requirement, PGPainless was born as an independent project.
In its early development stages the library was however influenced by bouncy-gpg written by Jens Neuhalje.

## Development
PGPainless is currently developed by [Paul Schaub (@vanitasvitae)](https://blog.jabberhead.tk).

### Contribute
Contributions are always welcome :) The project is developed in the following places:
* [Github](https://github.com/pgpainless/pgpainless)
* [Codeberg](https://codeberg.org/pgpainless/pgpainless)

Pull requests are accepted on either of them.

### Bug Reports
If you encounter a bug, please make sure to check, whether the bug has already been reported
either [here](https://github.com/pgpainless/pgpainless/issues),
or [here](https://codeberg.org/PGPainless/pgpainless/issues), in order to avoid duplicate bug reports.
