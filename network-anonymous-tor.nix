{ mkDerivation, attoparsec, base, base32string, bytestring
, exceptions, hexstring, hspec, hspec-attoparsec
, hspec-expectations, network, network-attoparsec, network-simple
, socks, splice, stdenv, text, transformers
}:
mkDerivation {
  pname = "network-anonymous-tor";
  version = "0.9.2";
  src = ./.;
  isLibrary = true;
  isExecutable = true;
  buildDepends = [
    attoparsec base base32string bytestring exceptions hexstring
    network network-attoparsec network-simple socks splice text
    transformers
  ];
  testDepends = [
    attoparsec base base32string bytestring exceptions hspec
    hspec-attoparsec hspec-expectations network network-simple socks
    text transformers
  ];
  homepage = "http://www.leonmergen.com/opensource.html";
  description = "Haskell API for Tor anonymous networking";
  license = stdenv.lib.licenses.mit;
}
