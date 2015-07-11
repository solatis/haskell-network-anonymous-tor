{ nixpkgs ? import <nixpkgs> {}, compiler ? "ghc7101" }:
nixpkgs.haskellPackages.callPackage ./network-anonymous-tor.nix { }
