{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  # nativeBuildInputs is for tools you need to run
  nativeBuildInputs = [
    pkgs.pkg-config
  ];

  # buildInputs is for libraries you need to link against
  buildInputs = [
    pkgs.openssl
  ];
}
