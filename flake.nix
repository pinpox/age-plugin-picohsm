{
  description = "age plugin for Pico HSM hardware security modules";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages.default = pkgs.buildGoModule {
          pname = "age-plugin-picohsm";
          version = "0.1.0";
          src = ./.;
          vendorHash = "sha256-khGb9VtM0KXgOwBRNkV68/mgLlUem0B6qjhun8MRVq8=";
          subPackages = [ "cmd/age-plugin-picohsm" ];

          meta = with pkgs.lib; {
            description = "age plugin for Pico HSM hardware security modules";
            homepage = "https://github.com/pinpox/age-plugin-picohsm";
            license = licenses.mit;
          };
        };
      }
    );
}
