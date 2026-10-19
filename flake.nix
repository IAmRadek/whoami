{
  description = "whoami: choose which SSH key the agent offers, per request";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      # src/macos.rs links AppKit through the Objective-C runtime, so Darwin only
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "whoami";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          # raylib-sys builds raylib with cmake and generates bindings with bindgen
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.rustPlatform.bindgenHook
          ];
          # cmake is for raylib-sys's build script, not for this crate
          dontUseCmakeConfigure = true;

          meta.mainProgram = "whoami-agent";
        };
      });

      darwinModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.services.whoami;
        in
        {
          options.services.whoami = {
            enable = lib.mkEnableOption "whoami, the per-request SSH key selector";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
            };
            upstream = lib.mkOption {
              type = lib.types.str;
              example = "/Users/me/.ssh/proton-pass-agent.sock";
              description = "Socket of the agent that holds the keys.";
            };
            socket = lib.mkOption {
              type = lib.types.str;
              example = "/Users/me/.ssh/whoami.sock";
              description = "Socket whoami listens on; SSH_AUTH_SOCK points here.";
            };
            log = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "/Users/me/Library/Logs/whoami.log";
              description = "File that receives whoami's diagnostics on stderr.";
            };
          };

          config = lib.mkIf cfg.enable {
            launchd.user.agents.whoami.serviceConfig = {
              ProgramArguments = [ (lib.getExe cfg.package) ];
              EnvironmentVariables = {
                WHOAMI_UPSTREAM = cfg.upstream;
                WHOAMI_SOCKET = cfg.socket;
              };
              RunAtLoad = true;
              KeepAlive = true;
            }
            // lib.optionalAttrs (cfg.log != null) { StandardErrorPath = cfg.log; };
            environment.variables.SSH_AUTH_SOCK = cfg.socket;
          };
        };
    };
}
