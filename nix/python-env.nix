{ pkgs }:

let
  pythonWithCustom = pkgs.python3.override {
    packageOverrides = pyfinal: pyprev: {

      nearcore-pytest = pyfinal.buildPythonPackage {
        pname = "nearcore-pytest";
        version = "0.1.0";

        # Use the project root so that ../../libs/ exists in the sandbox
        src = ../.;

        pyproject = true;
        nativeBuildInputs = [ pyfinal.setuptools ];

        postPatch = ''
          cd pytest/nearcore_pytest
        '';

        preBuild = ''
          mkdir -p ../../libs/nearcore/pytest/lib
        '';

        doCheck = false;
      };

      # NB! downgrade to python 3.12 if blspy is needed
      #
      # blspy = pyfinal.buildPythonPackage rec {
      #   pname = "blspy";
      #   version = "2.0.2";
      #   pyproject = true;

      #   src = pyfinal.fetchPypi {
      #     inherit pname version;
      #     hash = "sha256-mxLWhfPBBNP+D682GPa4JCctExuOo4QxkK1nBhhzZ3U=";
      #   };

      #   relic-src = pkgs.fetchFromGitHub {
      #     owner = "Chia-Network";
      #     repo = "relic";
      #     rev = "215c69966cb78b255995f0ee9c86bbbb41c3c42b";
      #     hash = "sha256-8Q5S6n2ciDB59H1C735bdk/u9Y+FdwlhZvb0lv2NOCI=";
      #   };

      #   blst-src = pkgs.fetchFromGitHub {
      #     owner = "supranational";
      #     repo = "blst";
      #     rev = "6b837a0921cf41e501faaee1976a4035ae29d893";
      #     hash = "sha256-6iNpxaMRy438XoC0wk/c/tInNg1I0VuyGFV9sUFk5sc=";
      #   };

      #   nativeBuildInputs = [
      #     pkgs.cmake
      #     pkgs.pkg-config
      #     pyfinal.setuptools
      #     pyfinal.setuptools-scm
      #     pyfinal.pybind11
      #   ];

      #   buildInputs = [
      #     pkgs.libsodium
      #     pkgs.gmp
      #     pyfinal.pybind11
      #   ];

      #   dontUseCmakeConfigure = true;

      #   postPatch = ''
      #     # 1. Strip all FetchContent to prevent network attempts
      #     find . -name "CMakeLists.txt" -exec sed -i '/FetchContent_Declare/,/FetchContent_MakeAvailable/d' {} +

      #     # 2. Setup Relic (writable copy)
      #     cp -r ${relic-src} ./relic-src
      #     chmod -R +w ./relic-src
      #     sed -i 's/cmake_minimum_required(VERSION [0-9.]*)/cmake_minimum_required(VERSION 3.5)/g' ./relic-src/CMakeLists.txt

      #     # 3. Inject dependency paths into main CMakeLists
      #     sed -i "1i set(relic_SOURCE_DIR \''${CMAKE_CURRENT_SOURCE_DIR}/relic-src)" CMakeLists.txt
      #     sed -i "2i set(blst_SOURCE_DIR ${blst-src})" CMakeLists.txt
      #     sed -i "3i set(sodium_FOUND TRUE)" CMakeLists.txt
      #     sed -i "4i set(Sodium_FOUND TRUE)" CMakeLists.txt

      #     # 4. Patch binding subdirectory
      #     if [ -f python-bindings/CMakeLists.txt ]; then
      #        sed -i '1i find_package(pybind11 REQUIRED)' python-bindings/CMakeLists.txt
      #     fi

      #     # 5. Hardware & Cryptography configuration (Force flags)
      #     cat >> CMakeLists.txt <<EOF
      #     set(ARCH "x64" CACHE STRING "" FORCE)
      #     set(FP_PRIME 381 CACHE STRING "" FORCE)
      #     set(FP_QNRES ON CACHE BOOL "" FORCE)
      #     set(WITH "BN;FP;EP;PP;PC;MAP;MD" CACHE STRING "" FORCE)
      #     set(EP_MAP ON CACHE BOOL "" FORCE)
      #     set(EP_MD "SHA3" CACHE STRING "" FORCE)
      #     set(BLST_PORTABLE ON CACHE BOOL "" FORCE)
      #     EOF

      #     # 6. Global Fixes: GCC 14/15 alignment & stripping strict errors
      #     find . -type f \( -name "*.h" -o -name "*.c" -o -name "*.cpp" \) -exec sed -i 's/__attribute__((aligned([0-9]*)))//g' {} +
      #     sed -i 's/-Werror//g' CMakeLists.txt || true
      #   '';

      #   NIX_CFLAGS_COMPILE = [
      #     "-Wno-error"
      #     "-fpermissive"
      #     "-fPIC"
      #     "-I${pkgs.libsodium}/include"
      #     "-I${pkgs.gmp.dev}/include"
      #   ];

      #   doCheck = false;
      # };

      borsh-construct = pyfinal.buildPythonPackage rec {
        pname = "borsh-construct";
        version = "0.1.0";
        pyproject = true;
        build-system = [ pyfinal.poetry-core ];
        src = pyfinal.fetchPypi {
          inherit pname version;
          hash = "sha256-yRZ1jOunAIXY9FahzCaZG4jLZCM9NHdndmRztlGzcmM=";
        };
        postPatch = ''
          sed -i 's/construct-typing = .*/construct-typing = "*"/' pyproject.toml
          sed -i 's/sumtypes = .*/sumtypes = "*"/' pyproject.toml
        '';
        propagatedBuildInputs = [
          pyfinal.construct
          pyfinal.construct-typing
          pyfinal.sumtypes
        ];
        doCheck = false;
      };

      py-arkworks-bls12381 = pyfinal.buildPythonPackage rec {
        pname = "py-arkworks-bls12381";
        version = "0.3.8";
        pyproject = true;
        src = pkgs.fetchFromGitHub {
          owner = "crate-crypto";
          repo = "py-arkworks-bls12381";
          rev = "v${version}";
          hash = "sha256-lhJq9jbbxaxIm9WlaPyWpD7Jq2VZe+jQcB0EXYYG/yw=";
        };
        cargoDeps = pkgs.rustPlatform.importCargoLock {
          lockFile = ./py-arkworks-bls12381-lockfile.lock;
        };
        postPatch = ''
          cp ${./py-arkworks-bls12381-lockfile.lock} Cargo.lock
        '';
        nativeBuildInputs = [
          pkgs.rustPlatform.cargoSetupHook
          pkgs.rustPlatform.maturinBuildHook
        ];
        doCheck = false;
      };

      nearup = pyfinal.buildPythonPackage rec {
        pname = "nearup";
        version = "1.2.0";
        pyproject = true;
        build-system = [ pyfinal.setuptools ];
        src = pyfinal.fetchPypi {
          inherit pname version;
          hash = "sha256-JB6snBmIOqKg5KOqpUwGdDOEeFKarnOZ/A4JOVBMpY8=";
        };
        doCheck = false;
        propagatedBuildInputs = with pyfinal; [
          requests
          psutil
          boto3
          click
        ];
      };
    };
  };
in
pythonWithCustom.withPackages (
  ps: with ps; [
    # pytest deps
    pytest
    pytest-rerunfailures
    gitpython
    ruamel-yaml
    pygithub
    base58
    cachetools
    cython
    deepdiff
    json-rpc
    locust
    geventhttpclient
    google-cloud-compute
    numpy
    prometheus-client
    psutil
    pydantic
    pynacl
    requests
    retrying
    scikit-learn
    scipy
    semver
    toml
    tqdm
    urllib3
    jmespath
    borsh-construct
    nearup
    # blspy
    py-arkworks-bls12381
    nearcore-pytest
  ]
)
