"""
Plugin to sign/verify Conan packages with Sigstore's (https://www.sigstore.dev/) transparency log using the Rekor CLI

Requirements: The following executables should be installed and in the PATH.
    - openssl: https://openssl-library.org/source/
    - rekor-cli: https://github.com/sigstore/rekor/releases

To use this sigstore plugin, first generate a compatible keypair and define the environment variables for the keys:

    $ openssl ecparam -genkey -name prime256v1 > ec_private.pem
    $ openssl ec -in ec_private.pem -pubout > ec_public.pem

Environment variables:
    - CONANSIGN_REKOR_PRIVKEY: Environment variable to ec_private.pem absolute path
    - CONANSIGN_REKOR_PUBKEY: Environment variable to ec_public.pem absolute path
    - CONAN_SIGSTORE_DISABLE_REKOR: Disable the rekor CLI calls, just sign/verify files with openssl.
    - CONAN_SIGSTORE_DISABLE_SIGN: Disable plugin's sign feature.
    - CONAN_SIGSTORE_DISABLE_VERIFY: Disable plugin's verify feature.
"""

import os
import subprocess
from shutil import which

from conan.api.output import cli_out_write
from conan.errors import ConanException


REKOR_CLI = "rekor-cli"
OPENSSL = "openssl"
CONAN_SIGSTORE_PUBKEY_VAR = "CONAN_SIGSTORE_PUBKEY"
CONAN_SIGSTORE_PRIVKEY_VAR = "CONAN_SIGSTORE_PRIVKEY"


def _is_rekor_disabled():
    return bool(os.getenv("CONAN_SIGSTORE_DISABLE_REKOR", False))


def _is_sign_disabled():
    return bool(os.getenv("CONAN_SIGSTORE_DISABLE_SIGN", False))


def _is_verify_disabled():
    return bool(os.getenv("CONAN_SIGSTORE_DISABLE_VERIFY", False))


def _check_requirements(check_verify_only=False):
    exes = [REKOR_CLI]
    env_vars = [CONAN_SIGSTORE_PUBKEY_VAR]
    if not check_verify_only:
        exes.append(OPENSSL)
        env_vars.append(CONAN_SIGSTORE_PRIVKEY_VAR)

    for exe in exes:
        if not which(exe):
            raise ConanException(f"Missing {exe} binary. {exe} is required to sign the artifacts. "
                                 f"Make sure it is installed in your system and available in the PATH")
    for env_var in env_vars:
        value = os.getenv(env_var)
        if not value:
            raise ConanException(f"Missing {env_var} environment variable")


def sign(_, artifacts_folder: str, signature_folder: str):
    if _is_sign_disabled():
        cli_out_write("Sign disabled")
        return

    _check_requirements()

    privkey_filepath = os.getenv(CONAN_SIGSTORE_PRIVKEY_VAR)
    pubkey_filepath = os.getenv(CONAN_SIGSTORE_PUBKEY_VAR)

    # Sign & upload each artifact using X509
    cli_out_write(f"Signing artifacts from {artifacts_folder} to {signature_folder}, "
                  f"using private key {privkey_filepath}")

    for fname in os.listdir(artifacts_folder):
        in_fpath = os.path.join(artifacts_folder, fname)
        out_fpath = os.path.join(signature_folder, fname + ".sig")
        if os.path.isfile(in_fpath):
            # Sign
            openssl_sign_cmd = [
                "openssl.exe",
                "dgst",
                "-sha256",
                "-sign", privkey_filepath,
                "-out", out_fpath,
                in_fpath,
            ]
            try:
                subprocess.check_call(openssl_sign_cmd, stdout=subprocess.DEVNULL, shell=True)
            except Exception as exc:
                raise ConanException(f"Error signing artifact {in_fpath}: {exc}")

            cli_out_write(f"Created signature for file {in_fpath} at {out_fpath}")

            # Upload to Rekor
            rekor_upload_cmd = [
                REKOR_CLI,
                "upload",
                "--pki-format", "x509",
                "--signature", out_fpath,
                "--public-key", pubkey_filepath,
                "--artifact", in_fpath
            ]
            if _is_rekor_disabled():
                cli_out_write(f"Rekor disabled. Skipping upload command: {' '.join(rekor_upload_cmd)}")
            else:
                try:
                    subprocess.check_call(rekor_upload_cmd, shell=True)
                except Exception as exc:
                    raise ConanException(f"Error uploading artifact sign {out_fpath}: {exc}")
                cli_out_write(f"Uploaded signature {out_fpath} to Sigstore")


def verify(ref, artifacts_folder, signature_folder, files):
    if _is_verify_disabled():
        cli_out_write("Verify disabled")
        return
    _check_requirements(check_verify_only=True)

    pubkey_filepath = os.getenv(CONAN_SIGSTORE_PUBKEY_VAR)

    # Verify each artifact using X509
    cli_out_write(f"Verifying artifacts from {artifacts_folder} with {signature_folder}, "
                  f"using public key {pubkey_filepath}")

    for fname in os.listdir(artifacts_folder):
        artifact_fpath = os.path.join(artifacts_folder, fname)
        sig_fpath = os.path.join(signature_folder, fname + ".sig")
        if os.path.isfile(artifact_fpath):
            if not os.path.isfile(sig_fpath):
                raise ConanException(f"Missing signature file for artifact {artifact_fpath}")

            # TODO: Verify signature locally with openssl:
            # TODO: $ openssl dgst -sha256 -verify <CONAN_SIGSTORE_PUBKEY (.pem)> -signature <SIGNATUREFILENAME (.sig)> <FILETOSIGN>

            # Verify against Rekor
            rekor_verify_cmd = [
                REKOR_CLI,
                "verify",
                "--pki-format", "x509",
                "--signature", sig_fpath,
                "--public-key", pubkey_filepath,
                "--artifact", artifact_fpath,
            ]
            if _is_rekor_disabled():
                cli_out_write(f"Rekor disabled. Skipping verify command: {' '.join(rekor_verify_cmd)}")
            else:
                try:
                    subprocess.check_call(rekor_verify_cmd, stdout=subprocess.DEVNULL)
                except Exception as exc:
                    raise ConanException(f"Error verifying signature for artifact {artifact_fpath}: {exc}")
                cli_out_write(f"Signature {sig_fpath} for {artifact_fpath} verified against Sigstore!")
