import subprocess
import tempfile
import textwrap
import time
import os
import signal
from random import randint

import pytest

from tools import run, save


def run_conan_server(server_home, server_port):
    """
    Starts a conan_server in a non-blocking way and returns the process.
    """
    server_conf = textwrap.dedent(f"""
        [server]
        jwt_secret: XlDDYgiCfvxHOoGyKsLXfHRF
        jwt_expire_minutes: 120
        ssl_enabled: False
        port: {server_port}
        host_name: localhost
        authorize_timeout: 1800
        disk_storage_path: ./data
        disk_authorize_timeout: 1800
        updown_secret: LqeuqTEdPwFsBUELXukaOSes

        [write_permissions]
        */*@*/*: *

        [read_permissions]
        */*@*/*: *

        [users]
        demo: demo
        """)
    save(os.path.join(server_home, "server.conf"), server_conf)
    server_process = subprocess.Popen(
        ["conan_server"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    time.sleep(2)  # Give the server some time to start
    return server_process


def stop_conan_server(server_process):
    """
    Stops the given conan_server process.
    """
    if not server_process:
        return
    if server_process.poll() is None:  # Check if the process is still running
        os.kill(server_process.pid, signal.SIGTERM)
        server_process.wait()  # Wait for the process to terminate


@pytest.fixture(autouse=True)
def conan_test_with_conan_server():
    old_env = dict(os.environ)
    env_vars = {"CONAN_HOME": tempfile.mkdtemp(suffix='conans'),
                "CONAN_SERVER_HOME": tempfile.mkdtemp(suffix='conanserver')}
    os.environ.update(env_vars)
    current = tempfile.mkdtemp(suffix="conans")
    cwd = os.getcwd()
    os.chdir(current)
    run("pip install conan_server")
    server_port = randint(9300, 9500)
    server_process = run_conan_server(env_vars["CONAN_SERVER_HOME"], server_port)
    run(f"conan remote add conan_server http://localhost:{server_port}")
    run("conan remote login conan_server demo -p demo")
    run("conan remove * -c -r conan_server")
    try:
        yield
    finally:
        run("conan remove * -c -r conan_server")
        os.chdir(cwd)
        os.environ.clear()
        os.environ.update(old_env)
        stop_conan_server(server_process)


def test_example():
    """
    Test plugins/sign/sign_example.py from Conan documentation
    """
    # Install plugin
    repo = os.path.join(os.path.dirname(__file__), "..")
    run(f"conan config install {repo}")
    conan_home = os.environ["CONAN_HOME"]
    base_path = os.path.join(conan_home, "extensions", "plugins", "sign")
    old_path = os.path.join(base_path, "sign_example.py")
    new_path = os.path.join(base_path, "sign.py")
    os.rename(old_path, new_path)

    # Run the tests
    run("conan profile detect")
    run("conan new cmake_lib -d name=mypkg -d version=1.0 --force")
    run("conan create .")
    out = run("conan upload * -r=conan_server -c")

    assert "Signing ref:  mypkg/1.0" in out
    assert "Signing ref:  mypkg/1.0:4d8ab52ebb49f51e63d5193ed580b5a7672e23d5" in out
    # Make sure it is signing the sources too
    assert "Signing files:  ['conan_package.tgz', 'conaninfo.txt', 'conanmanifest.txt']" in out
    run("conan remove mypkg/* -c")
    out = run("conan install --requires=mypkg/1.0 -r=conan_server")
    assert "Verifying ref:  mypkg/1.0" in out
    assert "Verifying ref:  mypkg/1.0:4d8ab52ebb49f51e63d5193ed580b5a7672e23d5" in out
    assert "VERIFYING  conanfile.py" in out
    assert "VERIFYING  conan_sources.tgz" not in out  # Sources not retrieved now
    # Let's force the retrieval of the sources
    out = run("conan install --requires=mypkg/1.0 --build=*")
    assert "Verifying ref:  mypkg/1.0" in out
    assert "VERIFYING  conanfile.py" not in out  # It doesn't re-verify previous contents
    assert "VERIFYING  conan_sources.tgz" in out


def test_sigstore():
    """
    Test plugins/sign/sign_sigstore.py for Sigstore signing using Rekor

    Following env vars should be defined to run the test:
        - CONAN_SIGSTORE_PRIVKEY: <CONAN_HOME>/keys/ec_private.pem
        - CONAN_SIGSTORE_PUBKEY: <CONAN_HOME>/keys/ec_public.pem
        - CONAN_SIGSTORE_DISABLE_REKOR: Enable or disable rekor to test locally (disabled by default in the test for CI)
    """
    # Prepare environment vars
    base_path = os.path.join(os.getenv("CONAN_HOME"), "keys")
    os.makedirs(base_path)
    conan_sigstore_privkey = os.path.join(base_path, "ec_private.pem")
    conan_sigstore_pubkey = os.path.join(base_path, "ec_public.pem")
    run(f"openssl ecparam -genkey -name prime256v1 > {conan_sigstore_privkey}")
    run(f"openssl ec -in {conan_sigstore_privkey} -pubout > {conan_sigstore_pubkey}")
    env_vars = {"CONAN_SIGSTORE_PRIVKEY": conan_sigstore_privkey,
                "CONAN_SIGSTORE_PUBKEY": conan_sigstore_pubkey,
                "CONAN_SIGSTORE_DISABLE_REKOR": "1"}
    os.environ.update(env_vars)

    # Install plugin
    repo = os.path.join(os.path.dirname(__file__), "..")
    run(f"conan config install {repo}")
    conan_home = os.environ["CONAN_HOME"]
    base_path = os.path.join(conan_home, "extensions", "plugins", "sign")
    old_path = os.path.join(base_path, "sign_sigstore.py")
    new_path = os.path.join(base_path, "sign.py")
    os.rename(old_path, new_path)
    config_path = os.path.join(base_path, "config.yaml")
    save(config_path, textwrap.dedent("""
        sign:
          - remote: conan_server
            references: **/**@**/**
            private_key: keys/ec_private.pem
            public_key: keys/ec_public.pem
        
        verify:
          - remote: conan_server
            references: **/**@**/**
            public_key: keys/ec_public.pem
    """))

    # Run the tests
    run("conan profile detect")
    run("conan new cmake_lib -d name=mypkg2 -d version=1.0 --force")
    run("conan create .")
    out = run("conan upload mypkg2/1.0 -r=conan_server -c")
    assert "Signing artifacts" in out

    run("conan remove * -c")
    out = run("conan install --requires mypkg2/1.0 -r=conan_server")
    assert "Verifying artifacts from" in out


def test_sigstore_should_sign_and_get_sign_keys():
    from extensions.plugins.sign.sign_sigstore import _should_sign, _get_sign_keys

    config = {
        "sign": [
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ]
    }
    assert _should_sign("zlib/1.2.11", "conancenter", config)
    assert "keys/ec_private.pem", "keys/ec_public.pem" == _get_sign_keys("zlib/1.2.11", "conancenter", config)

    config = {
        "sign": [
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ]
    }
    assert not _should_sign("zlib/1.2.11", "conan_server", config)
    assert None, None is _get_sign_keys("zlib/1.2.11", "conan_server", config)

    assert _should_sign("zlib/1.2.11", "conancenter", {
        "sign": [
            {
                "remote": "conancenter",
                "references": "zlib/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ]
    })
    assert not _should_sign("zlib/1.2.11", "my_company_remote", {
        "sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@my_company/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ]
    })
    assert _should_sign("zlib/1.2.11@my_company", "my_company_remote", {
        "sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@my_company/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ]
    })
    assert not _should_sign("zlib/1.2.11@my_company", "my_company_remote", {
        "sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ],
        "exclude_sign": [
            {
                "remote": "my_company_remote",
                "references": "zlib/**@**/**"
            }
        ]
    })
    assert not _should_sign("zlib/1.2.11", "my_company_remote", {
        "sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ],
        "exclude_sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@None/None"
            }
        ]
    })
    assert _should_sign("zlib/1.2.11@my_company", "my_company_remote", {
        "sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ],
        "exclude_sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@None/None"
            }
        ]
    })


def test_sigstore_should_verify_and_get_verify_key():
    from extensions.plugins.sign.sign_sigstore import _should_verify, _get_verify_key

    config = {
        "verify": [
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "public_key": "keys/ec_public.pem"
            }
        ]
    }
    assert _should_verify("zlib/1.2.11", "conancenter", config)
    assert "keys/ec_public.pem" in _get_verify_key("zlib/1.2.11", "conancenter", config)

    config = {
        "verify": [
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "public_key": "keys/ec_public1.pem"
            },
            {
                "remote": "conancenter",
                "references": "zlib/**@**/**",
                "public_key": "keys/ec_public2.pem"
            }
        ]
    }
    assert _should_verify("zlib/1.2.11", "conancenter", config)
    assert "keys/ec_public1.pem" in _get_verify_key("zlib/1.2.11", "conancenter", config)

    config = {
        "verify": [
            {
                "remote": "conancenter",
                "references": "zlib/**@**/**",
                "public_key": "keys/ec_public2.pem"
            },
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "public_key": "keys/ec_public1.pem"
            }
        ]
    }
    assert _should_verify("zlib/1.2.11", "conancenter", config)
    assert "keys/ec_public2.pem" in _get_verify_key("zlib/1.2.11", "conancenter", config)

    config = {
        "verify": [
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "public_key": "keys/ec_public1.pem"
            },
            {
                "remote": "conancenter",
                "references": "zlib/**@**/**",
                "public_key": "keys/ec_public2.pem"
            }
        ],
        "exclude_verify": [
            {
                "remote": "conancenter",
                "references": "**/**@None/None",
            }
        ]
    }
    assert not _should_verify("zlib/1.2.11", "conancenter", config)
    assert _get_verify_key("zlib/1.2.11", "conancenter", config) is None
