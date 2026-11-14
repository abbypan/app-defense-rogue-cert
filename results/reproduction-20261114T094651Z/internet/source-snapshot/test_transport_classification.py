"""Compile the actual Java classifier; no device, network, or app state is used."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent


class TransportClassificationTest(unittest.TestCase):
    def test_concrete_transport_failures_are_separate_from_policy_and_native_errors(self):
        source = (ROOT / 'ASPin/shared/src/main/java/com/cert/aspin/SchemeComparisonBenchmark.java').read_text()
        method = source[source.index('    private static boolean isTransportFailure'):
                        source.index('    private static void requireExpected')]
        checks = r'''
    public static void main(String[] args) {
        if (!isTransportFailure(new java.net.SocketTimeoutException("timeout"), "network_error")) throw new AssertionError();
        if (!isTransportFailure(new IllegalStateException("ASPin validation failed: failed to connect to host/1.2.3.4 (port 443) after 10000ms"), "policy_error")) throw new AssertionError();
        if (!isTransportFailure(new IllegalStateException("ASPin validation failed: Read timed out"), "policy_error")) throw new AssertionError();
        if (isTransportFailure(new IllegalStateException("ASPin validation failed: signature mismatch"), "policy_error")) throw new AssertionError();
        if (isTransportFailure(new IllegalStateException("ASPin validation failed: anti-rollback"), "policy_error")) throw new AssertionError();
        if (isTransportFailure(new javax.net.ssl.SSLHandshakeException("native certificate failure"), "network_error")) throw new AssertionError();
    }
'''
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / 'TransportCheck.java'
            path.write_text('public class TransportCheck {\n' + method + checks + '\n}\n')
            subprocess.run([shutil.which('javac'), '-d', directory, path], check=True,
                           capture_output=True, text=True, timeout=30)
            subprocess.run([shutil.which('java'), '-cp', directory, 'TransportCheck'], check=True,
                           capture_output=True, text=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
