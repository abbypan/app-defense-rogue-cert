package com.cert.aspin;

import org.junit.Test;

import java.lang.reflect.Modifier;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class ConnectionSecurityTest {
    @Test
    public void missingClaimFailsBeforeNetworkAccess() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> HttpsConn.createASPinConnection("invalid host", null));
        assertEquals("An OS-authenticated ASPin claim is required", error.getMessage());
    }

    @Test
    public void missingNativeValidatedPathIsRejected() {
        assertThrows(CertificateException.class, () -> HttpsConn.requireValidatedPath(null));
    }

    @Test
    public void connectionApiHasNoManualPinningOrTrustBypass() throws Exception {
        Set<String> publicMethods = Arrays.stream(HttpsConn.class.getDeclaredMethods())
                .filter(method -> Modifier.isPublic(method.getModifiers()))
                .map(method -> method.getName())
                .collect(Collectors.toSet());
        assertEquals(Set.of("create_conn", "createStandardTLSConnection",
                "createASPinConnection", "get_content", "getHttpContent"), publicMethods);
        assertTrue(Modifier.isPrivate(HttpsConn.class.getDeclaredConstructor().getModifiers()));
        assertEquals(ASPinVerifier.CertificateClaim.class,
                HttpsConn.class.getMethod("createASPinConnection", String.class,
                        ASPinVerifier.CertificateClaim.class).getParameterTypes()[1]);
    }
}
