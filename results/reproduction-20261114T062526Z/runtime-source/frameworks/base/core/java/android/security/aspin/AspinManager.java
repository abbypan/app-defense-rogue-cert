/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.security.aspin;

import android.Manifest;
import android.annotation.FlaggedApi;
import android.annotation.NonNull;
import android.annotation.RequiresPermission;
import android.annotation.SystemService;
import android.content.Context;
import android.os.RemoteException;
import android.security.Flags;

import java.util.Objects;

/**
 * Provides certificate claims authenticated from an OS-verified app signing identity and
 * checked against a requested hostname using the claim's signed SAN entries. The self-query API
 * derives the calling app from its Binder UID. The cross-app API accepts a target package name;
 * in both cases the service resolves the signing key from trusted package-manager state.
 */
@SystemService(Context.ASPIN_SERVICE)
@FlaggedApi(Flags.FLAG_ASPIN_API)
public final class AspinManager {
    @NonNull private final IAspinService mService;

    /** @hide */
    public AspinManager(@NonNull IAspinService service) {
        mService = Objects.requireNonNull(service);
    }

    /**
     * Returns the calling app's authenticated claim for {@code hostname}. The OS derives the
     * calling package from the Binder caller UID and uses its verified signing key.
    */
    @NonNull
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    @RequiresPermission(Manifest.permission.INTERNET)
    public AspinCertificateClaim getCertificateClaim(@NonNull String hostname) {
        return getOwnCertificateClaimInternal(hostname, false);
    }

    /**
     * Returns an authenticated claim for {@code targetPackageName}'s {@code hostname}. The OS
     * resolves the installed target app's verified signing key independently of the caller.
     */
    @NonNull
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    @RequiresPermission(Manifest.permission.INTERNET)
    public AspinCertificateClaim getCertificateClaimForApp(
            @NonNull String targetPackageName, @NonNull String hostname) {
        return getCertificateClaimForAppInternal(targetPackageName, hostname, false);
    }

    /**
     * Forces retrieval and verification of both ASPin tokens before returning the claim.
     *
     * <p>This evaluation hook is available only to debuggable apps on debuggable builds.
     *
     * @throws SecurityException if forced refresh is unavailable to the caller
     */
    @NonNull
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    @RequiresPermission(Manifest.permission.INTERNET)
    public AspinCertificateClaim refreshCertificateClaim(@NonNull String hostname) {
        return getOwnCertificateClaimInternal(hostname, true);
    }

    /**
     * Forces retrieval and verification for a named target app.
     *
     * <p>This evaluation hook is available only to debuggable apps on debuggable builds.
     *
     * @throws SecurityException if forced refresh is unavailable to the caller
     */
    @NonNull
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    @RequiresPermission(Manifest.permission.INTERNET)
    public AspinCertificateClaim refreshCertificateClaimForApp(
            @NonNull String targetPackageName, @NonNull String hostname) {
        return getCertificateClaimForAppInternal(targetPackageName, hostname, true);
    }

    @NonNull
    private AspinCertificateClaim getOwnCertificateClaimInternal(
            @NonNull String hostname, boolean forceRefresh) {
        Objects.requireNonNull(hostname);
        try {
            return mService.getOwnCertificateClaim(hostname, forceRefresh);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    @NonNull
    private AspinCertificateClaim getCertificateClaimForAppInternal(
            @NonNull String targetPackageName, @NonNull String hostname, boolean forceRefresh) {
        Objects.requireNonNull(targetPackageName);
        Objects.requireNonNull(hostname);
        try {
            return mService.getCertificateClaimForApp(
                    targetPackageName, hostname, forceRefresh);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }
}
