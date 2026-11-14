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

import android.annotation.FlaggedApi;
import android.annotation.NonNull;
import android.os.Parcel;
import android.os.Parcelable;
import android.security.Flags;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * An app-signing-key-authenticated certificate claim returned by the ASPin system service.
 */
@FlaggedApi(Flags.FLAG_ASPIN_API)
public final class AspinCertificateClaim implements Parcelable {
    @NonNull private final String mHostname;
    @NonNull private final String mSubject;
    @NonNull private final List<String> mSubjectAlternativeNames;
    @NonNull private final List<String> mIssuers;
    private final long mIssuedAtMillis;
    private final long mExpiresAtMillis;
    private final long mClaimKeyDownloadAndVerificationNanos;
    private final long mClaimDownloadAndVerificationNanos;

    /** @hide */
    public AspinCertificateClaim(@NonNull String hostname, @NonNull String subject,
            @NonNull List<String> subjectAlternativeNames, @NonNull List<String> issuers,
            long issuedAtMillis, long expiresAtMillis,
            long claimKeyDownloadAndVerificationNanos,
            long claimDownloadAndVerificationNanos) {
        mHostname = Objects.requireNonNull(hostname);
        mSubject = Objects.requireNonNull(subject);
        mSubjectAlternativeNames = Collections.unmodifiableList(
                new ArrayList<>(Objects.requireNonNull(subjectAlternativeNames)));
        mIssuers = Collections.unmodifiableList(new ArrayList<>(Objects.requireNonNull(issuers)));
        mIssuedAtMillis = issuedAtMillis;
        mExpiresAtMillis = expiresAtMillis;
        mClaimKeyDownloadAndVerificationNanos = claimKeyDownloadAndVerificationNanos;
        mClaimDownloadAndVerificationNanos = claimDownloadAndVerificationNanos;
    }

    private AspinCertificateClaim(Parcel in) {
        mHostname = Objects.requireNonNull(in.readString());
        mSubject = Objects.requireNonNull(in.readString());
        mSubjectAlternativeNames = Collections.unmodifiableList(
                Objects.requireNonNull(in.createStringArrayList()));
        mIssuers = Collections.unmodifiableList(
                Objects.requireNonNull(in.createStringArrayList()));
        mIssuedAtMillis = in.readLong();
        mExpiresAtMillis = in.readLong();
        mClaimKeyDownloadAndVerificationNanos = in.readLong();
        mClaimDownloadAndVerificationNanos = in.readLong();
    }

    /** Returns the requested canonical hostname covered by the signed SAN entries. */
    @NonNull
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public String getHostname() {
        return mHostname;
    }

    /** Returns the authenticated X.509 Subject distinguished name. */
    @NonNull
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public String getSubject() {
        return mSubject;
    }

    /** Returns the authenticated DNS Subject Alternative Names. */
    @NonNull
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public List<String> getSubjectAlternativeNames() {
        return mSubjectAlternativeNames;
    }

    /**
     * Returns the authenticated acceptable issuer identifiers. Each identifier is the
     * lower-case hash name, a colon, and the unpadded base64url digest of the complete
     * DER-encoded direct issuer CA certificate.
     */
    @NonNull
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public List<String> getIssuers() {
        return mIssuers;
    }

    /** Returns the signed certificate-claim issuance time in Unix-epoch milliseconds. */
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public long getIssuedAtMillis() {
        return mIssuedAtMillis;
    }

    /**
     * Returns the effective expiration time in Unix-epoch milliseconds. This is no later than
     * either the signed claim expiration or the expiration of its authenticated delegation.
     */
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public long getExpiresAtMillis() {
        return mExpiresAtMillis;
    }

    /** Returns the latest claim-key-token download and verification duration, or zero for cache. */
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public long getClaimKeyDownloadAndVerificationNanos() {
        return mClaimKeyDownloadAndVerificationNanos;
    }

    /** Returns the latest claim-token download and verification duration, or zero for cache. */
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public long getClaimDownloadAndVerificationNanos() {
        return mClaimDownloadAndVerificationNanos;
    }

    @Override
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public int describeContents() {
        return 0;
    }

    @Override
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        dest.writeString(mHostname);
        dest.writeString(mSubject);
        dest.writeStringList(mSubjectAlternativeNames);
        dest.writeStringList(mIssuers);
        dest.writeLong(mIssuedAtMillis);
        dest.writeLong(mExpiresAtMillis);
        dest.writeLong(mClaimKeyDownloadAndVerificationNanos);
        dest.writeLong(mClaimDownloadAndVerificationNanos);
    }

    @NonNull
    @FlaggedApi(Flags.FLAG_ASPIN_API)
    public static final Creator<AspinCertificateClaim> CREATOR =
            new Creator<AspinCertificateClaim>() {
                @Override
                public AspinCertificateClaim createFromParcel(Parcel in) {
                    return new AspinCertificateClaim(in);
                }

                @Override
                public AspinCertificateClaim[] newArray(int size) {
                    return new AspinCertificateClaim[size];
                }
            };
}
