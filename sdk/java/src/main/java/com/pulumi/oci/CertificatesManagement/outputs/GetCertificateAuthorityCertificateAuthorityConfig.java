// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificateAuthorityCertificateAuthorityConfigSubject;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificateAuthorityCertificateAuthorityConfigValidity;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCertificateAuthorityCertificateAuthorityConfig {
    /**
     * @return The origin of the CA.
     * 
     */
    private final String configType;
    /**
     * @return The OCID of the parent CA that issued this CA. If this is the root CA, then this value is null.
     * 
     */
    private final String issuerCertificateAuthorityId;
    /**
     * @return The algorithm used to sign public key certificates that the CA issues.
     * 
     */
    private final String signingAlgorithm;
    /**
     * @return The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
     * 
     */
    private final List<GetCertificateAuthorityCertificateAuthorityConfigSubject> subjects;
    /**
     * @return An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
     * 
     */
    private final List<GetCertificateAuthorityCertificateAuthorityConfigValidity> validities;
    /**
     * @return The name of the CA version. When this value is not null, the name is unique across CA versions for a given CA.
     * 
     */
    private final String versionName;

    @CustomType.Constructor
    private GetCertificateAuthorityCertificateAuthorityConfig(
        @CustomType.Parameter("configType") String configType,
        @CustomType.Parameter("issuerCertificateAuthorityId") String issuerCertificateAuthorityId,
        @CustomType.Parameter("signingAlgorithm") String signingAlgorithm,
        @CustomType.Parameter("subjects") List<GetCertificateAuthorityCertificateAuthorityConfigSubject> subjects,
        @CustomType.Parameter("validities") List<GetCertificateAuthorityCertificateAuthorityConfigValidity> validities,
        @CustomType.Parameter("versionName") String versionName) {
        this.configType = configType;
        this.issuerCertificateAuthorityId = issuerCertificateAuthorityId;
        this.signingAlgorithm = signingAlgorithm;
        this.subjects = subjects;
        this.validities = validities;
        this.versionName = versionName;
    }

    /**
     * @return The origin of the CA.
     * 
     */
    public String configType() {
        return this.configType;
    }
    /**
     * @return The OCID of the parent CA that issued this CA. If this is the root CA, then this value is null.
     * 
     */
    public String issuerCertificateAuthorityId() {
        return this.issuerCertificateAuthorityId;
    }
    /**
     * @return The algorithm used to sign public key certificates that the CA issues.
     * 
     */
    public String signingAlgorithm() {
        return this.signingAlgorithm;
    }
    /**
     * @return The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
     * 
     */
    public List<GetCertificateAuthorityCertificateAuthorityConfigSubject> subjects() {
        return this.subjects;
    }
    /**
     * @return An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
     * 
     */
    public List<GetCertificateAuthorityCertificateAuthorityConfigValidity> validities() {
        return this.validities;
    }
    /**
     * @return The name of the CA version. When this value is not null, the name is unique across CA versions for a given CA.
     * 
     */
    public String versionName() {
        return this.versionName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCertificateAuthorityCertificateAuthorityConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String configType;
        private String issuerCertificateAuthorityId;
        private String signingAlgorithm;
        private List<GetCertificateAuthorityCertificateAuthorityConfigSubject> subjects;
        private List<GetCertificateAuthorityCertificateAuthorityConfigValidity> validities;
        private String versionName;

        public Builder() {
    	      // Empty
        }

        public Builder(GetCertificateAuthorityCertificateAuthorityConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configType = defaults.configType;
    	      this.issuerCertificateAuthorityId = defaults.issuerCertificateAuthorityId;
    	      this.signingAlgorithm = defaults.signingAlgorithm;
    	      this.subjects = defaults.subjects;
    	      this.validities = defaults.validities;
    	      this.versionName = defaults.versionName;
        }

        public Builder configType(String configType) {
            this.configType = Objects.requireNonNull(configType);
            return this;
        }
        public Builder issuerCertificateAuthorityId(String issuerCertificateAuthorityId) {
            this.issuerCertificateAuthorityId = Objects.requireNonNull(issuerCertificateAuthorityId);
            return this;
        }
        public Builder signingAlgorithm(String signingAlgorithm) {
            this.signingAlgorithm = Objects.requireNonNull(signingAlgorithm);
            return this;
        }
        public Builder subjects(List<GetCertificateAuthorityCertificateAuthorityConfigSubject> subjects) {
            this.subjects = Objects.requireNonNull(subjects);
            return this;
        }
        public Builder subjects(GetCertificateAuthorityCertificateAuthorityConfigSubject... subjects) {
            return subjects(List.of(subjects));
        }
        public Builder validities(List<GetCertificateAuthorityCertificateAuthorityConfigValidity> validities) {
            this.validities = Objects.requireNonNull(validities);
            return this;
        }
        public Builder validities(GetCertificateAuthorityCertificateAuthorityConfigValidity... validities) {
            return validities(List.of(validities));
        }
        public Builder versionName(String versionName) {
            this.versionName = Objects.requireNonNull(versionName);
            return this;
        }        public GetCertificateAuthorityCertificateAuthorityConfig build() {
            return new GetCertificateAuthorityCertificateAuthorityConfig(configType, issuerCertificateAuthorityId, signingAlgorithm, subjects, validities, versionName);
        }
    }
}
