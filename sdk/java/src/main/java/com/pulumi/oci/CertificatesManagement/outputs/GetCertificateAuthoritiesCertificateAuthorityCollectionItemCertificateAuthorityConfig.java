// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigSubject;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigValidity;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfig {
    /**
     * @return The origin of the CA.
     * 
     */
    private String configType;
    /**
     * @return The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     * 
     */
    private String issuerCertificateAuthorityId;
    /**
     * @return The algorithm used to sign public key certificates that the CA issues.
     * 
     */
    private String signingAlgorithm;
    /**
     * @return The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
     * 
     */
    private List<GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigSubject> subjects;
    /**
     * @return An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
     * 
     */
    private List<GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigValidity> validities;
    /**
     * @return The name of the CA version. When this value is not null, the name is unique across CA versions for a given CA.
     * 
     */
    private String versionName;

    private GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfig() {}
    /**
     * @return The origin of the CA.
     * 
     */
    public String configType() {
        return this.configType;
    }
    /**
     * @return The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
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
    public List<GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigSubject> subjects() {
        return this.subjects;
    }
    /**
     * @return An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
     * 
     */
    public List<GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigValidity> validities() {
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

    public static Builder builder(GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String configType;
        private String issuerCertificateAuthorityId;
        private String signingAlgorithm;
        private List<GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigSubject> subjects;
        private List<GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigValidity> validities;
        private String versionName;
        public Builder() {}
        public Builder(GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configType = defaults.configType;
    	      this.issuerCertificateAuthorityId = defaults.issuerCertificateAuthorityId;
    	      this.signingAlgorithm = defaults.signingAlgorithm;
    	      this.subjects = defaults.subjects;
    	      this.validities = defaults.validities;
    	      this.versionName = defaults.versionName;
        }

        @CustomType.Setter
        public Builder configType(String configType) {
            this.configType = Objects.requireNonNull(configType);
            return this;
        }
        @CustomType.Setter
        public Builder issuerCertificateAuthorityId(String issuerCertificateAuthorityId) {
            this.issuerCertificateAuthorityId = Objects.requireNonNull(issuerCertificateAuthorityId);
            return this;
        }
        @CustomType.Setter
        public Builder signingAlgorithm(String signingAlgorithm) {
            this.signingAlgorithm = Objects.requireNonNull(signingAlgorithm);
            return this;
        }
        @CustomType.Setter
        public Builder subjects(List<GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigSubject> subjects) {
            this.subjects = Objects.requireNonNull(subjects);
            return this;
        }
        public Builder subjects(GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigSubject... subjects) {
            return subjects(List.of(subjects));
        }
        @CustomType.Setter
        public Builder validities(List<GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigValidity> validities) {
            this.validities = Objects.requireNonNull(validities);
            return this;
        }
        public Builder validities(GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfigValidity... validities) {
            return validities(List.of(validities));
        }
        @CustomType.Setter
        public Builder versionName(String versionName) {
            this.versionName = Objects.requireNonNull(versionName);
            return this;
        }
        public GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfig build() {
            final var o = new GetCertificateAuthoritiesCertificateAuthorityCollectionItemCertificateAuthorityConfig();
            o.configType = configType;
            o.issuerCertificateAuthorityId = issuerCertificateAuthorityId;
            o.signingAlgorithm = signingAlgorithm;
            o.subjects = subjects;
            o.validities = validities;
            o.versionName = versionName;
            return o;
        }
    }
}