// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificatesCertificateCollectionItemCertificateConfigSubject;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificatesCertificateCollectionItemCertificateConfigSubjectAlternativeName;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificatesCertificateCollectionItemCertificateConfigValidity;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCertificatesCertificateCollectionItemCertificateConfig {
    /**
     * @return The name of the profile used to create the certificate, which depends on the type of certificate you need.
     * 
     */
    private String certificateProfileType;
    /**
     * @return The origin of the certificate.
     * 
     */
    private String configType;
    private String csrPem;
    /**
     * @return The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     * 
     */
    private String issuerCertificateAuthorityId;
    /**
     * @return The algorithm used to create key pairs.
     * 
     */
    private String keyAlgorithm;
    /**
     * @return The algorithm used to sign the public key certificate.
     * 
     */
    private String signatureAlgorithm;
    /**
     * @return A list of subject alternative names.
     * 
     */
    private List<GetCertificatesCertificateCollectionItemCertificateConfigSubjectAlternativeName> subjectAlternativeNames;
    /**
     * @return The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
     * 
     */
    private List<GetCertificatesCertificateCollectionItemCertificateConfigSubject> subjects;
    /**
     * @return An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
     * 
     */
    private List<GetCertificatesCertificateCollectionItemCertificateConfigValidity> validities;
    /**
     * @return The name of the certificate version. When the value is not null, a name is unique across versions of a given certificate.
     * 
     */
    private String versionName;

    private GetCertificatesCertificateCollectionItemCertificateConfig() {}
    /**
     * @return The name of the profile used to create the certificate, which depends on the type of certificate you need.
     * 
     */
    public String certificateProfileType() {
        return this.certificateProfileType;
    }
    /**
     * @return The origin of the certificate.
     * 
     */
    public String configType() {
        return this.configType;
    }
    public String csrPem() {
        return this.csrPem;
    }
    /**
     * @return The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     * 
     */
    public String issuerCertificateAuthorityId() {
        return this.issuerCertificateAuthorityId;
    }
    /**
     * @return The algorithm used to create key pairs.
     * 
     */
    public String keyAlgorithm() {
        return this.keyAlgorithm;
    }
    /**
     * @return The algorithm used to sign the public key certificate.
     * 
     */
    public String signatureAlgorithm() {
        return this.signatureAlgorithm;
    }
    /**
     * @return A list of subject alternative names.
     * 
     */
    public List<GetCertificatesCertificateCollectionItemCertificateConfigSubjectAlternativeName> subjectAlternativeNames() {
        return this.subjectAlternativeNames;
    }
    /**
     * @return The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
     * 
     */
    public List<GetCertificatesCertificateCollectionItemCertificateConfigSubject> subjects() {
        return this.subjects;
    }
    /**
     * @return An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
     * 
     */
    public List<GetCertificatesCertificateCollectionItemCertificateConfigValidity> validities() {
        return this.validities;
    }
    /**
     * @return The name of the certificate version. When the value is not null, a name is unique across versions of a given certificate.
     * 
     */
    public String versionName() {
        return this.versionName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCertificatesCertificateCollectionItemCertificateConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String certificateProfileType;
        private String configType;
        private String csrPem;
        private String issuerCertificateAuthorityId;
        private String keyAlgorithm;
        private String signatureAlgorithm;
        private List<GetCertificatesCertificateCollectionItemCertificateConfigSubjectAlternativeName> subjectAlternativeNames;
        private List<GetCertificatesCertificateCollectionItemCertificateConfigSubject> subjects;
        private List<GetCertificatesCertificateCollectionItemCertificateConfigValidity> validities;
        private String versionName;
        public Builder() {}
        public Builder(GetCertificatesCertificateCollectionItemCertificateConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certificateProfileType = defaults.certificateProfileType;
    	      this.configType = defaults.configType;
    	      this.csrPem = defaults.csrPem;
    	      this.issuerCertificateAuthorityId = defaults.issuerCertificateAuthorityId;
    	      this.keyAlgorithm = defaults.keyAlgorithm;
    	      this.signatureAlgorithm = defaults.signatureAlgorithm;
    	      this.subjectAlternativeNames = defaults.subjectAlternativeNames;
    	      this.subjects = defaults.subjects;
    	      this.validities = defaults.validities;
    	      this.versionName = defaults.versionName;
        }

        @CustomType.Setter
        public Builder certificateProfileType(String certificateProfileType) {
            this.certificateProfileType = Objects.requireNonNull(certificateProfileType);
            return this;
        }
        @CustomType.Setter
        public Builder configType(String configType) {
            this.configType = Objects.requireNonNull(configType);
            return this;
        }
        @CustomType.Setter
        public Builder csrPem(String csrPem) {
            this.csrPem = Objects.requireNonNull(csrPem);
            return this;
        }
        @CustomType.Setter
        public Builder issuerCertificateAuthorityId(String issuerCertificateAuthorityId) {
            this.issuerCertificateAuthorityId = Objects.requireNonNull(issuerCertificateAuthorityId);
            return this;
        }
        @CustomType.Setter
        public Builder keyAlgorithm(String keyAlgorithm) {
            this.keyAlgorithm = Objects.requireNonNull(keyAlgorithm);
            return this;
        }
        @CustomType.Setter
        public Builder signatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = Objects.requireNonNull(signatureAlgorithm);
            return this;
        }
        @CustomType.Setter
        public Builder subjectAlternativeNames(List<GetCertificatesCertificateCollectionItemCertificateConfigSubjectAlternativeName> subjectAlternativeNames) {
            this.subjectAlternativeNames = Objects.requireNonNull(subjectAlternativeNames);
            return this;
        }
        public Builder subjectAlternativeNames(GetCertificatesCertificateCollectionItemCertificateConfigSubjectAlternativeName... subjectAlternativeNames) {
            return subjectAlternativeNames(List.of(subjectAlternativeNames));
        }
        @CustomType.Setter
        public Builder subjects(List<GetCertificatesCertificateCollectionItemCertificateConfigSubject> subjects) {
            this.subjects = Objects.requireNonNull(subjects);
            return this;
        }
        public Builder subjects(GetCertificatesCertificateCollectionItemCertificateConfigSubject... subjects) {
            return subjects(List.of(subjects));
        }
        @CustomType.Setter
        public Builder validities(List<GetCertificatesCertificateCollectionItemCertificateConfigValidity> validities) {
            this.validities = Objects.requireNonNull(validities);
            return this;
        }
        public Builder validities(GetCertificatesCertificateCollectionItemCertificateConfigValidity... validities) {
            return validities(List.of(validities));
        }
        @CustomType.Setter
        public Builder versionName(String versionName) {
            this.versionName = Objects.requireNonNull(versionName);
            return this;
        }
        public GetCertificatesCertificateCollectionItemCertificateConfig build() {
            final var o = new GetCertificatesCertificateCollectionItemCertificateConfig();
            o.certificateProfileType = certificateProfileType;
            o.configType = configType;
            o.csrPem = csrPem;
            o.issuerCertificateAuthorityId = issuerCertificateAuthorityId;
            o.keyAlgorithm = keyAlgorithm;
            o.signatureAlgorithm = signatureAlgorithm;
            o.subjectAlternativeNames = subjectAlternativeNames;
            o.subjects = subjects;
            o.validities = validities;
            o.versionName = versionName;
            return o;
        }
    }
}