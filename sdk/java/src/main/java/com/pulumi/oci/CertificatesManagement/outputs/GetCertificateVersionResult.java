// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificateVersionRevocationStatus;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificateVersionSubjectAlternativeName;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificateVersionValidity;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCertificateVersionResult {
    /**
     * @return The OCID of the certificate.
     * 
     */
    private String certificateId;
    private String certificateVersionNumber;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The version number of the issuing certificate authority (CA).
     * 
     */
    private String issuerCaVersionNumber;
    /**
     * @return The current revocation status of the entity.
     * 
     */
    private List<GetCertificateVersionRevocationStatus> revocationStatuses;
    /**
     * @return A unique certificate identifier used in certificate revocation tracking, formatted as octets. Example: `03 AC FC FA CC B3 CB 02 B8 F8 DE F5 85 E7 7B FF`
     * 
     */
    private String serialNumber;
    /**
     * @return A list of stages of this entity.
     * 
     */
    private List<String> stages;
    /**
     * @return A list of subject alternative names.
     * 
     */
    private List<GetCertificateVersionSubjectAlternativeName> subjectAlternativeNames;
    /**
     * @return A optional property indicating when the certificate version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return An optional property indicating when to delete the certificate version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    private String timeOfDeletion;
    /**
     * @return An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
     * 
     */
    private List<GetCertificateVersionValidity> validities;
    /**
     * @return The name of the certificate version. When the value is not null, a name is unique across versions of a given certificate.
     * 
     */
    private String versionName;
    /**
     * @return The version number of the certificate.
     * 
     */
    private String versionNumber;

    private GetCertificateVersionResult() {}
    /**
     * @return The OCID of the certificate.
     * 
     */
    public String certificateId() {
        return this.certificateId;
    }
    public String certificateVersionNumber() {
        return this.certificateVersionNumber;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The version number of the issuing certificate authority (CA).
     * 
     */
    public String issuerCaVersionNumber() {
        return this.issuerCaVersionNumber;
    }
    /**
     * @return The current revocation status of the entity.
     * 
     */
    public List<GetCertificateVersionRevocationStatus> revocationStatuses() {
        return this.revocationStatuses;
    }
    /**
     * @return A unique certificate identifier used in certificate revocation tracking, formatted as octets. Example: `03 AC FC FA CC B3 CB 02 B8 F8 DE F5 85 E7 7B FF`
     * 
     */
    public String serialNumber() {
        return this.serialNumber;
    }
    /**
     * @return A list of stages of this entity.
     * 
     */
    public List<String> stages() {
        return this.stages;
    }
    /**
     * @return A list of subject alternative names.
     * 
     */
    public List<GetCertificateVersionSubjectAlternativeName> subjectAlternativeNames() {
        return this.subjectAlternativeNames;
    }
    /**
     * @return A optional property indicating when the certificate version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return An optional property indicating when to delete the certificate version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public String timeOfDeletion() {
        return this.timeOfDeletion;
    }
    /**
     * @return An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
     * 
     */
    public List<GetCertificateVersionValidity> validities() {
        return this.validities;
    }
    /**
     * @return The name of the certificate version. When the value is not null, a name is unique across versions of a given certificate.
     * 
     */
    public String versionName() {
        return this.versionName;
    }
    /**
     * @return The version number of the certificate.
     * 
     */
    public String versionNumber() {
        return this.versionNumber;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCertificateVersionResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String certificateId;
        private String certificateVersionNumber;
        private String id;
        private String issuerCaVersionNumber;
        private List<GetCertificateVersionRevocationStatus> revocationStatuses;
        private String serialNumber;
        private List<String> stages;
        private List<GetCertificateVersionSubjectAlternativeName> subjectAlternativeNames;
        private String timeCreated;
        private String timeOfDeletion;
        private List<GetCertificateVersionValidity> validities;
        private String versionName;
        private String versionNumber;
        public Builder() {}
        public Builder(GetCertificateVersionResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certificateId = defaults.certificateId;
    	      this.certificateVersionNumber = defaults.certificateVersionNumber;
    	      this.id = defaults.id;
    	      this.issuerCaVersionNumber = defaults.issuerCaVersionNumber;
    	      this.revocationStatuses = defaults.revocationStatuses;
    	      this.serialNumber = defaults.serialNumber;
    	      this.stages = defaults.stages;
    	      this.subjectAlternativeNames = defaults.subjectAlternativeNames;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeOfDeletion = defaults.timeOfDeletion;
    	      this.validities = defaults.validities;
    	      this.versionName = defaults.versionName;
    	      this.versionNumber = defaults.versionNumber;
        }

        @CustomType.Setter
        public Builder certificateId(String certificateId) {
            this.certificateId = Objects.requireNonNull(certificateId);
            return this;
        }
        @CustomType.Setter
        public Builder certificateVersionNumber(String certificateVersionNumber) {
            this.certificateVersionNumber = Objects.requireNonNull(certificateVersionNumber);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder issuerCaVersionNumber(String issuerCaVersionNumber) {
            this.issuerCaVersionNumber = Objects.requireNonNull(issuerCaVersionNumber);
            return this;
        }
        @CustomType.Setter
        public Builder revocationStatuses(List<GetCertificateVersionRevocationStatus> revocationStatuses) {
            this.revocationStatuses = Objects.requireNonNull(revocationStatuses);
            return this;
        }
        public Builder revocationStatuses(GetCertificateVersionRevocationStatus... revocationStatuses) {
            return revocationStatuses(List.of(revocationStatuses));
        }
        @CustomType.Setter
        public Builder serialNumber(String serialNumber) {
            this.serialNumber = Objects.requireNonNull(serialNumber);
            return this;
        }
        @CustomType.Setter
        public Builder stages(List<String> stages) {
            this.stages = Objects.requireNonNull(stages);
            return this;
        }
        public Builder stages(String... stages) {
            return stages(List.of(stages));
        }
        @CustomType.Setter
        public Builder subjectAlternativeNames(List<GetCertificateVersionSubjectAlternativeName> subjectAlternativeNames) {
            this.subjectAlternativeNames = Objects.requireNonNull(subjectAlternativeNames);
            return this;
        }
        public Builder subjectAlternativeNames(GetCertificateVersionSubjectAlternativeName... subjectAlternativeNames) {
            return subjectAlternativeNames(List.of(subjectAlternativeNames));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeOfDeletion(String timeOfDeletion) {
            this.timeOfDeletion = Objects.requireNonNull(timeOfDeletion);
            return this;
        }
        @CustomType.Setter
        public Builder validities(List<GetCertificateVersionValidity> validities) {
            this.validities = Objects.requireNonNull(validities);
            return this;
        }
        public Builder validities(GetCertificateVersionValidity... validities) {
            return validities(List.of(validities));
        }
        @CustomType.Setter
        public Builder versionName(String versionName) {
            this.versionName = Objects.requireNonNull(versionName);
            return this;
        }
        @CustomType.Setter
        public Builder versionNumber(String versionNumber) {
            this.versionNumber = Objects.requireNonNull(versionNumber);
            return this;
        }
        public GetCertificateVersionResult build() {
            final var o = new GetCertificateVersionResult();
            o.certificateId = certificateId;
            o.certificateVersionNumber = certificateVersionNumber;
            o.id = id;
            o.issuerCaVersionNumber = issuerCaVersionNumber;
            o.revocationStatuses = revocationStatuses;
            o.serialNumber = serialNumber;
            o.stages = stages;
            o.subjectAlternativeNames = subjectAlternativeNames;
            o.timeCreated = timeCreated;
            o.timeOfDeletion = timeOfDeletion;
            o.validities = validities;
            o.versionName = versionName;
            o.versionNumber = versionNumber;
            return o;
        }
    }
}