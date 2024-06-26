// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CertificatesManagement.inputs.CertificateCertificateConfigSubjectAlternativeNameArgs;
import com.pulumi.oci.CertificatesManagement.inputs.CertificateCertificateConfigSubjectArgs;
import com.pulumi.oci.CertificatesManagement.inputs.CertificateCertificateConfigValidityArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CertificateCertificateConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final CertificateCertificateConfigArgs Empty = new CertificateCertificateConfigArgs();

    /**
     * The name of the profile used to create the certificate, which depends on the type of certificate you need.
     * 
     */
    @Import(name="certificateProfileType")
    private @Nullable Output<String> certificateProfileType;

    /**
     * @return The name of the profile used to create the certificate, which depends on the type of certificate you need.
     * 
     */
    public Optional<Output<String>> certificateProfileType() {
        return Optional.ofNullable(this.certificateProfileType);
    }

    /**
     * (Updatable) The origin of the certificate.
     * 
     */
    @Import(name="configType", required=true)
    private Output<String> configType;

    /**
     * @return (Updatable) The origin of the certificate.
     * 
     */
    public Output<String> configType() {
        return this.configType;
    }

    /**
     * (Updatable) The certificate signing request (in PEM format).
     * 
     */
    @Import(name="csrPem")
    private @Nullable Output<String> csrPem;

    /**
     * @return (Updatable) The certificate signing request (in PEM format).
     * 
     */
    public Optional<Output<String>> csrPem() {
        return Optional.ofNullable(this.csrPem);
    }

    /**
     * The OCID of the private CA.
     * 
     */
    @Import(name="issuerCertificateAuthorityId")
    private @Nullable Output<String> issuerCertificateAuthorityId;

    /**
     * @return The OCID of the private CA.
     * 
     */
    public Optional<Output<String>> issuerCertificateAuthorityId() {
        return Optional.ofNullable(this.issuerCertificateAuthorityId);
    }

    /**
     * The algorithm to use to create key pairs.
     * 
     */
    @Import(name="keyAlgorithm")
    private @Nullable Output<String> keyAlgorithm;

    /**
     * @return The algorithm to use to create key pairs.
     * 
     */
    public Optional<Output<String>> keyAlgorithm() {
        return Optional.ofNullable(this.keyAlgorithm);
    }

    /**
     * The algorithm to use to sign the public key certificate.
     * 
     */
    @Import(name="signatureAlgorithm")
    private @Nullable Output<String> signatureAlgorithm;

    /**
     * @return The algorithm to use to sign the public key certificate.
     * 
     */
    public Optional<Output<String>> signatureAlgorithm() {
        return Optional.ofNullable(this.signatureAlgorithm);
    }

    /**
     * The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
     * 
     */
    @Import(name="subject")
    private @Nullable Output<CertificateCertificateConfigSubjectArgs> subject;

    /**
     * @return The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
     * 
     */
    public Optional<Output<CertificateCertificateConfigSubjectArgs>> subject() {
        return Optional.ofNullable(this.subject);
    }

    /**
     * A list of subject alternative names.
     * 
     */
    @Import(name="subjectAlternativeNames")
    private @Nullable Output<List<CertificateCertificateConfigSubjectAlternativeNameArgs>> subjectAlternativeNames;

    /**
     * @return A list of subject alternative names.
     * 
     */
    public Optional<Output<List<CertificateCertificateConfigSubjectAlternativeNameArgs>>> subjectAlternativeNames() {
        return Optional.ofNullable(this.subjectAlternativeNames);
    }

    /**
     * (Updatable) An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
     * 
     */
    @Import(name="validity")
    private @Nullable Output<CertificateCertificateConfigValidityArgs> validity;

    /**
     * @return (Updatable) An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
     * 
     */
    public Optional<Output<CertificateCertificateConfigValidityArgs>> validity() {
        return Optional.ofNullable(this.validity);
    }

    /**
     * (Updatable) A name for the certificate. When the value is not null, a name is unique across versions of a given certificate.
     * 
     */
    @Import(name="versionName")
    private @Nullable Output<String> versionName;

    /**
     * @return (Updatable) A name for the certificate. When the value is not null, a name is unique across versions of a given certificate.
     * 
     */
    public Optional<Output<String>> versionName() {
        return Optional.ofNullable(this.versionName);
    }

    private CertificateCertificateConfigArgs() {}

    private CertificateCertificateConfigArgs(CertificateCertificateConfigArgs $) {
        this.certificateProfileType = $.certificateProfileType;
        this.configType = $.configType;
        this.csrPem = $.csrPem;
        this.issuerCertificateAuthorityId = $.issuerCertificateAuthorityId;
        this.keyAlgorithm = $.keyAlgorithm;
        this.signatureAlgorithm = $.signatureAlgorithm;
        this.subject = $.subject;
        this.subjectAlternativeNames = $.subjectAlternativeNames;
        this.validity = $.validity;
        this.versionName = $.versionName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CertificateCertificateConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CertificateCertificateConfigArgs $;

        public Builder() {
            $ = new CertificateCertificateConfigArgs();
        }

        public Builder(CertificateCertificateConfigArgs defaults) {
            $ = new CertificateCertificateConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param certificateProfileType The name of the profile used to create the certificate, which depends on the type of certificate you need.
         * 
         * @return builder
         * 
         */
        public Builder certificateProfileType(@Nullable Output<String> certificateProfileType) {
            $.certificateProfileType = certificateProfileType;
            return this;
        }

        /**
         * @param certificateProfileType The name of the profile used to create the certificate, which depends on the type of certificate you need.
         * 
         * @return builder
         * 
         */
        public Builder certificateProfileType(String certificateProfileType) {
            return certificateProfileType(Output.of(certificateProfileType));
        }

        /**
         * @param configType (Updatable) The origin of the certificate.
         * 
         * @return builder
         * 
         */
        public Builder configType(Output<String> configType) {
            $.configType = configType;
            return this;
        }

        /**
         * @param configType (Updatable) The origin of the certificate.
         * 
         * @return builder
         * 
         */
        public Builder configType(String configType) {
            return configType(Output.of(configType));
        }

        /**
         * @param csrPem (Updatable) The certificate signing request (in PEM format).
         * 
         * @return builder
         * 
         */
        public Builder csrPem(@Nullable Output<String> csrPem) {
            $.csrPem = csrPem;
            return this;
        }

        /**
         * @param csrPem (Updatable) The certificate signing request (in PEM format).
         * 
         * @return builder
         * 
         */
        public Builder csrPem(String csrPem) {
            return csrPem(Output.of(csrPem));
        }

        /**
         * @param issuerCertificateAuthorityId The OCID of the private CA.
         * 
         * @return builder
         * 
         */
        public Builder issuerCertificateAuthorityId(@Nullable Output<String> issuerCertificateAuthorityId) {
            $.issuerCertificateAuthorityId = issuerCertificateAuthorityId;
            return this;
        }

        /**
         * @param issuerCertificateAuthorityId The OCID of the private CA.
         * 
         * @return builder
         * 
         */
        public Builder issuerCertificateAuthorityId(String issuerCertificateAuthorityId) {
            return issuerCertificateAuthorityId(Output.of(issuerCertificateAuthorityId));
        }

        /**
         * @param keyAlgorithm The algorithm to use to create key pairs.
         * 
         * @return builder
         * 
         */
        public Builder keyAlgorithm(@Nullable Output<String> keyAlgorithm) {
            $.keyAlgorithm = keyAlgorithm;
            return this;
        }

        /**
         * @param keyAlgorithm The algorithm to use to create key pairs.
         * 
         * @return builder
         * 
         */
        public Builder keyAlgorithm(String keyAlgorithm) {
            return keyAlgorithm(Output.of(keyAlgorithm));
        }

        /**
         * @param signatureAlgorithm The algorithm to use to sign the public key certificate.
         * 
         * @return builder
         * 
         */
        public Builder signatureAlgorithm(@Nullable Output<String> signatureAlgorithm) {
            $.signatureAlgorithm = signatureAlgorithm;
            return this;
        }

        /**
         * @param signatureAlgorithm The algorithm to use to sign the public key certificate.
         * 
         * @return builder
         * 
         */
        public Builder signatureAlgorithm(String signatureAlgorithm) {
            return signatureAlgorithm(Output.of(signatureAlgorithm));
        }

        /**
         * @param subject The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
         * 
         * @return builder
         * 
         */
        public Builder subject(@Nullable Output<CertificateCertificateConfigSubjectArgs> subject) {
            $.subject = subject;
            return this;
        }

        /**
         * @param subject The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
         * 
         * @return builder
         * 
         */
        public Builder subject(CertificateCertificateConfigSubjectArgs subject) {
            return subject(Output.of(subject));
        }

        /**
         * @param subjectAlternativeNames A list of subject alternative names.
         * 
         * @return builder
         * 
         */
        public Builder subjectAlternativeNames(@Nullable Output<List<CertificateCertificateConfigSubjectAlternativeNameArgs>> subjectAlternativeNames) {
            $.subjectAlternativeNames = subjectAlternativeNames;
            return this;
        }

        /**
         * @param subjectAlternativeNames A list of subject alternative names.
         * 
         * @return builder
         * 
         */
        public Builder subjectAlternativeNames(List<CertificateCertificateConfigSubjectAlternativeNameArgs> subjectAlternativeNames) {
            return subjectAlternativeNames(Output.of(subjectAlternativeNames));
        }

        /**
         * @param subjectAlternativeNames A list of subject alternative names.
         * 
         * @return builder
         * 
         */
        public Builder subjectAlternativeNames(CertificateCertificateConfigSubjectAlternativeNameArgs... subjectAlternativeNames) {
            return subjectAlternativeNames(List.of(subjectAlternativeNames));
        }

        /**
         * @param validity (Updatable) An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
         * 
         * @return builder
         * 
         */
        public Builder validity(@Nullable Output<CertificateCertificateConfigValidityArgs> validity) {
            $.validity = validity;
            return this;
        }

        /**
         * @param validity (Updatable) An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
         * 
         * @return builder
         * 
         */
        public Builder validity(CertificateCertificateConfigValidityArgs validity) {
            return validity(Output.of(validity));
        }

        /**
         * @param versionName (Updatable) A name for the certificate. When the value is not null, a name is unique across versions of a given certificate.
         * 
         * @return builder
         * 
         */
        public Builder versionName(@Nullable Output<String> versionName) {
            $.versionName = versionName;
            return this;
        }

        /**
         * @param versionName (Updatable) A name for the certificate. When the value is not null, a name is unique across versions of a given certificate.
         * 
         * @return builder
         * 
         */
        public Builder versionName(String versionName) {
            return versionName(Output.of(versionName));
        }

        public CertificateCertificateConfigArgs build() {
            if ($.configType == null) {
                throw new MissingRequiredPropertyException("CertificateCertificateConfigArgs", "configType");
            }
            return $;
        }
    }

}
