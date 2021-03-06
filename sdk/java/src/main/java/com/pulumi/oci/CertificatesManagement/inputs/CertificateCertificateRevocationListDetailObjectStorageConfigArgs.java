// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CertificateCertificateRevocationListDetailObjectStorageConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final CertificateCertificateRevocationListDetailObjectStorageConfigArgs Empty = new CertificateCertificateRevocationListDetailObjectStorageConfigArgs();

    /**
     * The name of the bucket where the CRL is stored.
     * 
     */
    @Import(name="objectStorageBucketName")
    private @Nullable Output<String> objectStorageBucketName;

    /**
     * @return The name of the bucket where the CRL is stored.
     * 
     */
    public Optional<Output<String>> objectStorageBucketName() {
        return Optional.ofNullable(this.objectStorageBucketName);
    }

    /**
     * The tenancy of the bucket where the CRL is stored.
     * 
     */
    @Import(name="objectStorageNamespace")
    private @Nullable Output<String> objectStorageNamespace;

    /**
     * @return The tenancy of the bucket where the CRL is stored.
     * 
     */
    public Optional<Output<String>> objectStorageNamespace() {
        return Optional.ofNullable(this.objectStorageNamespace);
    }

    /**
     * The object name in the bucket where the CRL is stored, expressed using a format where the version number of the issuing CA is inserted as part of the Object Storage object name wherever you include a pair of curly braces. This versioning scheme helps avoid collisions when new CA versions are created. For example, myCrlFileIssuedFromCAVersion{}.crl becomes myCrlFileIssuedFromCAVersion2.crl for CA version 2.
     * 
     */
    @Import(name="objectStorageObjectNameFormat")
    private @Nullable Output<String> objectStorageObjectNameFormat;

    /**
     * @return The object name in the bucket where the CRL is stored, expressed using a format where the version number of the issuing CA is inserted as part of the Object Storage object name wherever you include a pair of curly braces. This versioning scheme helps avoid collisions when new CA versions are created. For example, myCrlFileIssuedFromCAVersion{}.crl becomes myCrlFileIssuedFromCAVersion2.crl for CA version 2.
     * 
     */
    public Optional<Output<String>> objectStorageObjectNameFormat() {
        return Optional.ofNullable(this.objectStorageObjectNameFormat);
    }

    private CertificateCertificateRevocationListDetailObjectStorageConfigArgs() {}

    private CertificateCertificateRevocationListDetailObjectStorageConfigArgs(CertificateCertificateRevocationListDetailObjectStorageConfigArgs $) {
        this.objectStorageBucketName = $.objectStorageBucketName;
        this.objectStorageNamespace = $.objectStorageNamespace;
        this.objectStorageObjectNameFormat = $.objectStorageObjectNameFormat;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CertificateCertificateRevocationListDetailObjectStorageConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CertificateCertificateRevocationListDetailObjectStorageConfigArgs $;

        public Builder() {
            $ = new CertificateCertificateRevocationListDetailObjectStorageConfigArgs();
        }

        public Builder(CertificateCertificateRevocationListDetailObjectStorageConfigArgs defaults) {
            $ = new CertificateCertificateRevocationListDetailObjectStorageConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param objectStorageBucketName The name of the bucket where the CRL is stored.
         * 
         * @return builder
         * 
         */
        public Builder objectStorageBucketName(@Nullable Output<String> objectStorageBucketName) {
            $.objectStorageBucketName = objectStorageBucketName;
            return this;
        }

        /**
         * @param objectStorageBucketName The name of the bucket where the CRL is stored.
         * 
         * @return builder
         * 
         */
        public Builder objectStorageBucketName(String objectStorageBucketName) {
            return objectStorageBucketName(Output.of(objectStorageBucketName));
        }

        /**
         * @param objectStorageNamespace The tenancy of the bucket where the CRL is stored.
         * 
         * @return builder
         * 
         */
        public Builder objectStorageNamespace(@Nullable Output<String> objectStorageNamespace) {
            $.objectStorageNamespace = objectStorageNamespace;
            return this;
        }

        /**
         * @param objectStorageNamespace The tenancy of the bucket where the CRL is stored.
         * 
         * @return builder
         * 
         */
        public Builder objectStorageNamespace(String objectStorageNamespace) {
            return objectStorageNamespace(Output.of(objectStorageNamespace));
        }

        /**
         * @param objectStorageObjectNameFormat The object name in the bucket where the CRL is stored, expressed using a format where the version number of the issuing CA is inserted as part of the Object Storage object name wherever you include a pair of curly braces. This versioning scheme helps avoid collisions when new CA versions are created. For example, myCrlFileIssuedFromCAVersion{}.crl becomes myCrlFileIssuedFromCAVersion2.crl for CA version 2.
         * 
         * @return builder
         * 
         */
        public Builder objectStorageObjectNameFormat(@Nullable Output<String> objectStorageObjectNameFormat) {
            $.objectStorageObjectNameFormat = objectStorageObjectNameFormat;
            return this;
        }

        /**
         * @param objectStorageObjectNameFormat The object name in the bucket where the CRL is stored, expressed using a format where the version number of the issuing CA is inserted as part of the Object Storage object name wherever you include a pair of curly braces. This versioning scheme helps avoid collisions when new CA versions are created. For example, myCrlFileIssuedFromCAVersion{}.crl becomes myCrlFileIssuedFromCAVersion2.crl for CA version 2.
         * 
         * @return builder
         * 
         */
        public Builder objectStorageObjectNameFormat(String objectStorageObjectNameFormat) {
            return objectStorageObjectNameFormat(Output.of(objectStorageObjectNameFormat));
        }

        public CertificateCertificateRevocationListDetailObjectStorageConfigArgs build() {
            return $;
        }
    }

}
