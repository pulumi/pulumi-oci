// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Artifacts.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetContainerImageSignatureResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the container repository exists.
     * 
     */
    private String compartmentId;
    /**
     * @return The id of the user or principal that created the resource.
     * 
     */
    private String createdBy;
    /**
     * @return The last 10 characters of the kmsKeyId, the last 10 characters of the kmsKeyVersionId, the signingAlgorithm, and the last 10 characters of the signatureId.  Example: `wrmz22sixa::qdwyc2ptun::SHA_256_RSA_PKCS_PSS::2vwmobasva`
     * 
     */
    private String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image signature.  Example: `ocid1.containerimagesignature.oc1..exampleuniqueID`
     * 
     */
    private String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image.  Example: `ocid1.containerimage.oc1..exampleuniqueID`
     * 
     */
    private String imageId;
    private String imageSignatureId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyId used to sign the container image.  Example: `ocid1.key.oc1..exampleuniqueID`
     * 
     */
    private String kmsKeyId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyVersionId used to sign the container image.  Example: `ocid1.keyversion.oc1..exampleuniqueID`
     * 
     */
    private String kmsKeyVersionId;
    /**
     * @return The base64 encoded signature payload that was signed.
     * 
     */
    private String message;
    /**
     * @return The signature of the message field using the kmsKeyId, the kmsKeyVersionId, and the signingAlgorithm.
     * 
     */
    private String signature;
    /**
     * @return The algorithm to be used for signing. These are the only supported signing algorithms for container images.
     * 
     */
    private String signingAlgorithm;
    /**
     * @return An RFC 3339 timestamp indicating when the image was created.
     * 
     */
    private String timeCreated;

    private GetContainerImageSignatureResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the container repository exists.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The id of the user or principal that created the resource.
     * 
     */
    public String createdBy() {
        return this.createdBy;
    }
    /**
     * @return The last 10 characters of the kmsKeyId, the last 10 characters of the kmsKeyVersionId, the signingAlgorithm, and the last 10 characters of the signatureId.  Example: `wrmz22sixa::qdwyc2ptun::SHA_256_RSA_PKCS_PSS::2vwmobasva`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image signature.  Example: `ocid1.containerimagesignature.oc1..exampleuniqueID`
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image.  Example: `ocid1.containerimage.oc1..exampleuniqueID`
     * 
     */
    public String imageId() {
        return this.imageId;
    }
    public String imageSignatureId() {
        return this.imageSignatureId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyId used to sign the container image.  Example: `ocid1.key.oc1..exampleuniqueID`
     * 
     */
    public String kmsKeyId() {
        return this.kmsKeyId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyVersionId used to sign the container image.  Example: `ocid1.keyversion.oc1..exampleuniqueID`
     * 
     */
    public String kmsKeyVersionId() {
        return this.kmsKeyVersionId;
    }
    /**
     * @return The base64 encoded signature payload that was signed.
     * 
     */
    public String message() {
        return this.message;
    }
    /**
     * @return The signature of the message field using the kmsKeyId, the kmsKeyVersionId, and the signingAlgorithm.
     * 
     */
    public String signature() {
        return this.signature;
    }
    /**
     * @return The algorithm to be used for signing. These are the only supported signing algorithms for container images.
     * 
     */
    public String signingAlgorithm() {
        return this.signingAlgorithm;
    }
    /**
     * @return An RFC 3339 timestamp indicating when the image was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetContainerImageSignatureResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String createdBy;
        private String displayName;
        private String id;
        private String imageId;
        private String imageSignatureId;
        private String kmsKeyId;
        private String kmsKeyVersionId;
        private String message;
        private String signature;
        private String signingAlgorithm;
        private String timeCreated;
        public Builder() {}
        public Builder(GetContainerImageSignatureResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.createdBy = defaults.createdBy;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.imageId = defaults.imageId;
    	      this.imageSignatureId = defaults.imageSignatureId;
    	      this.kmsKeyId = defaults.kmsKeyId;
    	      this.kmsKeyVersionId = defaults.kmsKeyVersionId;
    	      this.message = defaults.message;
    	      this.signature = defaults.signature;
    	      this.signingAlgorithm = defaults.signingAlgorithm;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder createdBy(String createdBy) {
            this.createdBy = Objects.requireNonNull(createdBy);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder imageId(String imageId) {
            this.imageId = Objects.requireNonNull(imageId);
            return this;
        }
        @CustomType.Setter
        public Builder imageSignatureId(String imageSignatureId) {
            this.imageSignatureId = Objects.requireNonNull(imageSignatureId);
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyId(String kmsKeyId) {
            this.kmsKeyId = Objects.requireNonNull(kmsKeyId);
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyVersionId(String kmsKeyVersionId) {
            this.kmsKeyVersionId = Objects.requireNonNull(kmsKeyVersionId);
            return this;
        }
        @CustomType.Setter
        public Builder message(String message) {
            this.message = Objects.requireNonNull(message);
            return this;
        }
        @CustomType.Setter
        public Builder signature(String signature) {
            this.signature = Objects.requireNonNull(signature);
            return this;
        }
        @CustomType.Setter
        public Builder signingAlgorithm(String signingAlgorithm) {
            this.signingAlgorithm = Objects.requireNonNull(signingAlgorithm);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public GetContainerImageSignatureResult build() {
            final var o = new GetContainerImageSignatureResult();
            o.compartmentId = compartmentId;
            o.createdBy = createdBy;
            o.displayName = displayName;
            o.id = id;
            o.imageId = imageId;
            o.imageSignatureId = imageSignatureId;
            o.kmsKeyId = kmsKeyId;
            o.kmsKeyVersionId = kmsKeyVersionId;
            o.message = message;
            o.signature = signature;
            o.signingAlgorithm = signingAlgorithm;
            o.timeCreated = timeCreated;
            return o;
        }
    }
}