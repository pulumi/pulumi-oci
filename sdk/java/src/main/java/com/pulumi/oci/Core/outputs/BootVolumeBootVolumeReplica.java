// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BootVolumeBootVolumeReplica {
    /**
     * @return (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The boot volume replica&#39;s Oracle ID (OCID).
     * 
     */
    private @Nullable String bootVolumeReplicaId;
    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return (Updatable) The OCID of the Vault service key to assign as the master encryption key for the boot volume.
     * 
     */
    private @Nullable String kmsKeyId;
    /**
     * @return (Updatable) The OCID of the Vault service key which is the master encryption key for the cross region boot volume replicas, which will be used in the destination region to encrypt the boot volume replica&#39;s encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     * 
     */
    private @Nullable String xrrKmsKeyId;

    private BootVolumeBootVolumeReplica() {}
    /**
     * @return (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The boot volume replica&#39;s Oracle ID (OCID).
     * 
     */
    public Optional<String> bootVolumeReplicaId() {
        return Optional.ofNullable(this.bootVolumeReplicaId);
    }
    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return (Updatable) The OCID of the Vault service key to assign as the master encryption key for the boot volume.
     * 
     */
    public Optional<String> kmsKeyId() {
        return Optional.ofNullable(this.kmsKeyId);
    }
    /**
     * @return (Updatable) The OCID of the Vault service key which is the master encryption key for the cross region boot volume replicas, which will be used in the destination region to encrypt the boot volume replica&#39;s encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     * 
     */
    public Optional<String> xrrKmsKeyId() {
        return Optional.ofNullable(this.xrrKmsKeyId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BootVolumeBootVolumeReplica defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private @Nullable String bootVolumeReplicaId;
        private @Nullable String displayName;
        private @Nullable String kmsKeyId;
        private @Nullable String xrrKmsKeyId;
        public Builder() {}
        public Builder(BootVolumeBootVolumeReplica defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.bootVolumeReplicaId = defaults.bootVolumeReplicaId;
    	      this.displayName = defaults.displayName;
    	      this.kmsKeyId = defaults.kmsKeyId;
    	      this.xrrKmsKeyId = defaults.xrrKmsKeyId;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("BootVolumeBootVolumeReplica", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder bootVolumeReplicaId(@Nullable String bootVolumeReplicaId) {

            this.bootVolumeReplicaId = bootVolumeReplicaId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyId(@Nullable String kmsKeyId) {

            this.kmsKeyId = kmsKeyId;
            return this;
        }
        @CustomType.Setter
        public Builder xrrKmsKeyId(@Nullable String xrrKmsKeyId) {

            this.xrrKmsKeyId = xrrKmsKeyId;
            return this;
        }
        public BootVolumeBootVolumeReplica build() {
            final var _resultValue = new BootVolumeBootVolumeReplica();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.bootVolumeReplicaId = bootVolumeReplicaId;
            _resultValue.displayName = displayName;
            _resultValue.kmsKeyId = kmsKeyId;
            _resultValue.xrrKmsKeyId = xrrKmsKeyId;
            return _resultValue;
        }
    }
}
