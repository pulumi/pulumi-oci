// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VolumeGroupVolumeGroupReplicaArgs extends com.pulumi.resources.ResourceArgs {

    public static final VolumeGroupVolumeGroupReplicaArgs Empty = new VolumeGroupVolumeGroupReplicaArgs();

    /**
     * (Updatable) The availability domain of the volume group replica.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return (Updatable) The availability domain of the volume group replica.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The volume group replica&#39;s Oracle ID (OCID).
     * 
     */
    @Import(name="volumeGroupReplicaId")
    private @Nullable Output<String> volumeGroupReplicaId;

    /**
     * @return The volume group replica&#39;s Oracle ID (OCID).
     * 
     */
    public Optional<Output<String>> volumeGroupReplicaId() {
        return Optional.ofNullable(this.volumeGroupReplicaId);
    }

    /**
     * (Updatable) The OCID of the Vault service key which is the master encryption key for the cross region volume group&#39;s replicas, which will be used in the destination region to encrypt the volume group&#39;s replicas encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     * 
     */
    @Import(name="xrrKmsKeyId")
    private @Nullable Output<String> xrrKmsKeyId;

    /**
     * @return (Updatable) The OCID of the Vault service key which is the master encryption key for the cross region volume group&#39;s replicas, which will be used in the destination region to encrypt the volume group&#39;s replicas encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     * 
     */
    public Optional<Output<String>> xrrKmsKeyId() {
        return Optional.ofNullable(this.xrrKmsKeyId);
    }

    private VolumeGroupVolumeGroupReplicaArgs() {}

    private VolumeGroupVolumeGroupReplicaArgs(VolumeGroupVolumeGroupReplicaArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.displayName = $.displayName;
        this.volumeGroupReplicaId = $.volumeGroupReplicaId;
        this.xrrKmsKeyId = $.xrrKmsKeyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VolumeGroupVolumeGroupReplicaArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VolumeGroupVolumeGroupReplicaArgs $;

        public Builder() {
            $ = new VolumeGroupVolumeGroupReplicaArgs();
        }

        public Builder(VolumeGroupVolumeGroupReplicaArgs defaults) {
            $ = new VolumeGroupVolumeGroupReplicaArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain (Updatable) The availability domain of the volume group replica.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain (Updatable) The availability domain of the volume group replica.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param volumeGroupReplicaId The volume group replica&#39;s Oracle ID (OCID).
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupReplicaId(@Nullable Output<String> volumeGroupReplicaId) {
            $.volumeGroupReplicaId = volumeGroupReplicaId;
            return this;
        }

        /**
         * @param volumeGroupReplicaId The volume group replica&#39;s Oracle ID (OCID).
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupReplicaId(String volumeGroupReplicaId) {
            return volumeGroupReplicaId(Output.of(volumeGroupReplicaId));
        }

        /**
         * @param xrrKmsKeyId (Updatable) The OCID of the Vault service key which is the master encryption key for the cross region volume group&#39;s replicas, which will be used in the destination region to encrypt the volume group&#39;s replicas encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
         * 
         * @return builder
         * 
         */
        public Builder xrrKmsKeyId(@Nullable Output<String> xrrKmsKeyId) {
            $.xrrKmsKeyId = xrrKmsKeyId;
            return this;
        }

        /**
         * @param xrrKmsKeyId (Updatable) The OCID of the Vault service key which is the master encryption key for the cross region volume group&#39;s replicas, which will be used in the destination region to encrypt the volume group&#39;s replicas encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
         * 
         * @return builder
         * 
         */
        public Builder xrrKmsKeyId(String xrrKmsKeyId) {
            return xrrKmsKeyId(Output.of(xrrKmsKeyId));
        }

        public VolumeGroupVolumeGroupReplicaArgs build() {
            if ($.availabilityDomain == null) {
                throw new MissingRequiredPropertyException("VolumeGroupVolumeGroupReplicaArgs", "availabilityDomain");
            }
            return $;
        }
    }

}
