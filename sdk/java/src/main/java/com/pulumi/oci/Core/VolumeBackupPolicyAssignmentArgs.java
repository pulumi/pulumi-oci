// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VolumeBackupPolicyAssignmentArgs extends com.pulumi.resources.ResourceArgs {

    public static final VolumeBackupPolicyAssignmentArgs Empty = new VolumeBackupPolicyAssignmentArgs();

    /**
     * The OCID of the volume or volume group to assign the policy to.
     * 
     */
    @Import(name="assetId", required=true)
    private Output<String> assetId;

    /**
     * @return The OCID of the volume or volume group to assign the policy to.
     * 
     */
    public Output<String> assetId() {
        return this.assetId;
    }

    /**
     * The OCID of the volume backup policy to assign to the volume.
     * 
     */
    @Import(name="policyId", required=true)
    private Output<String> policyId;

    /**
     * @return The OCID of the volume backup policy to assign to the volume.
     * 
     */
    public Output<String> policyId() {
        return this.policyId;
    }

    /**
     * The OCID of the Vault service key which is the master encryption key for the block / boot volume cross region backups, which will be used in the destination region to encrypt the backup&#39;s encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="xrcKmsKeyId")
    private @Nullable Output<String> xrcKmsKeyId;

    /**
     * @return The OCID of the Vault service key which is the master encryption key for the block / boot volume cross region backups, which will be used in the destination region to encrypt the backup&#39;s encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> xrcKmsKeyId() {
        return Optional.ofNullable(this.xrcKmsKeyId);
    }

    private VolumeBackupPolicyAssignmentArgs() {}

    private VolumeBackupPolicyAssignmentArgs(VolumeBackupPolicyAssignmentArgs $) {
        this.assetId = $.assetId;
        this.policyId = $.policyId;
        this.xrcKmsKeyId = $.xrcKmsKeyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VolumeBackupPolicyAssignmentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VolumeBackupPolicyAssignmentArgs $;

        public Builder() {
            $ = new VolumeBackupPolicyAssignmentArgs();
        }

        public Builder(VolumeBackupPolicyAssignmentArgs defaults) {
            $ = new VolumeBackupPolicyAssignmentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param assetId The OCID of the volume or volume group to assign the policy to.
         * 
         * @return builder
         * 
         */
        public Builder assetId(Output<String> assetId) {
            $.assetId = assetId;
            return this;
        }

        /**
         * @param assetId The OCID of the volume or volume group to assign the policy to.
         * 
         * @return builder
         * 
         */
        public Builder assetId(String assetId) {
            return assetId(Output.of(assetId));
        }

        /**
         * @param policyId The OCID of the volume backup policy to assign to the volume.
         * 
         * @return builder
         * 
         */
        public Builder policyId(Output<String> policyId) {
            $.policyId = policyId;
            return this;
        }

        /**
         * @param policyId The OCID of the volume backup policy to assign to the volume.
         * 
         * @return builder
         * 
         */
        public Builder policyId(String policyId) {
            return policyId(Output.of(policyId));
        }

        /**
         * @param xrcKmsKeyId The OCID of the Vault service key which is the master encryption key for the block / boot volume cross region backups, which will be used in the destination region to encrypt the backup&#39;s encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder xrcKmsKeyId(@Nullable Output<String> xrcKmsKeyId) {
            $.xrcKmsKeyId = xrcKmsKeyId;
            return this;
        }

        /**
         * @param xrcKmsKeyId The OCID of the Vault service key which is the master encryption key for the block / boot volume cross region backups, which will be used in the destination region to encrypt the backup&#39;s encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder xrcKmsKeyId(String xrcKmsKeyId) {
            return xrcKmsKeyId(Output.of(xrcKmsKeyId));
        }

        public VolumeBackupPolicyAssignmentArgs build() {
            if ($.assetId == null) {
                throw new MissingRequiredPropertyException("VolumeBackupPolicyAssignmentArgs", "assetId");
            }
            if ($.policyId == null) {
                throw new MissingRequiredPropertyException("VolumeBackupPolicyAssignmentArgs", "policyId");
            }
            return $;
        }
    }

}
