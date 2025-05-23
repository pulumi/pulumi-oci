// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.VolumeAutotunePolicyArgs;
import com.pulumi.oci.Core.inputs.VolumeBlockVolumeReplicaArgs;
import com.pulumi.oci.Core.inputs.VolumeSourceDetailsArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VolumeArgs extends com.pulumi.resources.ResourceArgs {

    public static final VolumeArgs Empty = new VolumeArgs();

    /**
     * (Updatable) The list of autotune policies to be enabled for this volume.
     * 
     */
    @Import(name="autotunePolicies")
    private @Nullable Output<List<VolumeAutotunePolicyArgs>> autotunePolicies;

    /**
     * @return (Updatable) The list of autotune policies to be enabled for this volume.
     * 
     */
    public Optional<Output<List<VolumeAutotunePolicyArgs>>> autotunePolicies() {
        return Optional.ofNullable(this.autotunePolicies);
    }

    /**
     * The availability domain of the volume. Omissible for cloning a volume. The new volume will be created in the availability domain of the source volume.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return The availability domain of the volume. Omissible for cloning a volume. The new volume will be created in the availability domain of the source volume.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned. This field is deprecated. Use the `oci.Core.getVolumeBackupPolicyAssignments` instead to assign a backup policy to a volume.
     * 
     * @deprecated
     * The &#39;backup_policy_id&#39; field has been deprecated. Please use the &#39;oci_core_volume_backup_policy_assignment&#39; resource instead.
     * 
     */
    @Deprecated /* The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead. */
    @Import(name="backupPolicyId")
    private @Nullable Output<String> backupPolicyId;

    /**
     * @return If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned. This field is deprecated. Use the `oci.Core.getVolumeBackupPolicyAssignments` instead to assign a backup policy to a volume.
     * 
     * @deprecated
     * The &#39;backup_policy_id&#39; field has been deprecated. Please use the &#39;oci_core_volume_backup_policy_assignment&#39; resource instead.
     * 
     */
    @Deprecated /* The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead. */
    public Optional<Output<String>> backupPolicyId() {
        return Optional.ofNullable(this.backupPolicyId);
    }

    /**
     * (Updatable) The list of block volume replicas to be enabled for this volume in the specified destination availability domains.
     * 
     */
    @Import(name="blockVolumeReplicas")
    private @Nullable Output<List<VolumeBlockVolumeReplicaArgs>> blockVolumeReplicas;

    /**
     * @return (Updatable) The list of block volume replicas to be enabled for this volume in the specified destination availability domains.
     * 
     */
    public Optional<Output<List<VolumeBlockVolumeReplicaArgs>>> blockVolumeReplicas() {
        return Optional.ofNullable(this.blockVolumeReplicas);
    }

    @Import(name="blockVolumeReplicasDeletion")
    private @Nullable Output<Boolean> blockVolumeReplicasDeletion;

    public Optional<Output<Boolean>> blockVolumeReplicasDeletion() {
        return Optional.ofNullable(this.blockVolumeReplicasDeletion);
    }

    /**
     * The clusterPlacementGroup Id of the volume for volume placement.
     * 
     */
    @Import(name="clusterPlacementGroupId")
    private @Nullable Output<String> clusterPlacementGroupId;

    /**
     * @return The clusterPlacementGroup Id of the volume for volume placement.
     * 
     */
    public Optional<Output<String>> clusterPlacementGroupId() {
        return Optional.ofNullable(this.clusterPlacementGroupId);
    }

    /**
     * (Updatable) The OCID of the compartment that contains the volume.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains the volume.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
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
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Specifies whether the auto-tune performance is enabled for this volume. This field is deprecated. Use the `DetachedVolumeAutotunePolicy` instead to enable the volume for detached autotune.
     * 
     */
    @Import(name="isAutoTuneEnabled")
    private @Nullable Output<Boolean> isAutoTuneEnabled;

    /**
     * @return (Updatable) Specifies whether the auto-tune performance is enabled for this volume. This field is deprecated. Use the `DetachedVolumeAutotunePolicy` instead to enable the volume for detached autotune.
     * 
     */
    public Optional<Output<Boolean>> isAutoTuneEnabled() {
        return Optional.ofNullable(this.isAutoTuneEnabled);
    }

    /**
     * (Updatable) Reservations-enabled is a boolean field that allows to enable PR (Persistent Reservation) on a volume.
     * 
     */
    @Import(name="isReservationsEnabled")
    private @Nullable Output<Boolean> isReservationsEnabled;

    /**
     * @return (Updatable) Reservations-enabled is a boolean field that allows to enable PR (Persistent Reservation) on a volume.
     * 
     */
    public Optional<Output<Boolean>> isReservationsEnabled() {
        return Optional.ofNullable(this.isReservationsEnabled);
    }

    /**
     * (Updatable) The OCID of the Vault service key to assign as the master encryption key for the volume.
     * 
     */
    @Import(name="kmsKeyId")
    private @Nullable Output<String> kmsKeyId;

    /**
     * @return (Updatable) The OCID of the Vault service key to assign as the master encryption key for the volume.
     * 
     */
    public Optional<Output<String>> kmsKeyId() {
        return Optional.ofNullable(this.kmsKeyId);
    }

    /**
     * (Updatable) The size of the volume in GBs.
     * 
     */
    @Import(name="sizeInGbs")
    private @Nullable Output<String> sizeInGbs;

    /**
     * @return (Updatable) The size of the volume in GBs.
     * 
     */
    public Optional<Output<String>> sizeInGbs() {
        return Optional.ofNullable(this.sizeInGbs);
    }

    /**
     * The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Use sizeInGBs instead.
     * 
     * @deprecated
     * The &#39;size_in_mbs&#39; field has been deprecated. Please use &#39;size_in_gbs&#39; instead.
     * 
     */
    @Deprecated /* The 'size_in_mbs' field has been deprecated. Please use 'size_in_gbs' instead. */
    @Import(name="sizeInMbs")
    private @Nullable Output<String> sizeInMbs;

    /**
     * @return The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Use sizeInGBs instead.
     * 
     * @deprecated
     * The &#39;size_in_mbs&#39; field has been deprecated. Please use &#39;size_in_gbs&#39; instead.
     * 
     */
    @Deprecated /* The 'size_in_mbs' field has been deprecated. Please use 'size_in_gbs' instead. */
    public Optional<Output<String>> sizeInMbs() {
        return Optional.ofNullable(this.sizeInMbs);
    }

    /**
     * Specifies the volume source details for a new Block volume. The volume source is either another Block volume in the same Availability Domain or a Block volume backup. This is an optional field. If not specified or set to null, the new Block volume will be empty. When specified, the new Block volume will contain data from the source volume or backup.
     * 
     */
    @Import(name="sourceDetails")
    private @Nullable Output<VolumeSourceDetailsArgs> sourceDetails;

    /**
     * @return Specifies the volume source details for a new Block volume. The volume source is either another Block volume in the same Availability Domain or a Block volume backup. This is an optional field. If not specified or set to null, the new Block volume will be empty. When specified, the new Block volume will contain data from the source volume or backup.
     * 
     */
    public Optional<Output<VolumeSourceDetailsArgs>> sourceDetails() {
        return Optional.ofNullable(this.sourceDetails);
    }

    /**
     * The OCID of the volume backup from which the data should be restored on the newly created volume. This field is deprecated. Use the sourceDetails field instead to specify the backup for the volume.
     * 
     */
    @Import(name="volumeBackupId")
    private @Nullable Output<String> volumeBackupId;

    /**
     * @return The OCID of the volume backup from which the data should be restored on the newly created volume. This field is deprecated. Use the sourceDetails field instead to specify the backup for the volume.
     * 
     */
    public Optional<Output<String>> volumeBackupId() {
        return Optional.ofNullable(this.volumeBackupId);
    }

    /**
     * (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
     * 
     * Allowed values:
     * 
     */
    @Import(name="vpusPerGb")
    private @Nullable Output<String> vpusPerGb;

    /**
     * @return (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
     * 
     * Allowed values:
     * 
     */
    public Optional<Output<String>> vpusPerGb() {
        return Optional.ofNullable(this.vpusPerGb);
    }

    /**
     * The OCID of the Vault service key which is the master encryption key for the block volume cross region backups, which will be used in the destination region to encrypt the backup&#39;s encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="xrcKmsKeyId")
    private @Nullable Output<String> xrcKmsKeyId;

    /**
     * @return The OCID of the Vault service key which is the master encryption key for the block volume cross region backups, which will be used in the destination region to encrypt the backup&#39;s encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> xrcKmsKeyId() {
        return Optional.ofNullable(this.xrcKmsKeyId);
    }

    private VolumeArgs() {}

    private VolumeArgs(VolumeArgs $) {
        this.autotunePolicies = $.autotunePolicies;
        this.availabilityDomain = $.availabilityDomain;
        this.backupPolicyId = $.backupPolicyId;
        this.blockVolumeReplicas = $.blockVolumeReplicas;
        this.blockVolumeReplicasDeletion = $.blockVolumeReplicasDeletion;
        this.clusterPlacementGroupId = $.clusterPlacementGroupId;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isAutoTuneEnabled = $.isAutoTuneEnabled;
        this.isReservationsEnabled = $.isReservationsEnabled;
        this.kmsKeyId = $.kmsKeyId;
        this.sizeInGbs = $.sizeInGbs;
        this.sizeInMbs = $.sizeInMbs;
        this.sourceDetails = $.sourceDetails;
        this.volumeBackupId = $.volumeBackupId;
        this.vpusPerGb = $.vpusPerGb;
        this.xrcKmsKeyId = $.xrcKmsKeyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VolumeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VolumeArgs $;

        public Builder() {
            $ = new VolumeArgs();
        }

        public Builder(VolumeArgs defaults) {
            $ = new VolumeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autotunePolicies (Updatable) The list of autotune policies to be enabled for this volume.
         * 
         * @return builder
         * 
         */
        public Builder autotunePolicies(@Nullable Output<List<VolumeAutotunePolicyArgs>> autotunePolicies) {
            $.autotunePolicies = autotunePolicies;
            return this;
        }

        /**
         * @param autotunePolicies (Updatable) The list of autotune policies to be enabled for this volume.
         * 
         * @return builder
         * 
         */
        public Builder autotunePolicies(List<VolumeAutotunePolicyArgs> autotunePolicies) {
            return autotunePolicies(Output.of(autotunePolicies));
        }

        /**
         * @param autotunePolicies (Updatable) The list of autotune policies to be enabled for this volume.
         * 
         * @return builder
         * 
         */
        public Builder autotunePolicies(VolumeAutotunePolicyArgs... autotunePolicies) {
            return autotunePolicies(List.of(autotunePolicies));
        }

        /**
         * @param availabilityDomain The availability domain of the volume. Omissible for cloning a volume. The new volume will be created in the availability domain of the source volume.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The availability domain of the volume. Omissible for cloning a volume. The new volume will be created in the availability domain of the source volume.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param backupPolicyId If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned. This field is deprecated. Use the `oci.Core.getVolumeBackupPolicyAssignments` instead to assign a backup policy to a volume.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;backup_policy_id&#39; field has been deprecated. Please use the &#39;oci_core_volume_backup_policy_assignment&#39; resource instead.
         * 
         */
        @Deprecated /* The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead. */
        public Builder backupPolicyId(@Nullable Output<String> backupPolicyId) {
            $.backupPolicyId = backupPolicyId;
            return this;
        }

        /**
         * @param backupPolicyId If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned. This field is deprecated. Use the `oci.Core.getVolumeBackupPolicyAssignments` instead to assign a backup policy to a volume.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;backup_policy_id&#39; field has been deprecated. Please use the &#39;oci_core_volume_backup_policy_assignment&#39; resource instead.
         * 
         */
        @Deprecated /* The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead. */
        public Builder backupPolicyId(String backupPolicyId) {
            return backupPolicyId(Output.of(backupPolicyId));
        }

        /**
         * @param blockVolumeReplicas (Updatable) The list of block volume replicas to be enabled for this volume in the specified destination availability domains.
         * 
         * @return builder
         * 
         */
        public Builder blockVolumeReplicas(@Nullable Output<List<VolumeBlockVolumeReplicaArgs>> blockVolumeReplicas) {
            $.blockVolumeReplicas = blockVolumeReplicas;
            return this;
        }

        /**
         * @param blockVolumeReplicas (Updatable) The list of block volume replicas to be enabled for this volume in the specified destination availability domains.
         * 
         * @return builder
         * 
         */
        public Builder blockVolumeReplicas(List<VolumeBlockVolumeReplicaArgs> blockVolumeReplicas) {
            return blockVolumeReplicas(Output.of(blockVolumeReplicas));
        }

        /**
         * @param blockVolumeReplicas (Updatable) The list of block volume replicas to be enabled for this volume in the specified destination availability domains.
         * 
         * @return builder
         * 
         */
        public Builder blockVolumeReplicas(VolumeBlockVolumeReplicaArgs... blockVolumeReplicas) {
            return blockVolumeReplicas(List.of(blockVolumeReplicas));
        }

        public Builder blockVolumeReplicasDeletion(@Nullable Output<Boolean> blockVolumeReplicasDeletion) {
            $.blockVolumeReplicasDeletion = blockVolumeReplicasDeletion;
            return this;
        }

        public Builder blockVolumeReplicasDeletion(Boolean blockVolumeReplicasDeletion) {
            return blockVolumeReplicasDeletion(Output.of(blockVolumeReplicasDeletion));
        }

        /**
         * @param clusterPlacementGroupId The clusterPlacementGroup Id of the volume for volume placement.
         * 
         * @return builder
         * 
         */
        public Builder clusterPlacementGroupId(@Nullable Output<String> clusterPlacementGroupId) {
            $.clusterPlacementGroupId = clusterPlacementGroupId;
            return this;
        }

        /**
         * @param clusterPlacementGroupId The clusterPlacementGroup Id of the volume for volume placement.
         * 
         * @return builder
         * 
         */
        public Builder clusterPlacementGroupId(String clusterPlacementGroupId) {
            return clusterPlacementGroupId(Output.of(clusterPlacementGroupId));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains the volume.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains the volume.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
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
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isAutoTuneEnabled (Updatable) Specifies whether the auto-tune performance is enabled for this volume. This field is deprecated. Use the `DetachedVolumeAutotunePolicy` instead to enable the volume for detached autotune.
         * 
         * @return builder
         * 
         */
        public Builder isAutoTuneEnabled(@Nullable Output<Boolean> isAutoTuneEnabled) {
            $.isAutoTuneEnabled = isAutoTuneEnabled;
            return this;
        }

        /**
         * @param isAutoTuneEnabled (Updatable) Specifies whether the auto-tune performance is enabled for this volume. This field is deprecated. Use the `DetachedVolumeAutotunePolicy` instead to enable the volume for detached autotune.
         * 
         * @return builder
         * 
         */
        public Builder isAutoTuneEnabled(Boolean isAutoTuneEnabled) {
            return isAutoTuneEnabled(Output.of(isAutoTuneEnabled));
        }

        /**
         * @param isReservationsEnabled (Updatable) Reservations-enabled is a boolean field that allows to enable PR (Persistent Reservation) on a volume.
         * 
         * @return builder
         * 
         */
        public Builder isReservationsEnabled(@Nullable Output<Boolean> isReservationsEnabled) {
            $.isReservationsEnabled = isReservationsEnabled;
            return this;
        }

        /**
         * @param isReservationsEnabled (Updatable) Reservations-enabled is a boolean field that allows to enable PR (Persistent Reservation) on a volume.
         * 
         * @return builder
         * 
         */
        public Builder isReservationsEnabled(Boolean isReservationsEnabled) {
            return isReservationsEnabled(Output.of(isReservationsEnabled));
        }

        /**
         * @param kmsKeyId (Updatable) The OCID of the Vault service key to assign as the master encryption key for the volume.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(@Nullable Output<String> kmsKeyId) {
            $.kmsKeyId = kmsKeyId;
            return this;
        }

        /**
         * @param kmsKeyId (Updatable) The OCID of the Vault service key to assign as the master encryption key for the volume.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(String kmsKeyId) {
            return kmsKeyId(Output.of(kmsKeyId));
        }

        /**
         * @param sizeInGbs (Updatable) The size of the volume in GBs.
         * 
         * @return builder
         * 
         */
        public Builder sizeInGbs(@Nullable Output<String> sizeInGbs) {
            $.sizeInGbs = sizeInGbs;
            return this;
        }

        /**
         * @param sizeInGbs (Updatable) The size of the volume in GBs.
         * 
         * @return builder
         * 
         */
        public Builder sizeInGbs(String sizeInGbs) {
            return sizeInGbs(Output.of(sizeInGbs));
        }

        /**
         * @param sizeInMbs The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Use sizeInGBs instead.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;size_in_mbs&#39; field has been deprecated. Please use &#39;size_in_gbs&#39; instead.
         * 
         */
        @Deprecated /* The 'size_in_mbs' field has been deprecated. Please use 'size_in_gbs' instead. */
        public Builder sizeInMbs(@Nullable Output<String> sizeInMbs) {
            $.sizeInMbs = sizeInMbs;
            return this;
        }

        /**
         * @param sizeInMbs The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Use sizeInGBs instead.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;size_in_mbs&#39; field has been deprecated. Please use &#39;size_in_gbs&#39; instead.
         * 
         */
        @Deprecated /* The 'size_in_mbs' field has been deprecated. Please use 'size_in_gbs' instead. */
        public Builder sizeInMbs(String sizeInMbs) {
            return sizeInMbs(Output.of(sizeInMbs));
        }

        /**
         * @param sourceDetails Specifies the volume source details for a new Block volume. The volume source is either another Block volume in the same Availability Domain or a Block volume backup. This is an optional field. If not specified or set to null, the new Block volume will be empty. When specified, the new Block volume will contain data from the source volume or backup.
         * 
         * @return builder
         * 
         */
        public Builder sourceDetails(@Nullable Output<VolumeSourceDetailsArgs> sourceDetails) {
            $.sourceDetails = sourceDetails;
            return this;
        }

        /**
         * @param sourceDetails Specifies the volume source details for a new Block volume. The volume source is either another Block volume in the same Availability Domain or a Block volume backup. This is an optional field. If not specified or set to null, the new Block volume will be empty. When specified, the new Block volume will contain data from the source volume or backup.
         * 
         * @return builder
         * 
         */
        public Builder sourceDetails(VolumeSourceDetailsArgs sourceDetails) {
            return sourceDetails(Output.of(sourceDetails));
        }

        /**
         * @param volumeBackupId The OCID of the volume backup from which the data should be restored on the newly created volume. This field is deprecated. Use the sourceDetails field instead to specify the backup for the volume.
         * 
         * @return builder
         * 
         */
        public Builder volumeBackupId(@Nullable Output<String> volumeBackupId) {
            $.volumeBackupId = volumeBackupId;
            return this;
        }

        /**
         * @param volumeBackupId The OCID of the volume backup from which the data should be restored on the newly created volume. This field is deprecated. Use the sourceDetails field instead to specify the backup for the volume.
         * 
         * @return builder
         * 
         */
        public Builder volumeBackupId(String volumeBackupId) {
            return volumeBackupId(Output.of(volumeBackupId));
        }

        /**
         * @param vpusPerGb (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
         * 
         * Allowed values:
         * 
         * @return builder
         * 
         */
        public Builder vpusPerGb(@Nullable Output<String> vpusPerGb) {
            $.vpusPerGb = vpusPerGb;
            return this;
        }

        /**
         * @param vpusPerGb (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
         * 
         * Allowed values:
         * 
         * @return builder
         * 
         */
        public Builder vpusPerGb(String vpusPerGb) {
            return vpusPerGb(Output.of(vpusPerGb));
        }

        /**
         * @param xrcKmsKeyId The OCID of the Vault service key which is the master encryption key for the block volume cross region backups, which will be used in the destination region to encrypt the backup&#39;s encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
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
         * @param xrcKmsKeyId The OCID of the Vault service key which is the master encryption key for the block volume cross region backups, which will be used in the destination region to encrypt the backup&#39;s encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
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

        public VolumeArgs build() {
            if ($.availabilityDomain == null) {
                throw new MissingRequiredPropertyException("VolumeArgs", "availabilityDomain");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("VolumeArgs", "compartmentId");
            }
            return $;
        }
    }

}
