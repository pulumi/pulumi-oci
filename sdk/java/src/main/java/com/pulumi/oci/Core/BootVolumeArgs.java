// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.BootVolumeAutotunePolicyArgs;
import com.pulumi.oci.Core.inputs.BootVolumeBootVolumeReplicaArgs;
import com.pulumi.oci.Core.inputs.BootVolumeSourceDetailsArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BootVolumeArgs extends com.pulumi.resources.ResourceArgs {

    public static final BootVolumeArgs Empty = new BootVolumeArgs();

    /**
     * (Updatable) The list of autotune policies to be enabled for this volume.
     * 
     */
    @Import(name="autotunePolicies")
    private @Nullable Output<List<BootVolumeAutotunePolicyArgs>> autotunePolicies;

    /**
     * @return (Updatable) The list of autotune policies to be enabled for this volume.
     * 
     */
    public Optional<Output<List<BootVolumeAutotunePolicyArgs>>> autotunePolicies() {
        return Optional.ofNullable(this.autotunePolicies);
    }

    /**
     * (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * If provided, specifies the ID of the boot volume backup policy to assign to the newly created boot volume. If omitted, no policy will be assigned.
     * 
     * @deprecated
     * The &#39;backup_policy_id&#39; field has been deprecated. Please use the &#39;oci_core_volume_backup_policy_assignment&#39; resource instead.
     * 
     */
    @Deprecated /* The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead. */
    @Import(name="backupPolicyId")
    private @Nullable Output<String> backupPolicyId;

    /**
     * @return If provided, specifies the ID of the boot volume backup policy to assign to the newly created boot volume. If omitted, no policy will be assigned.
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
     * (Updatable) The list of boot volume replicas to be enabled for this boot volume in the specified destination availability domains.
     * 
     */
    @Import(name="bootVolumeReplicas")
    private @Nullable Output<List<BootVolumeBootVolumeReplicaArgs>> bootVolumeReplicas;

    /**
     * @return (Updatable) The list of boot volume replicas to be enabled for this boot volume in the specified destination availability domains.
     * 
     */
    public Optional<Output<List<BootVolumeBootVolumeReplicaArgs>>> bootVolumeReplicas() {
        return Optional.ofNullable(this.bootVolumeReplicas);
    }

    @Import(name="bootVolumeReplicasDeletion")
    private @Nullable Output<Boolean> bootVolumeReplicasDeletion;

    public Optional<Output<Boolean>> bootVolumeReplicasDeletion() {
        return Optional.ofNullable(this.bootVolumeReplicasDeletion);
    }

    /**
     * (Updatable) The OCID of the compartment that contains the boot volume.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains the boot volume.
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
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
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
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Specifies whether the auto-tune performance is enabled for this boot volume. This field is deprecated. Use the `DetachedVolumeAutotunePolicy` instead to enable the volume for detached autotune.
     * 
     */
    @Import(name="isAutoTuneEnabled")
    private @Nullable Output<Boolean> isAutoTuneEnabled;

    /**
     * @return (Updatable) Specifies whether the auto-tune performance is enabled for this boot volume. This field is deprecated. Use the `DetachedVolumeAutotunePolicy` instead to enable the volume for detached autotune.
     * 
     */
    public Optional<Output<Boolean>> isAutoTuneEnabled() {
        return Optional.ofNullable(this.isAutoTuneEnabled);
    }

    /**
     * (Updatable) The OCID of the Key Management key to assign as the master encryption key for the boot volume.
     * 
     */
    @Import(name="kmsKeyId")
    private @Nullable Output<String> kmsKeyId;

    /**
     * @return (Updatable) The OCID of the Key Management key to assign as the master encryption key for the boot volume.
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

    @Import(name="sourceDetails", required=true)
    private Output<BootVolumeSourceDetailsArgs> sourceDetails;

    public Output<BootVolumeSourceDetailsArgs> sourceDetails() {
        return this.sourceDetails;
    }

    /**
     * (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
     * 
     */
    @Import(name="vpusPerGb")
    private @Nullable Output<String> vpusPerGb;

    /**
     * @return (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
     * 
     */
    public Optional<Output<String>> vpusPerGb() {
        return Optional.ofNullable(this.vpusPerGb);
    }

    private BootVolumeArgs() {}

    private BootVolumeArgs(BootVolumeArgs $) {
        this.autotunePolicies = $.autotunePolicies;
        this.availabilityDomain = $.availabilityDomain;
        this.backupPolicyId = $.backupPolicyId;
        this.bootVolumeReplicas = $.bootVolumeReplicas;
        this.bootVolumeReplicasDeletion = $.bootVolumeReplicasDeletion;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isAutoTuneEnabled = $.isAutoTuneEnabled;
        this.kmsKeyId = $.kmsKeyId;
        this.sizeInGbs = $.sizeInGbs;
        this.sourceDetails = $.sourceDetails;
        this.vpusPerGb = $.vpusPerGb;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BootVolumeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BootVolumeArgs $;

        public Builder() {
            $ = new BootVolumeArgs();
        }

        public Builder(BootVolumeArgs defaults) {
            $ = new BootVolumeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autotunePolicies (Updatable) The list of autotune policies to be enabled for this volume.
         * 
         * @return builder
         * 
         */
        public Builder autotunePolicies(@Nullable Output<List<BootVolumeAutotunePolicyArgs>> autotunePolicies) {
            $.autotunePolicies = autotunePolicies;
            return this;
        }

        /**
         * @param autotunePolicies (Updatable) The list of autotune policies to be enabled for this volume.
         * 
         * @return builder
         * 
         */
        public Builder autotunePolicies(List<BootVolumeAutotunePolicyArgs> autotunePolicies) {
            return autotunePolicies(Output.of(autotunePolicies));
        }

        /**
         * @param autotunePolicies (Updatable) The list of autotune policies to be enabled for this volume.
         * 
         * @return builder
         * 
         */
        public Builder autotunePolicies(BootVolumeAutotunePolicyArgs... autotunePolicies) {
            return autotunePolicies(List.of(autotunePolicies));
        }

        /**
         * @param availabilityDomain (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param backupPolicyId If provided, specifies the ID of the boot volume backup policy to assign to the newly created boot volume. If omitted, no policy will be assigned.
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
         * @param backupPolicyId If provided, specifies the ID of the boot volume backup policy to assign to the newly created boot volume. If omitted, no policy will be assigned.
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
         * @param bootVolumeReplicas (Updatable) The list of boot volume replicas to be enabled for this boot volume in the specified destination availability domains.
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeReplicas(@Nullable Output<List<BootVolumeBootVolumeReplicaArgs>> bootVolumeReplicas) {
            $.bootVolumeReplicas = bootVolumeReplicas;
            return this;
        }

        /**
         * @param bootVolumeReplicas (Updatable) The list of boot volume replicas to be enabled for this boot volume in the specified destination availability domains.
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeReplicas(List<BootVolumeBootVolumeReplicaArgs> bootVolumeReplicas) {
            return bootVolumeReplicas(Output.of(bootVolumeReplicas));
        }

        /**
         * @param bootVolumeReplicas (Updatable) The list of boot volume replicas to be enabled for this boot volume in the specified destination availability domains.
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeReplicas(BootVolumeBootVolumeReplicaArgs... bootVolumeReplicas) {
            return bootVolumeReplicas(List.of(bootVolumeReplicas));
        }

        public Builder bootVolumeReplicasDeletion(@Nullable Output<Boolean> bootVolumeReplicasDeletion) {
            $.bootVolumeReplicasDeletion = bootVolumeReplicasDeletion;
            return this;
        }

        public Builder bootVolumeReplicasDeletion(Boolean bootVolumeReplicasDeletion) {
            return bootVolumeReplicasDeletion(Output.of(bootVolumeReplicasDeletion));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains the boot volume.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains the boot volume.
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
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
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
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isAutoTuneEnabled (Updatable) Specifies whether the auto-tune performance is enabled for this boot volume. This field is deprecated. Use the `DetachedVolumeAutotunePolicy` instead to enable the volume for detached autotune.
         * 
         * @return builder
         * 
         */
        public Builder isAutoTuneEnabled(@Nullable Output<Boolean> isAutoTuneEnabled) {
            $.isAutoTuneEnabled = isAutoTuneEnabled;
            return this;
        }

        /**
         * @param isAutoTuneEnabled (Updatable) Specifies whether the auto-tune performance is enabled for this boot volume. This field is deprecated. Use the `DetachedVolumeAutotunePolicy` instead to enable the volume for detached autotune.
         * 
         * @return builder
         * 
         */
        public Builder isAutoTuneEnabled(Boolean isAutoTuneEnabled) {
            return isAutoTuneEnabled(Output.of(isAutoTuneEnabled));
        }

        /**
         * @param kmsKeyId (Updatable) The OCID of the Key Management key to assign as the master encryption key for the boot volume.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(@Nullable Output<String> kmsKeyId) {
            $.kmsKeyId = kmsKeyId;
            return this;
        }

        /**
         * @param kmsKeyId (Updatable) The OCID of the Key Management key to assign as the master encryption key for the boot volume.
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

        public Builder sourceDetails(Output<BootVolumeSourceDetailsArgs> sourceDetails) {
            $.sourceDetails = sourceDetails;
            return this;
        }

        public Builder sourceDetails(BootVolumeSourceDetailsArgs sourceDetails) {
            return sourceDetails(Output.of(sourceDetails));
        }

        /**
         * @param vpusPerGb (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
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
         * @return builder
         * 
         */
        public Builder vpusPerGb(String vpusPerGb) {
            return vpusPerGb(Output.of(vpusPerGb));
        }

        public BootVolumeArgs build() {
            $.availabilityDomain = Objects.requireNonNull($.availabilityDomain, "expected parameter 'availabilityDomain' to be non-null");
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.sourceDetails = Objects.requireNonNull($.sourceDetails, "expected parameter 'sourceDetails' to be non-null");
            return $;
        }
    }

}