// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsAutotunePolicyArgs;
import com.pulumi.oci.Core.inputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetailsArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs Empty = new InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs();

    /**
     * The list of autotune policies enabled for this volume.
     * 
     */
    @Import(name="autotunePolicies")
    private @Nullable Output<List<InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsAutotunePolicyArgs>> autotunePolicies;

    /**
     * @return The list of autotune policies enabled for this volume.
     * 
     */
    public Optional<Output<List<InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsAutotunePolicyArgs>>> autotunePolicies() {
        return Optional.ofNullable(this.autotunePolicies);
    }

    /**
     * The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned.
     * 
     */
    @Import(name="backupPolicyId")
    private @Nullable Output<String> backupPolicyId;

    /**
     * @return If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned.
     * 
     */
    public Optional<Output<String>> backupPolicyId() {
        return Optional.ofNullable(this.backupPolicyId);
    }

    /**
     * The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The OCID of the Key Management key to assign as the master encryption key for the volume.
     * 
     */
    @Import(name="kmsKeyId")
    private @Nullable Output<String> kmsKeyId;

    /**
     * @return The OCID of the Key Management key to assign as the master encryption key for the volume.
     * 
     */
    public Optional<Output<String>> kmsKeyId() {
        return Optional.ofNullable(this.kmsKeyId);
    }

    /**
     * The size of the volume in GBs.
     * 
     */
    @Import(name="sizeInGbs")
    private @Nullable Output<String> sizeInGbs;

    /**
     * @return The size of the volume in GBs.
     * 
     */
    public Optional<Output<String>> sizeInGbs() {
        return Optional.ofNullable(this.sizeInGbs);
    }

    @Import(name="sourceDetails")
    private @Nullable Output<InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetailsArgs> sourceDetails;

    public Optional<Output<InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetailsArgs>> sourceDetails() {
        return Optional.ofNullable(this.sourceDetails);
    }

    /**
     * The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
     * 
     */
    @Import(name="vpusPerGb")
    private @Nullable Output<String> vpusPerGb;

    /**
     * @return The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
     * 
     */
    public Optional<Output<String>> vpusPerGb() {
        return Optional.ofNullable(this.vpusPerGb);
    }

    private InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs() {}

    private InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs(InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs $) {
        this.autotunePolicies = $.autotunePolicies;
        this.availabilityDomain = $.availabilityDomain;
        this.backupPolicyId = $.backupPolicyId;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.kmsKeyId = $.kmsKeyId;
        this.sizeInGbs = $.sizeInGbs;
        this.sourceDetails = $.sourceDetails;
        this.vpusPerGb = $.vpusPerGb;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs $;

        public Builder() {
            $ = new InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs();
        }

        public Builder(InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs defaults) {
            $ = new InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autotunePolicies The list of autotune policies enabled for this volume.
         * 
         * @return builder
         * 
         */
        public Builder autotunePolicies(@Nullable Output<List<InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsAutotunePolicyArgs>> autotunePolicies) {
            $.autotunePolicies = autotunePolicies;
            return this;
        }

        /**
         * @param autotunePolicies The list of autotune policies enabled for this volume.
         * 
         * @return builder
         * 
         */
        public Builder autotunePolicies(List<InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsAutotunePolicyArgs> autotunePolicies) {
            return autotunePolicies(Output.of(autotunePolicies));
        }

        /**
         * @param autotunePolicies The list of autotune policies enabled for this volume.
         * 
         * @return builder
         * 
         */
        public Builder autotunePolicies(InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsAutotunePolicyArgs... autotunePolicies) {
            return autotunePolicies(List.of(autotunePolicies));
        }

        /**
         * @param availabilityDomain The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param backupPolicyId If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned.
         * 
         * @return builder
         * 
         */
        public Builder backupPolicyId(@Nullable Output<String> backupPolicyId) {
            $.backupPolicyId = backupPolicyId;
            return this;
        }

        /**
         * @param backupPolicyId If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned.
         * 
         * @return builder
         * 
         */
        public Builder backupPolicyId(String backupPolicyId) {
            return backupPolicyId(Output.of(backupPolicyId));
        }

        /**
         * @param compartmentId The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param kmsKeyId The OCID of the Key Management key to assign as the master encryption key for the volume.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(@Nullable Output<String> kmsKeyId) {
            $.kmsKeyId = kmsKeyId;
            return this;
        }

        /**
         * @param kmsKeyId The OCID of the Key Management key to assign as the master encryption key for the volume.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(String kmsKeyId) {
            return kmsKeyId(Output.of(kmsKeyId));
        }

        /**
         * @param sizeInGbs The size of the volume in GBs.
         * 
         * @return builder
         * 
         */
        public Builder sizeInGbs(@Nullable Output<String> sizeInGbs) {
            $.sizeInGbs = sizeInGbs;
            return this;
        }

        /**
         * @param sizeInGbs The size of the volume in GBs.
         * 
         * @return builder
         * 
         */
        public Builder sizeInGbs(String sizeInGbs) {
            return sizeInGbs(Output.of(sizeInGbs));
        }

        public Builder sourceDetails(@Nullable Output<InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetailsArgs> sourceDetails) {
            $.sourceDetails = sourceDetails;
            return this;
        }

        public Builder sourceDetails(InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetailsArgs sourceDetails) {
            return sourceDetails(Output.of(sourceDetails));
        }

        /**
         * @param vpusPerGb The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
         * 
         * @return builder
         * 
         */
        public Builder vpusPerGb(@Nullable Output<String> vpusPerGb) {
            $.vpusPerGb = vpusPerGb;
            return this;
        }

        /**
         * @param vpusPerGb The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
         * 
         * @return builder
         * 
         */
        public Builder vpusPerGb(String vpusPerGb) {
            return vpusPerGb(Output.of(vpusPerGb));
        }

        public InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs build() {
            return $;
        }
    }

}