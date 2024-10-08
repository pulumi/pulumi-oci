// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Optimizer.inputs.ProfileLevelsConfigurationArgs;
import com.pulumi.oci.Optimizer.inputs.ProfileTargetCompartmentsArgs;
import com.pulumi.oci.Optimizer.inputs.ProfileTargetTagsArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ProfileState extends com.pulumi.resources.ResourceArgs {

    public static final ProfileState Empty = new ProfileState();

    /**
     * (Updatable) The time period over which to collect data for the recommendations, measured in number of days.
     * 
     */
    @Import(name="aggregationIntervalInDays")
    private @Nullable Output<Integer> aggregationIntervalInDays;

    /**
     * @return (Updatable) The time period over which to collect data for the recommendations, measured in number of days.
     * 
     */
    public Optional<Output<Integer>> aggregationIntervalInDays() {
        return Optional.ofNullable(this.aggregationIntervalInDays);
    }

    /**
     * The OCID of the tenancy. The tenancy is the root compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the tenancy. The tenancy is the root compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Text describing the profile. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Text describing the profile. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Simple key-value pair applied without any predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Exists for cross-compatibility only.  Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair applied without any predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Exists for cross-compatibility only.  Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) A list of configuration levels for each recommendation.
     * 
     */
    @Import(name="levelsConfiguration")
    private @Nullable Output<ProfileLevelsConfigurationArgs> levelsConfiguration;

    /**
     * @return (Updatable) A list of configuration levels for each recommendation.
     * 
     */
    public Optional<Output<ProfileLevelsConfigurationArgs>> levelsConfiguration() {
        return Optional.ofNullable(this.levelsConfiguration);
    }

    /**
     * (Updatable) The name assigned to the profile. Avoid entering confidential information.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) The name assigned to the profile. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The profile&#39;s current state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The profile&#39;s current state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * (Updatable) Optional. The compartments specified in the profile override for a recommendation.
     * 
     */
    @Import(name="targetCompartments")
    private @Nullable Output<ProfileTargetCompartmentsArgs> targetCompartments;

    /**
     * @return (Updatable) Optional. The compartments specified in the profile override for a recommendation.
     * 
     */
    public Optional<Output<ProfileTargetCompartmentsArgs>> targetCompartments() {
        return Optional.ofNullable(this.targetCompartments);
    }

    /**
     * (Updatable) Optional. The tags specified in the profile override for a recommendation.
     * 
     */
    @Import(name="targetTags")
    private @Nullable Output<ProfileTargetTagsArgs> targetTags;

    /**
     * @return (Updatable) Optional. The tags specified in the profile override for a recommendation.
     * 
     */
    public Optional<Output<ProfileTargetTagsArgs>> targetTags() {
        return Optional.ofNullable(this.targetTags);
    }

    /**
     * The date and time the profile was created, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the profile was created, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the profile was last updated, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the profile was last updated, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private ProfileState() {}

    private ProfileState(ProfileState $) {
        this.aggregationIntervalInDays = $.aggregationIntervalInDays;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.freeformTags = $.freeformTags;
        this.levelsConfiguration = $.levelsConfiguration;
        this.name = $.name;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.targetCompartments = $.targetCompartments;
        this.targetTags = $.targetTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ProfileState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ProfileState $;

        public Builder() {
            $ = new ProfileState();
        }

        public Builder(ProfileState defaults) {
            $ = new ProfileState(Objects.requireNonNull(defaults));
        }

        /**
         * @param aggregationIntervalInDays (Updatable) The time period over which to collect data for the recommendations, measured in number of days.
         * 
         * @return builder
         * 
         */
        public Builder aggregationIntervalInDays(@Nullable Output<Integer> aggregationIntervalInDays) {
            $.aggregationIntervalInDays = aggregationIntervalInDays;
            return this;
        }

        /**
         * @param aggregationIntervalInDays (Updatable) The time period over which to collect data for the recommendations, measured in number of days.
         * 
         * @return builder
         * 
         */
        public Builder aggregationIntervalInDays(Integer aggregationIntervalInDays) {
            return aggregationIntervalInDays(Output.of(aggregationIntervalInDays));
        }

        /**
         * @param compartmentId The OCID of the tenancy. The tenancy is the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the tenancy. The tenancy is the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) Text describing the profile. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Text describing the profile. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair applied without any predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Exists for cross-compatibility only.  Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair applied without any predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Exists for cross-compatibility only.  Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param levelsConfiguration (Updatable) A list of configuration levels for each recommendation.
         * 
         * @return builder
         * 
         */
        public Builder levelsConfiguration(@Nullable Output<ProfileLevelsConfigurationArgs> levelsConfiguration) {
            $.levelsConfiguration = levelsConfiguration;
            return this;
        }

        /**
         * @param levelsConfiguration (Updatable) A list of configuration levels for each recommendation.
         * 
         * @return builder
         * 
         */
        public Builder levelsConfiguration(ProfileLevelsConfigurationArgs levelsConfiguration) {
            return levelsConfiguration(Output.of(levelsConfiguration));
        }

        /**
         * @param name (Updatable) The name assigned to the profile. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The name assigned to the profile. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param state The profile&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The profile&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param targetCompartments (Updatable) Optional. The compartments specified in the profile override for a recommendation.
         * 
         * @return builder
         * 
         */
        public Builder targetCompartments(@Nullable Output<ProfileTargetCompartmentsArgs> targetCompartments) {
            $.targetCompartments = targetCompartments;
            return this;
        }

        /**
         * @param targetCompartments (Updatable) Optional. The compartments specified in the profile override for a recommendation.
         * 
         * @return builder
         * 
         */
        public Builder targetCompartments(ProfileTargetCompartmentsArgs targetCompartments) {
            return targetCompartments(Output.of(targetCompartments));
        }

        /**
         * @param targetTags (Updatable) Optional. The tags specified in the profile override for a recommendation.
         * 
         * @return builder
         * 
         */
        public Builder targetTags(@Nullable Output<ProfileTargetTagsArgs> targetTags) {
            $.targetTags = targetTags;
            return this;
        }

        /**
         * @param targetTags (Updatable) Optional. The tags specified in the profile override for a recommendation.
         * 
         * @return builder
         * 
         */
        public Builder targetTags(ProfileTargetTagsArgs targetTags) {
            return targetTags(Output.of(targetTags));
        }

        /**
         * @param timeCreated The date and time the profile was created, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the profile was created, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the profile was last updated, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the profile was last updated, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public ProfileState build() {
            return $;
        }
    }

}
