// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FusionApps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FusionApps.inputs.FusionEnvironmentFamilyFamilyMaintenancePolicyArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FusionEnvironmentFamilyArgs extends com.pulumi.resources.ResourceArgs {

    public static final FusionEnvironmentFamilyArgs Empty = new FusionEnvironmentFamilyArgs();

    /**
     * (Updatable) The OCID of the compartment where the environment family is located.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment where the environment family is located.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
     * 
     */
    @Import(name="familyMaintenancePolicy")
    private @Nullable Output<FusionEnvironmentFamilyFamilyMaintenancePolicyArgs> familyMaintenancePolicy;

    /**
     * @return (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
     * 
     */
    public Optional<Output<FusionEnvironmentFamilyFamilyMaintenancePolicyArgs>> familyMaintenancePolicy() {
        return Optional.ofNullable(this.familyMaintenancePolicy);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="subscriptionIds", required=true)
    private Output<List<String>> subscriptionIds;

    /**
     * @return (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<List<String>> subscriptionIds() {
        return this.subscriptionIds;
    }

    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private FusionEnvironmentFamilyArgs() {}

    private FusionEnvironmentFamilyArgs(FusionEnvironmentFamilyArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.familyMaintenancePolicy = $.familyMaintenancePolicy;
        this.freeformTags = $.freeformTags;
        this.subscriptionIds = $.subscriptionIds;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FusionEnvironmentFamilyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FusionEnvironmentFamilyArgs $;

        public Builder() {
            $ = new FusionEnvironmentFamilyArgs();
        }

        public Builder(FusionEnvironmentFamilyArgs defaults) {
            $ = new FusionEnvironmentFamilyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment where the environment family is located.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment where the environment family is located.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param familyMaintenancePolicy (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
         * 
         * @return builder
         * 
         */
        public Builder familyMaintenancePolicy(@Nullable Output<FusionEnvironmentFamilyFamilyMaintenancePolicyArgs> familyMaintenancePolicy) {
            $.familyMaintenancePolicy = familyMaintenancePolicy;
            return this;
        }

        /**
         * @param familyMaintenancePolicy (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
         * 
         * @return builder
         * 
         */
        public Builder familyMaintenancePolicy(FusionEnvironmentFamilyFamilyMaintenancePolicyArgs familyMaintenancePolicy) {
            return familyMaintenancePolicy(Output.of(familyMaintenancePolicy));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param subscriptionIds (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subscriptionIds(Output<List<String>> subscriptionIds) {
            $.subscriptionIds = subscriptionIds;
            return this;
        }

        /**
         * @param subscriptionIds (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subscriptionIds(List<String> subscriptionIds) {
            return subscriptionIds(Output.of(subscriptionIds));
        }

        /**
         * @param subscriptionIds (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subscriptionIds(String... subscriptionIds) {
            return subscriptionIds(List.of(subscriptionIds));
        }

        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public FusionEnvironmentFamilyArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("FusionEnvironmentFamilyArgs", "compartmentId");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("FusionEnvironmentFamilyArgs", "displayName");
            }
            if ($.subscriptionIds == null) {
                throw new MissingRequiredPropertyException("FusionEnvironmentFamilyArgs", "subscriptionIds");
            }
            return $;
        }
    }

}
