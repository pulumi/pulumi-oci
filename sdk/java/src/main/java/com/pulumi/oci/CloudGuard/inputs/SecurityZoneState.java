// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SecurityZoneState extends com.pulumi.resources.ResourceArgs {

    public static final SecurityZoneState Empty = new SecurityZoneState();

    /**
     * (Updatable) The OCID of the compartment for the security zone
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment for the security zone
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The security zone&#39;s description
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) The security zone&#39;s description
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) The security zone&#39;s name
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The security zone&#39;s name
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * List of inherited compartments
     * 
     */
    @Import(name="inheritedByCompartments")
    private @Nullable Output<List<String>> inheritedByCompartments;

    /**
     * @return List of inherited compartments
     * 
     */
    public Optional<Output<List<String>>> inheritedByCompartments() {
        return Optional.ofNullable(this.inheritedByCompartments);
    }

    /**
     * A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * (Updatable) The OCID of the recipe (`SecurityRecipe`) for the security zone
     * 
     */
    @Import(name="securityZoneRecipeId")
    private @Nullable Output<String> securityZoneRecipeId;

    /**
     * @return (Updatable) The OCID of the recipe (`SecurityRecipe`) for the security zone
     * 
     */
    public Optional<Output<String>> securityZoneRecipeId() {
        return Optional.ofNullable(this.securityZoneRecipeId);
    }

    /**
     * The OCID of the target associated with the security zone
     * 
     */
    @Import(name="securityZoneTargetId")
    private @Nullable Output<String> securityZoneTargetId;

    /**
     * @return The OCID of the target associated with the security zone
     * 
     */
    public Optional<Output<String>> securityZoneTargetId() {
        return Optional.ofNullable(this.securityZoneTargetId);
    }

    /**
     * The current state of the security zone
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the security zone
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,Object>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The time the security zone was created. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the security zone was created. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the security zone was last updated. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the security zone was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private SecurityZoneState() {}

    private SecurityZoneState(SecurityZoneState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.inheritedByCompartments = $.inheritedByCompartments;
        this.lifecycleDetails = $.lifecycleDetails;
        this.securityZoneRecipeId = $.securityZoneRecipeId;
        this.securityZoneTargetId = $.securityZoneTargetId;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SecurityZoneState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SecurityZoneState $;

        public Builder() {
            $ = new SecurityZoneState();
        }

        public Builder(SecurityZoneState defaults) {
            $ = new SecurityZoneState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment for the security zone
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment for the security zone
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
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) The security zone&#39;s description
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) The security zone&#39;s description
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) The security zone&#39;s name
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The security zone&#39;s name
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param inheritedByCompartments List of inherited compartments
         * 
         * @return builder
         * 
         */
        public Builder inheritedByCompartments(@Nullable Output<List<String>> inheritedByCompartments) {
            $.inheritedByCompartments = inheritedByCompartments;
            return this;
        }

        /**
         * @param inheritedByCompartments List of inherited compartments
         * 
         * @return builder
         * 
         */
        public Builder inheritedByCompartments(List<String> inheritedByCompartments) {
            return inheritedByCompartments(Output.of(inheritedByCompartments));
        }

        /**
         * @param inheritedByCompartments List of inherited compartments
         * 
         * @return builder
         * 
         */
        public Builder inheritedByCompartments(String... inheritedByCompartments) {
            return inheritedByCompartments(List.of(inheritedByCompartments));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param securityZoneRecipeId (Updatable) The OCID of the recipe (`SecurityRecipe`) for the security zone
         * 
         * @return builder
         * 
         */
        public Builder securityZoneRecipeId(@Nullable Output<String> securityZoneRecipeId) {
            $.securityZoneRecipeId = securityZoneRecipeId;
            return this;
        }

        /**
         * @param securityZoneRecipeId (Updatable) The OCID of the recipe (`SecurityRecipe`) for the security zone
         * 
         * @return builder
         * 
         */
        public Builder securityZoneRecipeId(String securityZoneRecipeId) {
            return securityZoneRecipeId(Output.of(securityZoneRecipeId));
        }

        /**
         * @param securityZoneTargetId The OCID of the target associated with the security zone
         * 
         * @return builder
         * 
         */
        public Builder securityZoneTargetId(@Nullable Output<String> securityZoneTargetId) {
            $.securityZoneTargetId = securityZoneTargetId;
            return this;
        }

        /**
         * @param securityZoneTargetId The OCID of the target associated with the security zone
         * 
         * @return builder
         * 
         */
        public Builder securityZoneTargetId(String securityZoneTargetId) {
            return securityZoneTargetId(Output.of(securityZoneTargetId));
        }

        /**
         * @param state The current state of the security zone
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the security zone
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,Object>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,Object> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The time the security zone was created. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the security zone was created. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the security zone was last updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the security zone was last updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public SecurityZoneState build() {
            return $;
        }
    }

}