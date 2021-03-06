// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudGuard.inputs.TargetTargetDetectorRecipeArgs;
import com.pulumi.oci.CloudGuard.inputs.TargetTargetResponderRecipeArgs;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TargetState extends com.pulumi.resources.ResourceArgs {

    public static final TargetState Empty = new TargetState();

    /**
     * (Updatable) compartment associated with condition
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) compartment associated with condition
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
     * The target description.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return The target description.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) DetectorTemplate Identifier
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) DetectorTemplate Identifier
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
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Import(name="lifecyleDetails")
    private @Nullable Output<String> lifecyleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Optional<Output<String>> lifecyleDetails() {
        return Optional.ofNullable(this.lifecyleDetails);
    }

    /**
     * Total number of recipes attached to target
     * 
     */
    @Import(name="recipeCount")
    private @Nullable Output<Integer> recipeCount;

    /**
     * @return Total number of recipes attached to target
     * 
     */
    public Optional<Output<Integer>> recipeCount() {
        return Optional.ofNullable(this.recipeCount);
    }

    /**
     * (Updatable) The current state of the DetectorRule.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return (Updatable) The current state of the DetectorRule.
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
     * (Updatable) List of detector recipes to associate with target
     * 
     */
    @Import(name="targetDetectorRecipes")
    private @Nullable Output<List<TargetTargetDetectorRecipeArgs>> targetDetectorRecipes;

    /**
     * @return (Updatable) List of detector recipes to associate with target
     * 
     */
    public Optional<Output<List<TargetTargetDetectorRecipeArgs>>> targetDetectorRecipes() {
        return Optional.ofNullable(this.targetDetectorRecipes);
    }

    /**
     * Resource ID which the target uses to monitor
     * 
     */
    @Import(name="targetResourceId")
    private @Nullable Output<String> targetResourceId;

    /**
     * @return Resource ID which the target uses to monitor
     * 
     */
    public Optional<Output<String>> targetResourceId() {
        return Optional.ofNullable(this.targetResourceId);
    }

    /**
     * possible type of targets(compartment/HCMCloud/ERPCloud)
     * 
     */
    @Import(name="targetResourceType")
    private @Nullable Output<String> targetResourceType;

    /**
     * @return possible type of targets(compartment/HCMCloud/ERPCloud)
     * 
     */
    public Optional<Output<String>> targetResourceType() {
        return Optional.ofNullable(this.targetResourceType);
    }

    /**
     * (Updatable) List of responder recipes to associate with target
     * 
     */
    @Import(name="targetResponderRecipes")
    private @Nullable Output<List<TargetTargetResponderRecipeArgs>> targetResponderRecipes;

    /**
     * @return (Updatable) List of responder recipes to associate with target
     * 
     */
    public Optional<Output<List<TargetTargetResponderRecipeArgs>>> targetResponderRecipes() {
        return Optional.ofNullable(this.targetResponderRecipes);
    }

    /**
     * The date and time the target was created. Format defined by RFC3339.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the target was updated. Format defined by RFC3339.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the target was updated. Format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private TargetState() {}

    private TargetState(TargetState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.inheritedByCompartments = $.inheritedByCompartments;
        this.lifecyleDetails = $.lifecyleDetails;
        this.recipeCount = $.recipeCount;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.targetDetectorRecipes = $.targetDetectorRecipes;
        this.targetResourceId = $.targetResourceId;
        this.targetResourceType = $.targetResourceType;
        this.targetResponderRecipes = $.targetResponderRecipes;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TargetState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TargetState $;

        public Builder() {
            $ = new TargetState();
        }

        public Builder(TargetState defaults) {
            $ = new TargetState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) compartment associated with condition
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) compartment associated with condition
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
         * @param description The target description.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description The target description.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) DetectorTemplate Identifier
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) DetectorTemplate Identifier
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
         * @param lifecyleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecyleDetails(@Nullable Output<String> lifecyleDetails) {
            $.lifecyleDetails = lifecyleDetails;
            return this;
        }

        /**
         * @param lifecyleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecyleDetails(String lifecyleDetails) {
            return lifecyleDetails(Output.of(lifecyleDetails));
        }

        /**
         * @param recipeCount Total number of recipes attached to target
         * 
         * @return builder
         * 
         */
        public Builder recipeCount(@Nullable Output<Integer> recipeCount) {
            $.recipeCount = recipeCount;
            return this;
        }

        /**
         * @param recipeCount Total number of recipes attached to target
         * 
         * @return builder
         * 
         */
        public Builder recipeCount(Integer recipeCount) {
            return recipeCount(Output.of(recipeCount));
        }

        /**
         * @param state (Updatable) The current state of the DetectorRule.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state (Updatable) The current state of the DetectorRule.
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
         * @param targetDetectorRecipes (Updatable) List of detector recipes to associate with target
         * 
         * @return builder
         * 
         */
        public Builder targetDetectorRecipes(@Nullable Output<List<TargetTargetDetectorRecipeArgs>> targetDetectorRecipes) {
            $.targetDetectorRecipes = targetDetectorRecipes;
            return this;
        }

        /**
         * @param targetDetectorRecipes (Updatable) List of detector recipes to associate with target
         * 
         * @return builder
         * 
         */
        public Builder targetDetectorRecipes(List<TargetTargetDetectorRecipeArgs> targetDetectorRecipes) {
            return targetDetectorRecipes(Output.of(targetDetectorRecipes));
        }

        /**
         * @param targetDetectorRecipes (Updatable) List of detector recipes to associate with target
         * 
         * @return builder
         * 
         */
        public Builder targetDetectorRecipes(TargetTargetDetectorRecipeArgs... targetDetectorRecipes) {
            return targetDetectorRecipes(List.of(targetDetectorRecipes));
        }

        /**
         * @param targetResourceId Resource ID which the target uses to monitor
         * 
         * @return builder
         * 
         */
        public Builder targetResourceId(@Nullable Output<String> targetResourceId) {
            $.targetResourceId = targetResourceId;
            return this;
        }

        /**
         * @param targetResourceId Resource ID which the target uses to monitor
         * 
         * @return builder
         * 
         */
        public Builder targetResourceId(String targetResourceId) {
            return targetResourceId(Output.of(targetResourceId));
        }

        /**
         * @param targetResourceType possible type of targets(compartment/HCMCloud/ERPCloud)
         * 
         * @return builder
         * 
         */
        public Builder targetResourceType(@Nullable Output<String> targetResourceType) {
            $.targetResourceType = targetResourceType;
            return this;
        }

        /**
         * @param targetResourceType possible type of targets(compartment/HCMCloud/ERPCloud)
         * 
         * @return builder
         * 
         */
        public Builder targetResourceType(String targetResourceType) {
            return targetResourceType(Output.of(targetResourceType));
        }

        /**
         * @param targetResponderRecipes (Updatable) List of responder recipes to associate with target
         * 
         * @return builder
         * 
         */
        public Builder targetResponderRecipes(@Nullable Output<List<TargetTargetResponderRecipeArgs>> targetResponderRecipes) {
            $.targetResponderRecipes = targetResponderRecipes;
            return this;
        }

        /**
         * @param targetResponderRecipes (Updatable) List of responder recipes to associate with target
         * 
         * @return builder
         * 
         */
        public Builder targetResponderRecipes(List<TargetTargetResponderRecipeArgs> targetResponderRecipes) {
            return targetResponderRecipes(Output.of(targetResponderRecipes));
        }

        /**
         * @param targetResponderRecipes (Updatable) List of responder recipes to associate with target
         * 
         * @return builder
         * 
         */
        public Builder targetResponderRecipes(TargetTargetResponderRecipeArgs... targetResponderRecipes) {
            return targetResponderRecipes(List.of(targetResponderRecipes));
        }

        /**
         * @param timeCreated The date and time the target was created. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the target was created. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the target was updated. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the target was updated. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public TargetState build() {
            return $;
        }
    }

}
