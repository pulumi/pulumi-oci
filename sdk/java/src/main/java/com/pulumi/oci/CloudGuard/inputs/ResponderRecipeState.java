// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudGuard.inputs.ResponderRecipeEffectiveResponderRuleArgs;
import com.pulumi.oci.CloudGuard.inputs.ResponderRecipeResponderRuleArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ResponderRecipeState extends com.pulumi.resources.ResourceArgs {

    public static final ResponderRecipeState Empty = new ResponderRecipeState();

    /**
     * (Updatable) Compartment Identifier
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier
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
     * (Updatable) ResponderRecipe Description
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) ResponderRecipe Description
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) ResponderRecipe Display Name
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) ResponderRecipe Display Name
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * List of responder rules associated with the recipe
     * 
     */
    @Import(name="effectiveResponderRules")
    private @Nullable Output<List<ResponderRecipeEffectiveResponderRuleArgs>> effectiveResponderRules;

    /**
     * @return List of responder rules associated with the recipe
     * 
     */
    public Optional<Output<List<ResponderRecipeEffectiveResponderRuleArgs>>> effectiveResponderRules() {
        return Optional.ofNullable(this.effectiveResponderRules);
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
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * Owner of ResponderRecipe
     * 
     */
    @Import(name="owner")
    private @Nullable Output<String> owner;

    /**
     * @return Owner of ResponderRecipe
     * 
     */
    public Optional<Output<String>> owner() {
        return Optional.ofNullable(this.owner);
    }

    /**
     * (Updatable) Responder Rules to override from source responder recipe
     * 
     */
    @Import(name="responderRules")
    private @Nullable Output<List<ResponderRecipeResponderRuleArgs>> responderRules;

    /**
     * @return (Updatable) Responder Rules to override from source responder recipe
     * 
     */
    public Optional<Output<List<ResponderRecipeResponderRuleArgs>>> responderRules() {
        return Optional.ofNullable(this.responderRules);
    }

    /**
     * The id of the source responder recipe.
     * 
     */
    @Import(name="sourceResponderRecipeId")
    private @Nullable Output<String> sourceResponderRecipeId;

    /**
     * @return The id of the source responder recipe.
     * 
     */
    public Optional<Output<String>> sourceResponderRecipeId() {
        return Optional.ofNullable(this.sourceResponderRecipeId);
    }

    /**
     * The current state of the Example.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the Example.
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
     * The date and time the responder recipe was created. Format defined by RFC3339.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the responder recipe was created. Format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the responder recipe was updated. Format defined by RFC3339.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the responder recipe was updated. Format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private ResponderRecipeState() {}

    private ResponderRecipeState(ResponderRecipeState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.effectiveResponderRules = $.effectiveResponderRules;
        this.freeformTags = $.freeformTags;
        this.lifecycleDetails = $.lifecycleDetails;
        this.owner = $.owner;
        this.responderRules = $.responderRules;
        this.sourceResponderRecipeId = $.sourceResponderRecipeId;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ResponderRecipeState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ResponderRecipeState $;

        public Builder() {
            $ = new ResponderRecipeState();
        }

        public Builder(ResponderRecipeState defaults) {
            $ = new ResponderRecipeState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier
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
         * @param description (Updatable) ResponderRecipe Description
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) ResponderRecipe Description
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) ResponderRecipe Display Name
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) ResponderRecipe Display Name
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param effectiveResponderRules List of responder rules associated with the recipe
         * 
         * @return builder
         * 
         */
        public Builder effectiveResponderRules(@Nullable Output<List<ResponderRecipeEffectiveResponderRuleArgs>> effectiveResponderRules) {
            $.effectiveResponderRules = effectiveResponderRules;
            return this;
        }

        /**
         * @param effectiveResponderRules List of responder rules associated with the recipe
         * 
         * @return builder
         * 
         */
        public Builder effectiveResponderRules(List<ResponderRecipeEffectiveResponderRuleArgs> effectiveResponderRules) {
            return effectiveResponderRules(Output.of(effectiveResponderRules));
        }

        /**
         * @param effectiveResponderRules List of responder rules associated with the recipe
         * 
         * @return builder
         * 
         */
        public Builder effectiveResponderRules(ResponderRecipeEffectiveResponderRuleArgs... effectiveResponderRules) {
            return effectiveResponderRules(List.of(effectiveResponderRules));
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
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param owner Owner of ResponderRecipe
         * 
         * @return builder
         * 
         */
        public Builder owner(@Nullable Output<String> owner) {
            $.owner = owner;
            return this;
        }

        /**
         * @param owner Owner of ResponderRecipe
         * 
         * @return builder
         * 
         */
        public Builder owner(String owner) {
            return owner(Output.of(owner));
        }

        /**
         * @param responderRules (Updatable) Responder Rules to override from source responder recipe
         * 
         * @return builder
         * 
         */
        public Builder responderRules(@Nullable Output<List<ResponderRecipeResponderRuleArgs>> responderRules) {
            $.responderRules = responderRules;
            return this;
        }

        /**
         * @param responderRules (Updatable) Responder Rules to override from source responder recipe
         * 
         * @return builder
         * 
         */
        public Builder responderRules(List<ResponderRecipeResponderRuleArgs> responderRules) {
            return responderRules(Output.of(responderRules));
        }

        /**
         * @param responderRules (Updatable) Responder Rules to override from source responder recipe
         * 
         * @return builder
         * 
         */
        public Builder responderRules(ResponderRecipeResponderRuleArgs... responderRules) {
            return responderRules(List.of(responderRules));
        }

        /**
         * @param sourceResponderRecipeId The id of the source responder recipe.
         * 
         * @return builder
         * 
         */
        public Builder sourceResponderRecipeId(@Nullable Output<String> sourceResponderRecipeId) {
            $.sourceResponderRecipeId = sourceResponderRecipeId;
            return this;
        }

        /**
         * @param sourceResponderRecipeId The id of the source responder recipe.
         * 
         * @return builder
         * 
         */
        public Builder sourceResponderRecipeId(String sourceResponderRecipeId) {
            return sourceResponderRecipeId(Output.of(sourceResponderRecipeId));
        }

        /**
         * @param state The current state of the Example.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the Example.
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
         * @param timeCreated The date and time the responder recipe was created. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the responder recipe was created. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the responder recipe was updated. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the responder recipe was updated. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public ResponderRecipeState build() {
            return $;
        }
    }

}
