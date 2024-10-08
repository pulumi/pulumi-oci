// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudGuard.inputs.TargetTargetResponderRecipeEffectiveResponderRuleDetailArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TargetTargetResponderRecipeEffectiveResponderRuleArgs extends com.pulumi.resources.ResourceArgs {

    public static final TargetTargetResponderRecipeEffectiveResponderRuleArgs Empty = new TargetTargetResponderRecipeEffectiveResponderRuleArgs();

    /**
     * Compartment OCID where the resource is created
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return Compartment OCID where the resource is created
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The target description.
     * 
     * Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return The target description.
     * 
     * Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * Detailed information for a responder rule
     * 
     */
    @Import(name="details")
    private @Nullable Output<List<TargetTargetResponderRecipeEffectiveResponderRuleDetailArgs>> details;

    /**
     * @return Detailed information for a responder rule
     * 
     */
    public Optional<Output<List<TargetTargetResponderRecipeEffectiveResponderRuleDetailArgs>>> details() {
        return Optional.ofNullable(this.details);
    }

    /**
     * (Updatable) Display name for the target.
     * 
     * Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Display name for the target.
     * 
     * Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
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
     * List of policies
     * 
     */
    @Import(name="policies")
    private @Nullable Output<List<String>> policies;

    /**
     * @return List of policies
     * 
     */
    public Optional<Output<List<String>>> policies() {
        return Optional.ofNullable(this.policies);
    }

    /**
     * Unique identifier for the responder rule
     * 
     */
    @Import(name="responderRuleId")
    private @Nullable Output<String> responderRuleId;

    /**
     * @return Unique identifier for the responder rule
     * 
     */
    public Optional<Output<String>> responderRuleId() {
        return Optional.ofNullable(this.responderRuleId);
    }

    /**
     * (Updatable) The enablement state of the detector rule
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return (Updatable) The enablement state of the detector rule
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Supported execution modes for the responder rule
     * 
     */
    @Import(name="supportedModes")
    private @Nullable Output<List<String>> supportedModes;

    /**
     * @return Supported execution modes for the responder rule
     * 
     */
    public Optional<Output<List<String>>> supportedModes() {
        return Optional.ofNullable(this.supportedModes);
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
     * The date and time the target was last updated. Format defined by RFC3339.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the target was last updated. Format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * Type of responder
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return Type of responder
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private TargetTargetResponderRecipeEffectiveResponderRuleArgs() {}

    private TargetTargetResponderRecipeEffectiveResponderRuleArgs(TargetTargetResponderRecipeEffectiveResponderRuleArgs $) {
        this.compartmentId = $.compartmentId;
        this.description = $.description;
        this.details = $.details;
        this.displayName = $.displayName;
        this.lifecycleDetails = $.lifecycleDetails;
        this.policies = $.policies;
        this.responderRuleId = $.responderRuleId;
        this.state = $.state;
        this.supportedModes = $.supportedModes;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TargetTargetResponderRecipeEffectiveResponderRuleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TargetTargetResponderRecipeEffectiveResponderRuleArgs $;

        public Builder() {
            $ = new TargetTargetResponderRecipeEffectiveResponderRuleArgs();
        }

        public Builder(TargetTargetResponderRecipeEffectiveResponderRuleArgs defaults) {
            $ = new TargetTargetResponderRecipeEffectiveResponderRuleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId Compartment OCID where the resource is created
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId Compartment OCID where the resource is created
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param description The target description.
         * 
         * Avoid entering confidential information.
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
         * Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param details Detailed information for a responder rule
         * 
         * @return builder
         * 
         */
        public Builder details(@Nullable Output<List<TargetTargetResponderRecipeEffectiveResponderRuleDetailArgs>> details) {
            $.details = details;
            return this;
        }

        /**
         * @param details Detailed information for a responder rule
         * 
         * @return builder
         * 
         */
        public Builder details(List<TargetTargetResponderRecipeEffectiveResponderRuleDetailArgs> details) {
            return details(Output.of(details));
        }

        /**
         * @param details Detailed information for a responder rule
         * 
         * @return builder
         * 
         */
        public Builder details(TargetTargetResponderRecipeEffectiveResponderRuleDetailArgs... details) {
            return details(List.of(details));
        }

        /**
         * @param displayName (Updatable) Display name for the target.
         * 
         * Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Display name for the target.
         * 
         * Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
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
         * @param policies List of policies
         * 
         * @return builder
         * 
         */
        public Builder policies(@Nullable Output<List<String>> policies) {
            $.policies = policies;
            return this;
        }

        /**
         * @param policies List of policies
         * 
         * @return builder
         * 
         */
        public Builder policies(List<String> policies) {
            return policies(Output.of(policies));
        }

        /**
         * @param policies List of policies
         * 
         * @return builder
         * 
         */
        public Builder policies(String... policies) {
            return policies(List.of(policies));
        }

        /**
         * @param responderRuleId Unique identifier for the responder rule
         * 
         * @return builder
         * 
         */
        public Builder responderRuleId(@Nullable Output<String> responderRuleId) {
            $.responderRuleId = responderRuleId;
            return this;
        }

        /**
         * @param responderRuleId Unique identifier for the responder rule
         * 
         * @return builder
         * 
         */
        public Builder responderRuleId(String responderRuleId) {
            return responderRuleId(Output.of(responderRuleId));
        }

        /**
         * @param state (Updatable) The enablement state of the detector rule
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state (Updatable) The enablement state of the detector rule
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param supportedModes Supported execution modes for the responder rule
         * 
         * @return builder
         * 
         */
        public Builder supportedModes(@Nullable Output<List<String>> supportedModes) {
            $.supportedModes = supportedModes;
            return this;
        }

        /**
         * @param supportedModes Supported execution modes for the responder rule
         * 
         * @return builder
         * 
         */
        public Builder supportedModes(List<String> supportedModes) {
            return supportedModes(Output.of(supportedModes));
        }

        /**
         * @param supportedModes Supported execution modes for the responder rule
         * 
         * @return builder
         * 
         */
        public Builder supportedModes(String... supportedModes) {
            return supportedModes(List.of(supportedModes));
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
         * @param timeUpdated The date and time the target was last updated. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the target was last updated. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param type Type of responder
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Type of responder
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public TargetTargetResponderRecipeEffectiveResponderRuleArgs build() {
            return $;
        }
    }

}
