// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.outputs.TargetTargetResponderRecipeResponderRuleDetails;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class TargetTargetResponderRecipeResponderRule {
    /**
     * @return Compartment OCID where the resource is created
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return The target description.
     * 
     * Avoid entering confidential information.
     * 
     */
    private @Nullable String description;
    /**
     * @return (Updatable) Parameters to update details for a responder rule for a target responder recipe. TargetResponderRuleDetails contains all configurations associated with the ResponderRule, whereas UpdateTargetResponderRecipeResponderRuleDetails refers to the details that are to be updated for ResponderRule.
     * 
     */
    private TargetTargetResponderRecipeResponderRuleDetails details;
    /**
     * @return (Updatable) Display name for the target.
     * 
     * Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private @Nullable String lifecycleDetails;
    /**
     * @return List of policies
     * 
     */
    private @Nullable List<String> policies;
    /**
     * @return (Updatable) Unique identifier for target detector recipe
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private String responderRuleId;
    /**
     * @return (Updatable) The enablement state of the detector rule
     * 
     */
    private @Nullable String state;
    /**
     * @return Supported execution modes for the responder rule
     * 
     */
    private @Nullable List<String> supportedModes;
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    private @Nullable String timeCreated;
    /**
     * @return The date and time the target was last updated. Format defined by RFC3339.
     * 
     */
    private @Nullable String timeUpdated;
    /**
     * @return Type of responder
     * 
     */
    private @Nullable String type;

    private TargetTargetResponderRecipeResponderRule() {}
    /**
     * @return Compartment OCID where the resource is created
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The target description.
     * 
     * Avoid entering confidential information.
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return (Updatable) Parameters to update details for a responder rule for a target responder recipe. TargetResponderRuleDetails contains all configurations associated with the ResponderRule, whereas UpdateTargetResponderRecipeResponderRuleDetails refers to the details that are to be updated for ResponderRule.
     * 
     */
    public TargetTargetResponderRecipeResponderRuleDetails details() {
        return this.details;
    }
    /**
     * @return (Updatable) Display name for the target.
     * 
     * Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Optional<String> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }
    /**
     * @return List of policies
     * 
     */
    public List<String> policies() {
        return this.policies == null ? List.of() : this.policies;
    }
    /**
     * @return (Updatable) Unique identifier for target detector recipe
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public String responderRuleId() {
        return this.responderRuleId;
    }
    /**
     * @return (Updatable) The enablement state of the detector rule
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return Supported execution modes for the responder rule
     * 
     */
    public List<String> supportedModes() {
        return this.supportedModes == null ? List.of() : this.supportedModes;
    }
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    public Optional<String> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }
    /**
     * @return The date and time the target was last updated. Format defined by RFC3339.
     * 
     */
    public Optional<String> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }
    /**
     * @return Type of responder
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(TargetTargetResponderRecipeResponderRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String description;
        private TargetTargetResponderRecipeResponderRuleDetails details;
        private @Nullable String displayName;
        private @Nullable String lifecycleDetails;
        private @Nullable List<String> policies;
        private String responderRuleId;
        private @Nullable String state;
        private @Nullable List<String> supportedModes;
        private @Nullable String timeCreated;
        private @Nullable String timeUpdated;
        private @Nullable String type;
        public Builder() {}
        public Builder(TargetTargetResponderRecipeResponderRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.description = defaults.description;
    	      this.details = defaults.details;
    	      this.displayName = defaults.displayName;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.policies = defaults.policies;
    	      this.responderRuleId = defaults.responderRuleId;
    	      this.state = defaults.state;
    	      this.supportedModes = defaults.supportedModes;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder description(@Nullable String description) {

            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder details(TargetTargetResponderRecipeResponderRuleDetails details) {
            if (details == null) {
              throw new MissingRequiredPropertyException("TargetTargetResponderRecipeResponderRule", "details");
            }
            this.details = details;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(@Nullable String lifecycleDetails) {

            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder policies(@Nullable List<String> policies) {

            this.policies = policies;
            return this;
        }
        public Builder policies(String... policies) {
            return policies(List.of(policies));
        }
        @CustomType.Setter
        public Builder responderRuleId(String responderRuleId) {
            if (responderRuleId == null) {
              throw new MissingRequiredPropertyException("TargetTargetResponderRecipeResponderRule", "responderRuleId");
            }
            this.responderRuleId = responderRuleId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder supportedModes(@Nullable List<String> supportedModes) {

            this.supportedModes = supportedModes;
            return this;
        }
        public Builder supportedModes(String... supportedModes) {
            return supportedModes(List.of(supportedModes));
        }
        @CustomType.Setter
        public Builder timeCreated(@Nullable String timeCreated) {

            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(@Nullable String timeUpdated) {

            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder type(@Nullable String type) {

            this.type = type;
            return this;
        }
        public TargetTargetResponderRecipeResponderRule build() {
            final var _resultValue = new TargetTargetResponderRecipeResponderRule();
            _resultValue.compartmentId = compartmentId;
            _resultValue.description = description;
            _resultValue.details = details;
            _resultValue.displayName = displayName;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.policies = policies;
            _resultValue.responderRuleId = responderRuleId;
            _resultValue.state = state;
            _resultValue.supportedModes = supportedModes;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
