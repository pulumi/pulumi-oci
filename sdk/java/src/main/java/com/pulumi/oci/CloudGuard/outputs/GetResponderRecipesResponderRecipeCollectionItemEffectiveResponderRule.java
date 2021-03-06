// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRuleDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRule {
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private final String compartmentId;
    /**
     * @return ResponderRule Description
     * 
     */
    private final String description;
    /**
     * @return Details of ResponderRule.
     * 
     */
    private final List<GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRuleDetail> details;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private final String displayName;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return List of Policy
     * 
     */
    private final List<String> policies;
    /**
     * @return Identifier for ResponderRule.
     * 
     */
    private final String responderRuleId;
    /**
     * @return The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    private final String state;
    /**
     * @return Supported Execution Modes
     * 
     */
    private final List<String> supportedModes;
    /**
     * @return The date and time the responder recipe was created. Format defined by RFC3339.
     * 
     */
    private final String timeCreated;
    /**
     * @return The date and time the responder recipe was updated. Format defined by RFC3339.
     * 
     */
    private final String timeUpdated;
    /**
     * @return Type of Responder
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRule(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("details") List<GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRuleDetail> details,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("policies") List<String> policies,
        @CustomType.Parameter("responderRuleId") String responderRuleId,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("supportedModes") List<String> supportedModes,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeUpdated") String timeUpdated,
        @CustomType.Parameter("type") String type) {
        this.compartmentId = compartmentId;
        this.description = description;
        this.details = details;
        this.displayName = displayName;
        this.lifecycleDetails = lifecycleDetails;
        this.policies = policies;
        this.responderRuleId = responderRuleId;
        this.state = state;
        this.supportedModes = supportedModes;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
        this.type = type;
    }

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return ResponderRule Description
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Details of ResponderRule.
     * 
     */
    public List<GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRuleDetail> details() {
        return this.details;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return List of Policy
     * 
     */
    public List<String> policies() {
        return this.policies;
    }
    /**
     * @return Identifier for ResponderRule.
     * 
     */
    public String responderRuleId() {
        return this.responderRuleId;
    }
    /**
     * @return The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Supported Execution Modes
     * 
     */
    public List<String> supportedModes() {
        return this.supportedModes;
    }
    /**
     * @return The date and time the responder recipe was created. Format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the responder recipe was updated. Format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return Type of Responder
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRule defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String description;
        private List<GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRuleDetail> details;
        private String displayName;
        private String lifecycleDetails;
        private List<String> policies;
        private String responderRuleId;
        private String state;
        private List<String> supportedModes;
        private String timeCreated;
        private String timeUpdated;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRule defaults) {
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

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder details(List<GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRuleDetail> details) {
            this.details = Objects.requireNonNull(details);
            return this;
        }
        public Builder details(GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRuleDetail... details) {
            return details(List.of(details));
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder policies(List<String> policies) {
            this.policies = Objects.requireNonNull(policies);
            return this;
        }
        public Builder policies(String... policies) {
            return policies(List.of(policies));
        }
        public Builder responderRuleId(String responderRuleId) {
            this.responderRuleId = Objects.requireNonNull(responderRuleId);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder supportedModes(List<String> supportedModes) {
            this.supportedModes = Objects.requireNonNull(supportedModes);
            return this;
        }
        public Builder supportedModes(String... supportedModes) {
            return supportedModes(List.of(supportedModes));
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRule build() {
            return new GetResponderRecipesResponderRecipeCollectionItemEffectiveResponderRule(compartmentId, description, details, displayName, lifecycleDetails, policies, responderRuleId, state, supportedModes, timeCreated, timeUpdated, type);
        }
    }
}
