// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.DetectorRecipeDetectorRuleCandidateResponderRule;
import com.pulumi.oci.CloudGuard.outputs.DetectorRecipeDetectorRuleDetails;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DetectorRecipeDetectorRule {
    /**
     * @return List of CandidateResponderRule related to this rule
     * 
     */
    private final @Nullable List<DetectorRecipeDetectorRuleCandidateResponderRule> candidateResponderRules;
    /**
     * @return (Updatable) DetectorRecipe Description
     * 
     */
    private final @Nullable String description;
    /**
     * @return (Updatable) Details of a Detector Rule to be overriden in Detector Recipe
     * 
     */
    private final DetectorRecipeDetectorRuleDetails details;
    /**
     * @return detector for the rule
     * 
     */
    private final @Nullable String detector;
    /**
     * @return (Updatable) DetectorRecipeRule Identifier
     * 
     */
    private final String detectorRuleId;
    /**
     * @return (Updatable) DetectorRecipe Display Name
     * 
     */
    private final @Nullable String displayName;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private final @Nullable String lifecycleDetails;
    /**
     * @return List of cloudguard managed list types related to this rule
     * 
     */
    private final @Nullable List<String> managedListTypes;
    /**
     * @return Recommendation for DetectorRecipeDetectorRule
     * 
     */
    private final @Nullable String recommendation;
    /**
     * @return resource type of the configuration to which the rule is applied
     * 
     */
    private final @Nullable String resourceType;
    /**
     * @return service type of the configuration to which the rule is applied
     * 
     */
    private final @Nullable String serviceType;
    /**
     * @return The current state of the resource.
     * 
     */
    private final @Nullable String state;
    /**
     * @return The date and time the detector recipe was created. Format defined by RFC3339.
     * 
     */
    private final @Nullable String timeCreated;
    /**
     * @return The date and time the detector recipe was updated. Format defined by RFC3339.
     * 
     */
    private final @Nullable String timeUpdated;

    @CustomType.Constructor
    private DetectorRecipeDetectorRule(
        @CustomType.Parameter("candidateResponderRules") @Nullable List<DetectorRecipeDetectorRuleCandidateResponderRule> candidateResponderRules,
        @CustomType.Parameter("description") @Nullable String description,
        @CustomType.Parameter("details") DetectorRecipeDetectorRuleDetails details,
        @CustomType.Parameter("detector") @Nullable String detector,
        @CustomType.Parameter("detectorRuleId") String detectorRuleId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("lifecycleDetails") @Nullable String lifecycleDetails,
        @CustomType.Parameter("managedListTypes") @Nullable List<String> managedListTypes,
        @CustomType.Parameter("recommendation") @Nullable String recommendation,
        @CustomType.Parameter("resourceType") @Nullable String resourceType,
        @CustomType.Parameter("serviceType") @Nullable String serviceType,
        @CustomType.Parameter("state") @Nullable String state,
        @CustomType.Parameter("timeCreated") @Nullable String timeCreated,
        @CustomType.Parameter("timeUpdated") @Nullable String timeUpdated) {
        this.candidateResponderRules = candidateResponderRules;
        this.description = description;
        this.details = details;
        this.detector = detector;
        this.detectorRuleId = detectorRuleId;
        this.displayName = displayName;
        this.lifecycleDetails = lifecycleDetails;
        this.managedListTypes = managedListTypes;
        this.recommendation = recommendation;
        this.resourceType = resourceType;
        this.serviceType = serviceType;
        this.state = state;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
    }

    /**
     * @return List of CandidateResponderRule related to this rule
     * 
     */
    public List<DetectorRecipeDetectorRuleCandidateResponderRule> candidateResponderRules() {
        return this.candidateResponderRules == null ? List.of() : this.candidateResponderRules;
    }
    /**
     * @return (Updatable) DetectorRecipe Description
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return (Updatable) Details of a Detector Rule to be overriden in Detector Recipe
     * 
     */
    public DetectorRecipeDetectorRuleDetails details() {
        return this.details;
    }
    /**
     * @return detector for the rule
     * 
     */
    public Optional<String> detector() {
        return Optional.ofNullable(this.detector);
    }
    /**
     * @return (Updatable) DetectorRecipeRule Identifier
     * 
     */
    public String detectorRuleId() {
        return this.detectorRuleId;
    }
    /**
     * @return (Updatable) DetectorRecipe Display Name
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
     * @return List of cloudguard managed list types related to this rule
     * 
     */
    public List<String> managedListTypes() {
        return this.managedListTypes == null ? List.of() : this.managedListTypes;
    }
    /**
     * @return Recommendation for DetectorRecipeDetectorRule
     * 
     */
    public Optional<String> recommendation() {
        return Optional.ofNullable(this.recommendation);
    }
    /**
     * @return resource type of the configuration to which the rule is applied
     * 
     */
    public Optional<String> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }
    /**
     * @return service type of the configuration to which the rule is applied
     * 
     */
    public Optional<String> serviceType() {
        return Optional.ofNullable(this.serviceType);
    }
    /**
     * @return The current state of the resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The date and time the detector recipe was created. Format defined by RFC3339.
     * 
     */
    public Optional<String> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }
    /**
     * @return The date and time the detector recipe was updated. Format defined by RFC3339.
     * 
     */
    public Optional<String> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DetectorRecipeDetectorRule defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable List<DetectorRecipeDetectorRuleCandidateResponderRule> candidateResponderRules;
        private @Nullable String description;
        private DetectorRecipeDetectorRuleDetails details;
        private @Nullable String detector;
        private String detectorRuleId;
        private @Nullable String displayName;
        private @Nullable String lifecycleDetails;
        private @Nullable List<String> managedListTypes;
        private @Nullable String recommendation;
        private @Nullable String resourceType;
        private @Nullable String serviceType;
        private @Nullable String state;
        private @Nullable String timeCreated;
        private @Nullable String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(DetectorRecipeDetectorRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.candidateResponderRules = defaults.candidateResponderRules;
    	      this.description = defaults.description;
    	      this.details = defaults.details;
    	      this.detector = defaults.detector;
    	      this.detectorRuleId = defaults.detectorRuleId;
    	      this.displayName = defaults.displayName;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.managedListTypes = defaults.managedListTypes;
    	      this.recommendation = defaults.recommendation;
    	      this.resourceType = defaults.resourceType;
    	      this.serviceType = defaults.serviceType;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        public Builder candidateResponderRules(@Nullable List<DetectorRecipeDetectorRuleCandidateResponderRule> candidateResponderRules) {
            this.candidateResponderRules = candidateResponderRules;
            return this;
        }
        public Builder candidateResponderRules(DetectorRecipeDetectorRuleCandidateResponderRule... candidateResponderRules) {
            return candidateResponderRules(List.of(candidateResponderRules));
        }
        public Builder description(@Nullable String description) {
            this.description = description;
            return this;
        }
        public Builder details(DetectorRecipeDetectorRuleDetails details) {
            this.details = Objects.requireNonNull(details);
            return this;
        }
        public Builder detector(@Nullable String detector) {
            this.detector = detector;
            return this;
        }
        public Builder detectorRuleId(String detectorRuleId) {
            this.detectorRuleId = Objects.requireNonNull(detectorRuleId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder lifecycleDetails(@Nullable String lifecycleDetails) {
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        public Builder managedListTypes(@Nullable List<String> managedListTypes) {
            this.managedListTypes = managedListTypes;
            return this;
        }
        public Builder managedListTypes(String... managedListTypes) {
            return managedListTypes(List.of(managedListTypes));
        }
        public Builder recommendation(@Nullable String recommendation) {
            this.recommendation = recommendation;
            return this;
        }
        public Builder resourceType(@Nullable String resourceType) {
            this.resourceType = resourceType;
            return this;
        }
        public Builder serviceType(@Nullable String serviceType) {
            this.serviceType = serviceType;
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public Builder timeCreated(@Nullable String timeCreated) {
            this.timeCreated = timeCreated;
            return this;
        }
        public Builder timeUpdated(@Nullable String timeUpdated) {
            this.timeUpdated = timeUpdated;
            return this;
        }        public DetectorRecipeDetectorRule build() {
            return new DetectorRecipeDetectorRule(candidateResponderRules, description, details, detector, detectorRuleId, displayName, lifecycleDetails, managedListTypes, recommendation, resourceType, serviceType, state, timeCreated, timeUpdated);
        }
    }
}
