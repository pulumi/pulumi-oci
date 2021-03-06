// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRule;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetGuardTargetsTargetCollectionItemTargetDetectorRecipe {
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
     * @return detector for the rule
     * 
     */
    private final String detector;
    /**
     * @return Unique identifier for Detector Recipe of which this is an extension
     * 
     */
    private final String detectorRecipeId;
    /**
     * @return List of detector rules for the detector type for recipe - user input
     * 
     */
    private final List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule> detectorRules;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private final String displayName;
    /**
     * @return List of effective detector rules for the detector type for recipe after applying defaults
     * 
     */
    private final List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRule> effectiveDetectorRules;
    /**
     * @return Unique identifier of TargetResponderRecipe that is immutable on creation
     * 
     */
    private final String id;
    /**
     * @return Owner of ResponderRecipe
     * 
     */
    private final String owner;
    /**
     * @return The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    private final String state;
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    private final String timeCreated;
    /**
     * @return The date and time the target was updated. Format defined by RFC3339.
     * 
     */
    private final String timeUpdated;

    @CustomType.Constructor
    private GetGuardTargetsTargetCollectionItemTargetDetectorRecipe(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("detector") String detector,
        @CustomType.Parameter("detectorRecipeId") String detectorRecipeId,
        @CustomType.Parameter("detectorRules") List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule> detectorRules,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("effectiveDetectorRules") List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRule> effectiveDetectorRules,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("owner") String owner,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeUpdated") String timeUpdated) {
        this.compartmentId = compartmentId;
        this.description = description;
        this.detector = detector;
        this.detectorRecipeId = detectorRecipeId;
        this.detectorRules = detectorRules;
        this.displayName = displayName;
        this.effectiveDetectorRules = effectiveDetectorRules;
        this.id = id;
        this.owner = owner;
        this.state = state;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
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
     * @return detector for the rule
     * 
     */
    public String detector() {
        return this.detector;
    }
    /**
     * @return Unique identifier for Detector Recipe of which this is an extension
     * 
     */
    public String detectorRecipeId() {
        return this.detectorRecipeId;
    }
    /**
     * @return List of detector rules for the detector type for recipe - user input
     * 
     */
    public List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule> detectorRules() {
        return this.detectorRules;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return List of effective detector rules for the detector type for recipe after applying defaults
     * 
     */
    public List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRule> effectiveDetectorRules() {
        return this.effectiveDetectorRules;
    }
    /**
     * @return Unique identifier of TargetResponderRecipe that is immutable on creation
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Owner of ResponderRecipe
     * 
     */
    public String owner() {
        return this.owner;
    }
    /**
     * @return The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the target was updated. Format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetGuardTargetsTargetCollectionItemTargetDetectorRecipe defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String description;
        private String detector;
        private String detectorRecipeId;
        private List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule> detectorRules;
        private String displayName;
        private List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRule> effectiveDetectorRules;
        private String id;
        private String owner;
        private String state;
        private String timeCreated;
        private String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetGuardTargetsTargetCollectionItemTargetDetectorRecipe defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.description = defaults.description;
    	      this.detector = defaults.detector;
    	      this.detectorRecipeId = defaults.detectorRecipeId;
    	      this.detectorRules = defaults.detectorRules;
    	      this.displayName = defaults.displayName;
    	      this.effectiveDetectorRules = defaults.effectiveDetectorRules;
    	      this.id = defaults.id;
    	      this.owner = defaults.owner;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder detector(String detector) {
            this.detector = Objects.requireNonNull(detector);
            return this;
        }
        public Builder detectorRecipeId(String detectorRecipeId) {
            this.detectorRecipeId = Objects.requireNonNull(detectorRecipeId);
            return this;
        }
        public Builder detectorRules(List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule> detectorRules) {
            this.detectorRules = Objects.requireNonNull(detectorRules);
            return this;
        }
        public Builder detectorRules(GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule... detectorRules) {
            return detectorRules(List.of(detectorRules));
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder effectiveDetectorRules(List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRule> effectiveDetectorRules) {
            this.effectiveDetectorRules = Objects.requireNonNull(effectiveDetectorRules);
            return this;
        }
        public Builder effectiveDetectorRules(GetGuardTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRule... effectiveDetectorRules) {
            return effectiveDetectorRules(List.of(effectiveDetectorRules));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder owner(String owner) {
            this.owner = Objects.requireNonNull(owner);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }        public GetGuardTargetsTargetCollectionItemTargetDetectorRecipe build() {
            return new GetGuardTargetsTargetCollectionItemTargetDetectorRecipe(compartmentId, description, detector, detectorRecipeId, detectorRules, displayName, effectiveDetectorRules, id, owner, state, timeCreated, timeUpdated);
        }
    }
}
