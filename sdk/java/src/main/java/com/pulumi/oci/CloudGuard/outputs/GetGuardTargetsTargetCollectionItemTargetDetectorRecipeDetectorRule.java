// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetail;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleEntitiesMapping;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule {
    /**
     * @return The ID of the attached data source
     * 
     */
    private String dataSourceId;
    /**
     * @return Responder rule description
     * 
     */
    private String description;
    /**
     * @return Detailed information for a responder rule
     * 
     */
    private List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetail> details;
    /**
     * @return Detector type for the rule
     * 
     */
    private String detector;
    /**
     * @return The unique identifier of the detector rule
     * 
     */
    private String detectorRuleId;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return Data source entities mapping for a detector rule
     * 
     */
    private List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleEntitiesMapping> entitiesMappings;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return List of managed list types related to this rule
     * 
     */
    private List<String> managedListTypes;
    /**
     * @return Recommendation for TargetDetectorRecipeDetectorRule resource
     * 
     */
    private String recommendation;
    /**
     * @return The type of resource which is monitored by the detector rule. For example, Instance, Database, VCN, Policy. To find the resource type for a particular rule, see [Detector Recipe Reference] (/iaas/cloud-guard/using/detect-recipes.htm#detect-recipes-reference).
     * 
     */
    private String resourceType;
    /**
     * @return Service type of the configuration to which the rule is applied
     * 
     */
    private String serviceType;
    /**
     * @return The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    private String state;
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the target was last updated. Format defined by RFC3339.
     * 
     */
    private String timeUpdated;

    private GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule() {}
    /**
     * @return The ID of the attached data source
     * 
     */
    public String dataSourceId() {
        return this.dataSourceId;
    }
    /**
     * @return Responder rule description
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Detailed information for a responder rule
     * 
     */
    public List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetail> details() {
        return this.details;
    }
    /**
     * @return Detector type for the rule
     * 
     */
    public String detector() {
        return this.detector;
    }
    /**
     * @return The unique identifier of the detector rule
     * 
     */
    public String detectorRuleId() {
        return this.detectorRuleId;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Data source entities mapping for a detector rule
     * 
     */
    public List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleEntitiesMapping> entitiesMappings() {
        return this.entitiesMappings;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return List of managed list types related to this rule
     * 
     */
    public List<String> managedListTypes() {
        return this.managedListTypes;
    }
    /**
     * @return Recommendation for TargetDetectorRecipeDetectorRule resource
     * 
     */
    public String recommendation() {
        return this.recommendation;
    }
    /**
     * @return The type of resource which is monitored by the detector rule. For example, Instance, Database, VCN, Policy. To find the resource type for a particular rule, see [Detector Recipe Reference] (/iaas/cloud-guard/using/detect-recipes.htm#detect-recipes-reference).
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }
    /**
     * @return Service type of the configuration to which the rule is applied
     * 
     */
    public String serviceType() {
        return this.serviceType;
    }
    /**
     * @return The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
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
     * @return The date and time the target was last updated. Format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dataSourceId;
        private String description;
        private List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetail> details;
        private String detector;
        private String detectorRuleId;
        private String displayName;
        private List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleEntitiesMapping> entitiesMappings;
        private String lifecycleDetails;
        private List<String> managedListTypes;
        private String recommendation;
        private String resourceType;
        private String serviceType;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dataSourceId = defaults.dataSourceId;
    	      this.description = defaults.description;
    	      this.details = defaults.details;
    	      this.detector = defaults.detector;
    	      this.detectorRuleId = defaults.detectorRuleId;
    	      this.displayName = defaults.displayName;
    	      this.entitiesMappings = defaults.entitiesMappings;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.managedListTypes = defaults.managedListTypes;
    	      this.recommendation = defaults.recommendation;
    	      this.resourceType = defaults.resourceType;
    	      this.serviceType = defaults.serviceType;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder dataSourceId(String dataSourceId) {
            if (dataSourceId == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "dataSourceId");
            }
            this.dataSourceId = dataSourceId;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder details(List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetail> details) {
            if (details == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "details");
            }
            this.details = details;
            return this;
        }
        public Builder details(GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetail... details) {
            return details(List.of(details));
        }
        @CustomType.Setter
        public Builder detector(String detector) {
            if (detector == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "detector");
            }
            this.detector = detector;
            return this;
        }
        @CustomType.Setter
        public Builder detectorRuleId(String detectorRuleId) {
            if (detectorRuleId == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "detectorRuleId");
            }
            this.detectorRuleId = detectorRuleId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder entitiesMappings(List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleEntitiesMapping> entitiesMappings) {
            if (entitiesMappings == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "entitiesMappings");
            }
            this.entitiesMappings = entitiesMappings;
            return this;
        }
        public Builder entitiesMappings(GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleEntitiesMapping... entitiesMappings) {
            return entitiesMappings(List.of(entitiesMappings));
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder managedListTypes(List<String> managedListTypes) {
            if (managedListTypes == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "managedListTypes");
            }
            this.managedListTypes = managedListTypes;
            return this;
        }
        public Builder managedListTypes(String... managedListTypes) {
            return managedListTypes(List.of(managedListTypes));
        }
        @CustomType.Setter
        public Builder recommendation(String recommendation) {
            if (recommendation == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "recommendation");
            }
            this.recommendation = recommendation;
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(String resourceType) {
            if (resourceType == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "resourceType");
            }
            this.resourceType = resourceType;
            return this;
        }
        @CustomType.Setter
        public Builder serviceType(String serviceType) {
            if (serviceType == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "serviceType");
            }
            this.serviceType = serviceType;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule build() {
            final var _resultValue = new GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRule();
            _resultValue.dataSourceId = dataSourceId;
            _resultValue.description = description;
            _resultValue.details = details;
            _resultValue.detector = detector;
            _resultValue.detectorRuleId = detectorRuleId;
            _resultValue.displayName = displayName;
            _resultValue.entitiesMappings = entitiesMappings;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.managedListTypes = managedListTypes;
            _resultValue.recommendation = recommendation;
            _resultValue.resourceType = resourceType;
            _resultValue.serviceType = serviceType;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
