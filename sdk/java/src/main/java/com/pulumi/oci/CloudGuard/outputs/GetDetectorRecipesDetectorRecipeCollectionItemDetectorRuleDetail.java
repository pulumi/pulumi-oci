// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.outputs.GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration;
import com.pulumi.oci.CloudGuard.outputs.GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail {
    /**
     * @return The base condition resource.
     * 
     */
    private String condition;
    /**
     * @return List of detector rule configurations
     * 
     */
    private List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration> configurations;
    /**
     * @return The ID of the attached data source
     * 
     */
    private String dataSourceId;
    /**
     * @return Description for detector recipe detector rule
     * 
     */
    private String description;
    /**
     * @return Data source entities mapping for the detector rule
     * 
     */
    private List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping> entitiesMappings;
    /**
     * @return Can the rule be configured?
     * 
     */
    private Boolean isConfigurationAllowed;
    /**
     * @return Enablement status for the rule
     * 
     */
    private Boolean isEnabled;
    /**
     * @return User-defined labels for a detector rule
     * 
     */
    private List<String> labels;
    /**
     * @return Recommendation for DetectorRecipeDetectorRule resource
     * 
     */
    private String recommendation;
    /**
     * @return The risk level for the rule
     * 
     */
    private String riskLevel;

    private GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail() {}
    /**
     * @return The base condition resource.
     * 
     */
    public String condition() {
        return this.condition;
    }
    /**
     * @return List of detector rule configurations
     * 
     */
    public List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration> configurations() {
        return this.configurations;
    }
    /**
     * @return The ID of the attached data source
     * 
     */
    public String dataSourceId() {
        return this.dataSourceId;
    }
    /**
     * @return Description for detector recipe detector rule
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Data source entities mapping for the detector rule
     * 
     */
    public List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping> entitiesMappings() {
        return this.entitiesMappings;
    }
    /**
     * @return Can the rule be configured?
     * 
     */
    public Boolean isConfigurationAllowed() {
        return this.isConfigurationAllowed;
    }
    /**
     * @return Enablement status for the rule
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return User-defined labels for a detector rule
     * 
     */
    public List<String> labels() {
        return this.labels;
    }
    /**
     * @return Recommendation for DetectorRecipeDetectorRule resource
     * 
     */
    public String recommendation() {
        return this.recommendation;
    }
    /**
     * @return The risk level for the rule
     * 
     */
    public String riskLevel() {
        return this.riskLevel;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String condition;
        private List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration> configurations;
        private String dataSourceId;
        private String description;
        private List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping> entitiesMappings;
        private Boolean isConfigurationAllowed;
        private Boolean isEnabled;
        private List<String> labels;
        private String recommendation;
        private String riskLevel;
        public Builder() {}
        public Builder(GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.condition = defaults.condition;
    	      this.configurations = defaults.configurations;
    	      this.dataSourceId = defaults.dataSourceId;
    	      this.description = defaults.description;
    	      this.entitiesMappings = defaults.entitiesMappings;
    	      this.isConfigurationAllowed = defaults.isConfigurationAllowed;
    	      this.isEnabled = defaults.isEnabled;
    	      this.labels = defaults.labels;
    	      this.recommendation = defaults.recommendation;
    	      this.riskLevel = defaults.riskLevel;
        }

        @CustomType.Setter
        public Builder condition(String condition) {
            if (condition == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail", "condition");
            }
            this.condition = condition;
            return this;
        }
        @CustomType.Setter
        public Builder configurations(List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration> configurations) {
            if (configurations == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail", "configurations");
            }
            this.configurations = configurations;
            return this;
        }
        public Builder configurations(GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration... configurations) {
            return configurations(List.of(configurations));
        }
        @CustomType.Setter
        public Builder dataSourceId(String dataSourceId) {
            if (dataSourceId == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail", "dataSourceId");
            }
            this.dataSourceId = dataSourceId;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder entitiesMappings(List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping> entitiesMappings) {
            if (entitiesMappings == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail", "entitiesMappings");
            }
            this.entitiesMappings = entitiesMappings;
            return this;
        }
        public Builder entitiesMappings(GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping... entitiesMappings) {
            return entitiesMappings(List.of(entitiesMappings));
        }
        @CustomType.Setter
        public Builder isConfigurationAllowed(Boolean isConfigurationAllowed) {
            if (isConfigurationAllowed == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail", "isConfigurationAllowed");
            }
            this.isConfigurationAllowed = isConfigurationAllowed;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            if (isEnabled == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail", "isEnabled");
            }
            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder labels(List<String> labels) {
            if (labels == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail", "labels");
            }
            this.labels = labels;
            return this;
        }
        public Builder labels(String... labels) {
            return labels(List.of(labels));
        }
        @CustomType.Setter
        public Builder recommendation(String recommendation) {
            if (recommendation == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail", "recommendation");
            }
            this.recommendation = recommendation;
            return this;
        }
        @CustomType.Setter
        public Builder riskLevel(String riskLevel) {
            if (riskLevel == null) {
              throw new MissingRequiredPropertyException("GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail", "riskLevel");
            }
            this.riskLevel = riskLevel;
            return this;
        }
        public GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail build() {
            final var _resultValue = new GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail();
            _resultValue.condition = condition;
            _resultValue.configurations = configurations;
            _resultValue.dataSourceId = dataSourceId;
            _resultValue.description = description;
            _resultValue.entitiesMappings = entitiesMappings;
            _resultValue.isConfigurationAllowed = isConfigurationAllowed;
            _resultValue.isEnabled = isEnabled;
            _resultValue.labels = labels;
            _resultValue.recommendation = recommendation;
            _resultValue.riskLevel = riskLevel;
            return _resultValue;
        }
    }
}
