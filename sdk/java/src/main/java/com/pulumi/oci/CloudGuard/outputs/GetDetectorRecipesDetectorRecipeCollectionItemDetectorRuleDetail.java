// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration;
import com.pulumi.oci.CloudGuard.outputs.GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail {
    /**
     * @return Base condition object
     * 
     */
    private String condition;
    /**
     * @return Configuration details
     * 
     */
    private List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration> configurations;
    /**
     * @return The id of the attached DataSource.
     * 
     */
    private String dataSourceId;
    /**
     * @return Description for DetectorRecipeDetectorRule.
     * 
     */
    private String description;
    /**
     * @return Data Source entities mapping for a Detector Rule
     * 
     */
    private List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping> entitiesMappings;
    /**
     * @return configuration allowed or not
     * 
     */
    private Boolean isConfigurationAllowed;
    /**
     * @return Enables the control
     * 
     */
    private Boolean isEnabled;
    /**
     * @return user defined labels for a detector rule
     * 
     */
    private List<String> labels;
    /**
     * @return Recommendation for DetectorRecipeDetectorRule
     * 
     */
    private String recommendation;
    /**
     * @return The Risk Level
     * 
     */
    private String riskLevel;

    private GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail() {}
    /**
     * @return Base condition object
     * 
     */
    public String condition() {
        return this.condition;
    }
    /**
     * @return Configuration details
     * 
     */
    public List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration> configurations() {
        return this.configurations;
    }
    /**
     * @return The id of the attached DataSource.
     * 
     */
    public String dataSourceId() {
        return this.dataSourceId;
    }
    /**
     * @return Description for DetectorRecipeDetectorRule.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Data Source entities mapping for a Detector Rule
     * 
     */
    public List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping> entitiesMappings() {
        return this.entitiesMappings;
    }
    /**
     * @return configuration allowed or not
     * 
     */
    public Boolean isConfigurationAllowed() {
        return this.isConfigurationAllowed;
    }
    /**
     * @return Enables the control
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return user defined labels for a detector rule
     * 
     */
    public List<String> labels() {
        return this.labels;
    }
    /**
     * @return Recommendation for DetectorRecipeDetectorRule
     * 
     */
    public String recommendation() {
        return this.recommendation;
    }
    /**
     * @return The Risk Level
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
            this.condition = Objects.requireNonNull(condition);
            return this;
        }
        @CustomType.Setter
        public Builder configurations(List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration> configurations) {
            this.configurations = Objects.requireNonNull(configurations);
            return this;
        }
        public Builder configurations(GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailConfiguration... configurations) {
            return configurations(List.of(configurations));
        }
        @CustomType.Setter
        public Builder dataSourceId(String dataSourceId) {
            this.dataSourceId = Objects.requireNonNull(dataSourceId);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder entitiesMappings(List<GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping> entitiesMappings) {
            this.entitiesMappings = Objects.requireNonNull(entitiesMappings);
            return this;
        }
        public Builder entitiesMappings(GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetailEntitiesMapping... entitiesMappings) {
            return entitiesMappings(List.of(entitiesMappings));
        }
        @CustomType.Setter
        public Builder isConfigurationAllowed(Boolean isConfigurationAllowed) {
            this.isConfigurationAllowed = Objects.requireNonNull(isConfigurationAllowed);
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder labels(List<String> labels) {
            this.labels = Objects.requireNonNull(labels);
            return this;
        }
        public Builder labels(String... labels) {
            return labels(List.of(labels));
        }
        @CustomType.Setter
        public Builder recommendation(String recommendation) {
            this.recommendation = Objects.requireNonNull(recommendation);
            return this;
        }
        @CustomType.Setter
        public Builder riskLevel(String riskLevel) {
            this.riskLevel = Objects.requireNonNull(riskLevel);
            return this;
        }
        public GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail build() {
            final var o = new GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleDetail();
            o.condition = condition;
            o.configurations = configurations;
            o.dataSourceId = dataSourceId;
            o.description = description;
            o.entitiesMappings = entitiesMappings;
            o.isConfigurationAllowed = isConfigurationAllowed;
            o.isEnabled = isEnabled;
            o.labels = labels;
            o.recommendation = recommendation;
            o.riskLevel = riskLevel;
            return o;
        }
    }
}