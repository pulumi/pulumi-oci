// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.GetDetectorRecipeDetectorRuleDetailConfiguration;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDetectorRecipeDetectorRuleDetail {
    private final String condition;
    /**
     * @return Configuration details
     * 
     */
    private final List<GetDetectorRecipeDetectorRuleDetailConfiguration> configurations;
    /**
     * @return configuration allowed or not
     * 
     */
    private final Boolean isConfigurationAllowed;
    /**
     * @return Enables the control
     * 
     */
    private final Boolean isEnabled;
    /**
     * @return user defined labels for a detector rule
     * 
     */
    private final List<String> labels;
    /**
     * @return The Risk Level
     * 
     */
    private final String riskLevel;

    @CustomType.Constructor
    private GetDetectorRecipeDetectorRuleDetail(
        @CustomType.Parameter("condition") String condition,
        @CustomType.Parameter("configurations") List<GetDetectorRecipeDetectorRuleDetailConfiguration> configurations,
        @CustomType.Parameter("isConfigurationAllowed") Boolean isConfigurationAllowed,
        @CustomType.Parameter("isEnabled") Boolean isEnabled,
        @CustomType.Parameter("labels") List<String> labels,
        @CustomType.Parameter("riskLevel") String riskLevel) {
        this.condition = condition;
        this.configurations = configurations;
        this.isConfigurationAllowed = isConfigurationAllowed;
        this.isEnabled = isEnabled;
        this.labels = labels;
        this.riskLevel = riskLevel;
    }

    public String condition() {
        return this.condition;
    }
    /**
     * @return Configuration details
     * 
     */
    public List<GetDetectorRecipeDetectorRuleDetailConfiguration> configurations() {
        return this.configurations;
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
     * @return The Risk Level
     * 
     */
    public String riskLevel() {
        return this.riskLevel;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectorRecipeDetectorRuleDetail defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String condition;
        private List<GetDetectorRecipeDetectorRuleDetailConfiguration> configurations;
        private Boolean isConfigurationAllowed;
        private Boolean isEnabled;
        private List<String> labels;
        private String riskLevel;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDetectorRecipeDetectorRuleDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.condition = defaults.condition;
    	      this.configurations = defaults.configurations;
    	      this.isConfigurationAllowed = defaults.isConfigurationAllowed;
    	      this.isEnabled = defaults.isEnabled;
    	      this.labels = defaults.labels;
    	      this.riskLevel = defaults.riskLevel;
        }

        public Builder condition(String condition) {
            this.condition = Objects.requireNonNull(condition);
            return this;
        }
        public Builder configurations(List<GetDetectorRecipeDetectorRuleDetailConfiguration> configurations) {
            this.configurations = Objects.requireNonNull(configurations);
            return this;
        }
        public Builder configurations(GetDetectorRecipeDetectorRuleDetailConfiguration... configurations) {
            return configurations(List.of(configurations));
        }
        public Builder isConfigurationAllowed(Boolean isConfigurationAllowed) {
            this.isConfigurationAllowed = Objects.requireNonNull(isConfigurationAllowed);
            return this;
        }
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        public Builder labels(List<String> labels) {
            this.labels = Objects.requireNonNull(labels);
            return this;
        }
        public Builder labels(String... labels) {
            return labels(List.of(labels));
        }
        public Builder riskLevel(String riskLevel) {
            this.riskLevel = Objects.requireNonNull(riskLevel);
            return this;
        }        public GetDetectorRecipeDetectorRuleDetail build() {
            return new GetDetectorRecipeDetectorRuleDetail(condition, configurations, isConfigurationAllowed, isEnabled, labels, riskLevel);
        }
    }
}
