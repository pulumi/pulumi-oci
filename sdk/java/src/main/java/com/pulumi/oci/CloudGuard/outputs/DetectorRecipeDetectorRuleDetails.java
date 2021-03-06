// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.DetectorRecipeDetectorRuleDetailsConfiguration;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DetectorRecipeDetectorRuleDetails {
    /**
     * @return (Updatable)
     * 
     */
    private final @Nullable String condition;
    /**
     * @return (Updatable) Configuration details
     * 
     */
    private final @Nullable List<DetectorRecipeDetectorRuleDetailsConfiguration> configurations;
    /**
     * @return configuration allowed or not
     * 
     */
    private final @Nullable Boolean isConfigurationAllowed;
    /**
     * @return (Updatable) Enables the control
     * 
     */
    private final Boolean isEnabled;
    /**
     * @return (Updatable) user defined labels for a detector rule
     * 
     */
    private final @Nullable List<String> labels;
    /**
     * @return (Updatable) The Risk Level
     * 
     */
    private final String riskLevel;

    @CustomType.Constructor
    private DetectorRecipeDetectorRuleDetails(
        @CustomType.Parameter("condition") @Nullable String condition,
        @CustomType.Parameter("configurations") @Nullable List<DetectorRecipeDetectorRuleDetailsConfiguration> configurations,
        @CustomType.Parameter("isConfigurationAllowed") @Nullable Boolean isConfigurationAllowed,
        @CustomType.Parameter("isEnabled") Boolean isEnabled,
        @CustomType.Parameter("labels") @Nullable List<String> labels,
        @CustomType.Parameter("riskLevel") String riskLevel) {
        this.condition = condition;
        this.configurations = configurations;
        this.isConfigurationAllowed = isConfigurationAllowed;
        this.isEnabled = isEnabled;
        this.labels = labels;
        this.riskLevel = riskLevel;
    }

    /**
     * @return (Updatable)
     * 
     */
    public Optional<String> condition() {
        return Optional.ofNullable(this.condition);
    }
    /**
     * @return (Updatable) Configuration details
     * 
     */
    public List<DetectorRecipeDetectorRuleDetailsConfiguration> configurations() {
        return this.configurations == null ? List.of() : this.configurations;
    }
    /**
     * @return configuration allowed or not
     * 
     */
    public Optional<Boolean> isConfigurationAllowed() {
        return Optional.ofNullable(this.isConfigurationAllowed);
    }
    /**
     * @return (Updatable) Enables the control
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return (Updatable) user defined labels for a detector rule
     * 
     */
    public List<String> labels() {
        return this.labels == null ? List.of() : this.labels;
    }
    /**
     * @return (Updatable) The Risk Level
     * 
     */
    public String riskLevel() {
        return this.riskLevel;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DetectorRecipeDetectorRuleDetails defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String condition;
        private @Nullable List<DetectorRecipeDetectorRuleDetailsConfiguration> configurations;
        private @Nullable Boolean isConfigurationAllowed;
        private Boolean isEnabled;
        private @Nullable List<String> labels;
        private String riskLevel;

        public Builder() {
    	      // Empty
        }

        public Builder(DetectorRecipeDetectorRuleDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.condition = defaults.condition;
    	      this.configurations = defaults.configurations;
    	      this.isConfigurationAllowed = defaults.isConfigurationAllowed;
    	      this.isEnabled = defaults.isEnabled;
    	      this.labels = defaults.labels;
    	      this.riskLevel = defaults.riskLevel;
        }

        public Builder condition(@Nullable String condition) {
            this.condition = condition;
            return this;
        }
        public Builder configurations(@Nullable List<DetectorRecipeDetectorRuleDetailsConfiguration> configurations) {
            this.configurations = configurations;
            return this;
        }
        public Builder configurations(DetectorRecipeDetectorRuleDetailsConfiguration... configurations) {
            return configurations(List.of(configurations));
        }
        public Builder isConfigurationAllowed(@Nullable Boolean isConfigurationAllowed) {
            this.isConfigurationAllowed = isConfigurationAllowed;
            return this;
        }
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        public Builder labels(@Nullable List<String> labels) {
            this.labels = labels;
            return this;
        }
        public Builder labels(String... labels) {
            return labels(List.of(labels));
        }
        public Builder riskLevel(String riskLevel) {
            this.riskLevel = Objects.requireNonNull(riskLevel);
            return this;
        }        public DetectorRecipeDetectorRuleDetails build() {
            return new DetectorRecipeDetectorRuleDetails(condition, configurations, isConfigurationAllowed, isEnabled, labels, riskLevel);
        }
    }
}
