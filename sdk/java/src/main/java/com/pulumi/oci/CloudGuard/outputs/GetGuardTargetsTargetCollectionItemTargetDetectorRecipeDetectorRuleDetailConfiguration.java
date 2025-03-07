// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfigurationValue;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration {
    /**
     * @return Unique identifier of the configuration
     * 
     */
    private String configKey;
    /**
     * @return Configuration data type
     * 
     */
    private String dataType;
    /**
     * @return Configuration name
     * 
     */
    private String name;
    /**
     * @return Configuration value
     * 
     */
    private String value;
    /**
     * @return List of configuration values
     * 
     */
    private List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfigurationValue> values;

    private GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration() {}
    /**
     * @return Unique identifier of the configuration
     * 
     */
    public String configKey() {
        return this.configKey;
    }
    /**
     * @return Configuration data type
     * 
     */
    public String dataType() {
        return this.dataType;
    }
    /**
     * @return Configuration name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Configuration value
     * 
     */
    public String value() {
        return this.value;
    }
    /**
     * @return List of configuration values
     * 
     */
    public List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfigurationValue> values() {
        return this.values;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String configKey;
        private String dataType;
        private String name;
        private String value;
        private List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfigurationValue> values;
        public Builder() {}
        public Builder(GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configKey = defaults.configKey;
    	      this.dataType = defaults.dataType;
    	      this.name = defaults.name;
    	      this.value = defaults.value;
    	      this.values = defaults.values;
        }

        @CustomType.Setter
        public Builder configKey(String configKey) {
            if (configKey == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration", "configKey");
            }
            this.configKey = configKey;
            return this;
        }
        @CustomType.Setter
        public Builder dataType(String dataType) {
            if (dataType == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration", "dataType");
            }
            this.dataType = dataType;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration", "value");
            }
            this.value = value;
            return this;
        }
        @CustomType.Setter
        public Builder values(List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfigurationValue> values) {
            if (values == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration", "values");
            }
            this.values = values;
            return this;
        }
        public Builder values(GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfigurationValue... values) {
            return values(List.of(values));
        }
        public GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration build() {
            final var _resultValue = new GetGuardTargetsTargetCollectionItemTargetDetectorRecipeDetectorRuleDetailConfiguration();
            _resultValue.configKey = configKey;
            _resultValue.dataType = dataType;
            _resultValue.name = name;
            _resultValue.value = value;
            _resultValue.values = values;
            return _resultValue;
        }
    }
}
