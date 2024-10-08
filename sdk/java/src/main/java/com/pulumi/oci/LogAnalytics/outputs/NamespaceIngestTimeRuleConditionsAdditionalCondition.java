// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class NamespaceIngestTimeRuleConditionsAdditionalCondition {
    /**
     * @return (Updatable) The additional field name to be evaluated.
     * 
     */
    private String conditionField;
    /**
     * @return (Updatable) The operator to be used for evaluating the additional field.
     * 
     */
    private String conditionOperator;
    /**
     * @return (Updatable) The additional field value to be evaluated.
     * 
     */
    private String conditionValue;

    private NamespaceIngestTimeRuleConditionsAdditionalCondition() {}
    /**
     * @return (Updatable) The additional field name to be evaluated.
     * 
     */
    public String conditionField() {
        return this.conditionField;
    }
    /**
     * @return (Updatable) The operator to be used for evaluating the additional field.
     * 
     */
    public String conditionOperator() {
        return this.conditionOperator;
    }
    /**
     * @return (Updatable) The additional field value to be evaluated.
     * 
     */
    public String conditionValue() {
        return this.conditionValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(NamespaceIngestTimeRuleConditionsAdditionalCondition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String conditionField;
        private String conditionOperator;
        private String conditionValue;
        public Builder() {}
        public Builder(NamespaceIngestTimeRuleConditionsAdditionalCondition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.conditionField = defaults.conditionField;
    	      this.conditionOperator = defaults.conditionOperator;
    	      this.conditionValue = defaults.conditionValue;
        }

        @CustomType.Setter
        public Builder conditionField(String conditionField) {
            if (conditionField == null) {
              throw new MissingRequiredPropertyException("NamespaceIngestTimeRuleConditionsAdditionalCondition", "conditionField");
            }
            this.conditionField = conditionField;
            return this;
        }
        @CustomType.Setter
        public Builder conditionOperator(String conditionOperator) {
            if (conditionOperator == null) {
              throw new MissingRequiredPropertyException("NamespaceIngestTimeRuleConditionsAdditionalCondition", "conditionOperator");
            }
            this.conditionOperator = conditionOperator;
            return this;
        }
        @CustomType.Setter
        public Builder conditionValue(String conditionValue) {
            if (conditionValue == null) {
              throw new MissingRequiredPropertyException("NamespaceIngestTimeRuleConditionsAdditionalCondition", "conditionValue");
            }
            this.conditionValue = conditionValue;
            return this;
        }
        public NamespaceIngestTimeRuleConditionsAdditionalCondition build() {
            final var _resultValue = new NamespaceIngestTimeRuleConditionsAdditionalCondition();
            _resultValue.conditionField = conditionField;
            _resultValue.conditionOperator = conditionOperator;
            _resultValue.conditionValue = conditionValue;
            return _resultValue;
        }
    }
}
