// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetScheduledActionParamsActionParamValuesCollectionItem {
    /**
     * @return The default value for this parameter.
     * 
     */
    private String defaultValue;
    /**
     * @return Whether this parameter is required or not for this action type.、
     * 
     */
    private Boolean isRequired;
    /**
     * @return The name of this parameter.
     * 
     */
    private String parameterName;
    /**
     * @return The type of the parameter.
     * 
     */
    private String parameterType;
    /**
     * @return Possible values for this parameter. In case of integer it&#39;s min and max values.
     * 
     */
    private List<String> parameterValues;

    private GetScheduledActionParamsActionParamValuesCollectionItem() {}
    /**
     * @return The default value for this parameter.
     * 
     */
    public String defaultValue() {
        return this.defaultValue;
    }
    /**
     * @return Whether this parameter is required or not for this action type.、
     * 
     */
    public Boolean isRequired() {
        return this.isRequired;
    }
    /**
     * @return The name of this parameter.
     * 
     */
    public String parameterName() {
        return this.parameterName;
    }
    /**
     * @return The type of the parameter.
     * 
     */
    public String parameterType() {
        return this.parameterType;
    }
    /**
     * @return Possible values for this parameter. In case of integer it&#39;s min and max values.
     * 
     */
    public List<String> parameterValues() {
        return this.parameterValues;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetScheduledActionParamsActionParamValuesCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String defaultValue;
        private Boolean isRequired;
        private String parameterName;
        private String parameterType;
        private List<String> parameterValues;
        public Builder() {}
        public Builder(GetScheduledActionParamsActionParamValuesCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.defaultValue = defaults.defaultValue;
    	      this.isRequired = defaults.isRequired;
    	      this.parameterName = defaults.parameterName;
    	      this.parameterType = defaults.parameterType;
    	      this.parameterValues = defaults.parameterValues;
        }

        @CustomType.Setter
        public Builder defaultValue(String defaultValue) {
            if (defaultValue == null) {
              throw new MissingRequiredPropertyException("GetScheduledActionParamsActionParamValuesCollectionItem", "defaultValue");
            }
            this.defaultValue = defaultValue;
            return this;
        }
        @CustomType.Setter
        public Builder isRequired(Boolean isRequired) {
            if (isRequired == null) {
              throw new MissingRequiredPropertyException("GetScheduledActionParamsActionParamValuesCollectionItem", "isRequired");
            }
            this.isRequired = isRequired;
            return this;
        }
        @CustomType.Setter
        public Builder parameterName(String parameterName) {
            if (parameterName == null) {
              throw new MissingRequiredPropertyException("GetScheduledActionParamsActionParamValuesCollectionItem", "parameterName");
            }
            this.parameterName = parameterName;
            return this;
        }
        @CustomType.Setter
        public Builder parameterType(String parameterType) {
            if (parameterType == null) {
              throw new MissingRequiredPropertyException("GetScheduledActionParamsActionParamValuesCollectionItem", "parameterType");
            }
            this.parameterType = parameterType;
            return this;
        }
        @CustomType.Setter
        public Builder parameterValues(List<String> parameterValues) {
            if (parameterValues == null) {
              throw new MissingRequiredPropertyException("GetScheduledActionParamsActionParamValuesCollectionItem", "parameterValues");
            }
            this.parameterValues = parameterValues;
            return this;
        }
        public Builder parameterValues(String... parameterValues) {
            return parameterValues(List.of(parameterValues));
        }
        public GetScheduledActionParamsActionParamValuesCollectionItem build() {
            final var _resultValue = new GetScheduledActionParamsActionParamValuesCollectionItem();
            _resultValue.defaultValue = defaultValue;
            _resultValue.isRequired = isRequired;
            _resultValue.parameterName = parameterName;
            _resultValue.parameterType = parameterType;
            _resultValue.parameterValues = parameterValues;
            return _resultValue;
        }
    }
}
