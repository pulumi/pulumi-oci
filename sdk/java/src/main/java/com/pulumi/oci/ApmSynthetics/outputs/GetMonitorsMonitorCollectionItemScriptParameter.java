// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApmSynthetics.outputs.GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMonitorsMonitorCollectionItemScriptParameter {
    /**
     * @return If parameter value is default or overwritten.
     * 
     */
    private Boolean isOverwritten;
    /**
     * @return Describes if  the parameter value is secret and should be kept confidential. isSecret is specified in either CreateScript or UpdateScript API.
     * 
     */
    private Boolean isSecret;
    /**
     * @return Details of the script parameter that can be used to overwrite the parameter present in the script.
     * 
     */
    private List<GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter> monitorScriptParameters;
    /**
     * @return Name of the parameter.
     * 
     */
    private String paramName;
    /**
     * @return Value of the parameter.
     * 
     */
    private String paramValue;

    private GetMonitorsMonitorCollectionItemScriptParameter() {}
    /**
     * @return If parameter value is default or overwritten.
     * 
     */
    public Boolean isOverwritten() {
        return this.isOverwritten;
    }
    /**
     * @return Describes if  the parameter value is secret and should be kept confidential. isSecret is specified in either CreateScript or UpdateScript API.
     * 
     */
    public Boolean isSecret() {
        return this.isSecret;
    }
    /**
     * @return Details of the script parameter that can be used to overwrite the parameter present in the script.
     * 
     */
    public List<GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter> monitorScriptParameters() {
        return this.monitorScriptParameters;
    }
    /**
     * @return Name of the parameter.
     * 
     */
    public String paramName() {
        return this.paramName;
    }
    /**
     * @return Value of the parameter.
     * 
     */
    public String paramValue() {
        return this.paramValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitorsMonitorCollectionItemScriptParameter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isOverwritten;
        private Boolean isSecret;
        private List<GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter> monitorScriptParameters;
        private String paramName;
        private String paramValue;
        public Builder() {}
        public Builder(GetMonitorsMonitorCollectionItemScriptParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isOverwritten = defaults.isOverwritten;
    	      this.isSecret = defaults.isSecret;
    	      this.monitorScriptParameters = defaults.monitorScriptParameters;
    	      this.paramName = defaults.paramName;
    	      this.paramValue = defaults.paramValue;
        }

        @CustomType.Setter
        public Builder isOverwritten(Boolean isOverwritten) {
            if (isOverwritten == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemScriptParameter", "isOverwritten");
            }
            this.isOverwritten = isOverwritten;
            return this;
        }
        @CustomType.Setter
        public Builder isSecret(Boolean isSecret) {
            if (isSecret == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemScriptParameter", "isSecret");
            }
            this.isSecret = isSecret;
            return this;
        }
        @CustomType.Setter
        public Builder monitorScriptParameters(List<GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter> monitorScriptParameters) {
            if (monitorScriptParameters == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemScriptParameter", "monitorScriptParameters");
            }
            this.monitorScriptParameters = monitorScriptParameters;
            return this;
        }
        public Builder monitorScriptParameters(GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter... monitorScriptParameters) {
            return monitorScriptParameters(List.of(monitorScriptParameters));
        }
        @CustomType.Setter
        public Builder paramName(String paramName) {
            if (paramName == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemScriptParameter", "paramName");
            }
            this.paramName = paramName;
            return this;
        }
        @CustomType.Setter
        public Builder paramValue(String paramValue) {
            if (paramValue == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemScriptParameter", "paramValue");
            }
            this.paramValue = paramValue;
            return this;
        }
        public GetMonitorsMonitorCollectionItemScriptParameter build() {
            final var _resultValue = new GetMonitorsMonitorCollectionItemScriptParameter();
            _resultValue.isOverwritten = isOverwritten;
            _resultValue.isSecret = isSecret;
            _resultValue.monitorScriptParameters = monitorScriptParameters;
            _resultValue.paramName = paramName;
            _resultValue.paramValue = paramValue;
            return _resultValue;
        }
    }
}
