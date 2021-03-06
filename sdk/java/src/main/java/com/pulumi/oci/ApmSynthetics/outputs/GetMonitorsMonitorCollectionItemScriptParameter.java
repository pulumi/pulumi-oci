// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
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
    private final Boolean isOverwritten;
    /**
     * @return Describes if  the parameter value is secret and should be kept confidential. isSecret is specified in either CreateScript or UpdateScript API.
     * 
     */
    private final Boolean isSecret;
    /**
     * @return Details of the script parameter that can be used to overwrite the parameter present in the script.
     * 
     */
    private final List<GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter> monitorScriptParameters;
    /**
     * @return Name of the parameter.
     * 
     */
    private final String paramName;
    /**
     * @return Value of the parameter.
     * 
     */
    private final String paramValue;

    @CustomType.Constructor
    private GetMonitorsMonitorCollectionItemScriptParameter(
        @CustomType.Parameter("isOverwritten") Boolean isOverwritten,
        @CustomType.Parameter("isSecret") Boolean isSecret,
        @CustomType.Parameter("monitorScriptParameters") List<GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter> monitorScriptParameters,
        @CustomType.Parameter("paramName") String paramName,
        @CustomType.Parameter("paramValue") String paramValue) {
        this.isOverwritten = isOverwritten;
        this.isSecret = isSecret;
        this.monitorScriptParameters = monitorScriptParameters;
        this.paramName = paramName;
        this.paramValue = paramValue;
    }

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

    public static final class Builder {
        private Boolean isOverwritten;
        private Boolean isSecret;
        private List<GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter> monitorScriptParameters;
        private String paramName;
        private String paramValue;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMonitorsMonitorCollectionItemScriptParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isOverwritten = defaults.isOverwritten;
    	      this.isSecret = defaults.isSecret;
    	      this.monitorScriptParameters = defaults.monitorScriptParameters;
    	      this.paramName = defaults.paramName;
    	      this.paramValue = defaults.paramValue;
        }

        public Builder isOverwritten(Boolean isOverwritten) {
            this.isOverwritten = Objects.requireNonNull(isOverwritten);
            return this;
        }
        public Builder isSecret(Boolean isSecret) {
            this.isSecret = Objects.requireNonNull(isSecret);
            return this;
        }
        public Builder monitorScriptParameters(List<GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter> monitorScriptParameters) {
            this.monitorScriptParameters = Objects.requireNonNull(monitorScriptParameters);
            return this;
        }
        public Builder monitorScriptParameters(GetMonitorsMonitorCollectionItemScriptParameterMonitorScriptParameter... monitorScriptParameters) {
            return monitorScriptParameters(List.of(monitorScriptParameters));
        }
        public Builder paramName(String paramName) {
            this.paramName = Objects.requireNonNull(paramName);
            return this;
        }
        public Builder paramValue(String paramValue) {
            this.paramValue = Objects.requireNonNull(paramValue);
            return this;
        }        public GetMonitorsMonitorCollectionItemScriptParameter build() {
            return new GetMonitorsMonitorCollectionItemScriptParameter(isOverwritten, isSecret, monitorScriptParameters, paramName, paramValue);
        }
    }
}
