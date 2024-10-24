// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceTaskExecuteRestCallConfigConfigValue;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetWorkspaceTaskExecuteRestCallConfig {
    /**
     * @return Configuration values can be string, objects, or parameters.
     * 
     */
    private List<GetWorkspaceTaskExecuteRestCallConfigConfigValue> configValues;
    /**
     * @return The key of the object.
     * 
     */
    private String key;
    /**
     * @return The REST method to use.
     * 
     */
    private String methodType;
    /**
     * @return The type of the types object.
     * 
     */
    private String modelType;
    /**
     * @return The headers for the REST call.
     * 
     */
    private Map<String,String> requestHeaders;

    private GetWorkspaceTaskExecuteRestCallConfig() {}
    /**
     * @return Configuration values can be string, objects, or parameters.
     * 
     */
    public List<GetWorkspaceTaskExecuteRestCallConfigConfigValue> configValues() {
        return this.configValues;
    }
    /**
     * @return The key of the object.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The REST method to use.
     * 
     */
    public String methodType() {
        return this.methodType;
    }
    /**
     * @return The type of the types object.
     * 
     */
    public String modelType() {
        return this.modelType;
    }
    /**
     * @return The headers for the REST call.
     * 
     */
    public Map<String,String> requestHeaders() {
        return this.requestHeaders;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceTaskExecuteRestCallConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWorkspaceTaskExecuteRestCallConfigConfigValue> configValues;
        private String key;
        private String methodType;
        private String modelType;
        private Map<String,String> requestHeaders;
        public Builder() {}
        public Builder(GetWorkspaceTaskExecuteRestCallConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configValues = defaults.configValues;
    	      this.key = defaults.key;
    	      this.methodType = defaults.methodType;
    	      this.modelType = defaults.modelType;
    	      this.requestHeaders = defaults.requestHeaders;
        }

        @CustomType.Setter
        public Builder configValues(List<GetWorkspaceTaskExecuteRestCallConfigConfigValue> configValues) {
            if (configValues == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTaskExecuteRestCallConfig", "configValues");
            }
            this.configValues = configValues;
            return this;
        }
        public Builder configValues(GetWorkspaceTaskExecuteRestCallConfigConfigValue... configValues) {
            return configValues(List.of(configValues));
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTaskExecuteRestCallConfig", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder methodType(String methodType) {
            if (methodType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTaskExecuteRestCallConfig", "methodType");
            }
            this.methodType = methodType;
            return this;
        }
        @CustomType.Setter
        public Builder modelType(String modelType) {
            if (modelType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTaskExecuteRestCallConfig", "modelType");
            }
            this.modelType = modelType;
            return this;
        }
        @CustomType.Setter
        public Builder requestHeaders(Map<String,String> requestHeaders) {
            if (requestHeaders == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTaskExecuteRestCallConfig", "requestHeaders");
            }
            this.requestHeaders = requestHeaders;
            return this;
        }
        public GetWorkspaceTaskExecuteRestCallConfig build() {
            final var _resultValue = new GetWorkspaceTaskExecuteRestCallConfig();
            _resultValue.configValues = configValues;
            _resultValue.key = key;
            _resultValue.methodType = methodType;
            _resultValue.modelType = modelType;
            _resultValue.requestHeaders = requestHeaders;
            return _resultValue;
        }
    }
}
