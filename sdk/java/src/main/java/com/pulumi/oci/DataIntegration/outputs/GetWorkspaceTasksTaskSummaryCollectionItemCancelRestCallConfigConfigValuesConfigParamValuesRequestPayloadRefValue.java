// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValueConfigValues;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue {
    /**
     * @return Configuration values can be string, objects, or parameters.
     * 
     */
    private GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValueConfigValues configValues;
    /**
     * @return Used to filter by the key of the object.
     * 
     */
    private String key;
    /**
     * @return The type of the types object.
     * 
     */
    private String modelType;

    private GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue() {}
    /**
     * @return Configuration values can be string, objects, or parameters.
     * 
     */
    public GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValueConfigValues configValues() {
        return this.configValues;
    }
    /**
     * @return Used to filter by the key of the object.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The type of the types object.
     * 
     */
    public String modelType() {
        return this.modelType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValueConfigValues configValues;
        private String key;
        private String modelType;
        public Builder() {}
        public Builder(GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configValues = defaults.configValues;
    	      this.key = defaults.key;
    	      this.modelType = defaults.modelType;
        }

        @CustomType.Setter
        public Builder configValues(GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValueConfigValues configValues) {
            if (configValues == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue", "configValues");
            }
            this.configValues = configValues;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder modelType(String modelType) {
            if (modelType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue", "modelType");
            }
            this.modelType = modelType;
            return this;
        }
        public GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue build() {
            final var _resultValue = new GetWorkspaceTasksTaskSummaryCollectionItemCancelRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue();
            _resultValue.configValues = configValues;
            _resultValue.key = key;
            _resultValue.modelType = modelType;
            return _resultValue;
        }
    }
}
