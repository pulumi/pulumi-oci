// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataIntegration.outputs.WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValueConfigValues;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue {
    /**
     * @return Configuration values can be string, objects, or parameters.
     * 
     */
    private @Nullable WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValueConfigValues configValues;
    /**
     * @return (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
     * 
     */
    private @Nullable String key;
    /**
     * @return (Updatable) The type of the task.
     * 
     */
    private @Nullable String modelType;
    /**
     * @return (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    private @Nullable String name;

    private WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue() {}
    /**
     * @return Configuration values can be string, objects, or parameters.
     * 
     */
    public Optional<WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValueConfigValues> configValues() {
        return Optional.ofNullable(this.configValues);
    }
    /**
     * @return (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
     * 
     */
    public Optional<String> key() {
        return Optional.ofNullable(this.key);
    }
    /**
     * @return (Updatable) The type of the task.
     * 
     */
    public Optional<String> modelType() {
        return Optional.ofNullable(this.modelType);
    }
    /**
     * @return (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValueConfigValues configValues;
        private @Nullable String key;
        private @Nullable String modelType;
        private @Nullable String name;
        public Builder() {}
        public Builder(WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configValues = defaults.configValues;
    	      this.key = defaults.key;
    	      this.modelType = defaults.modelType;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder configValues(@Nullable WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValueConfigValues configValues) {

            this.configValues = configValues;
            return this;
        }
        @CustomType.Setter
        public Builder key(@Nullable String key) {

            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder modelType(@Nullable String modelType) {

            this.modelType = modelType;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        public WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue build() {
            final var _resultValue = new WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadRefValue();
            _resultValue.configValues = configValues;
            _resultValue.key = key;
            _resultValue.modelType = modelType;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
