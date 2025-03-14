// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataIntegration.outputs.WorkspaceTaskOpConfigValuesConfigParamValues;
import com.pulumi.oci.DataIntegration.outputs.WorkspaceTaskOpConfigValuesParentRef;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class WorkspaceTaskOpConfigValues {
    /**
     * @return (Updatable) The configuration parameter values.
     * 
     */
    private @Nullable WorkspaceTaskOpConfigValuesConfigParamValues configParamValues;
    /**
     * @return (Updatable) A reference to the object&#39;s parent.
     * 
     */
    private @Nullable WorkspaceTaskOpConfigValuesParentRef parentRef;

    private WorkspaceTaskOpConfigValues() {}
    /**
     * @return (Updatable) The configuration parameter values.
     * 
     */
    public Optional<WorkspaceTaskOpConfigValuesConfigParamValues> configParamValues() {
        return Optional.ofNullable(this.configParamValues);
    }
    /**
     * @return (Updatable) A reference to the object&#39;s parent.
     * 
     */
    public Optional<WorkspaceTaskOpConfigValuesParentRef> parentRef() {
        return Optional.ofNullable(this.parentRef);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(WorkspaceTaskOpConfigValues defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable WorkspaceTaskOpConfigValuesConfigParamValues configParamValues;
        private @Nullable WorkspaceTaskOpConfigValuesParentRef parentRef;
        public Builder() {}
        public Builder(WorkspaceTaskOpConfigValues defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configParamValues = defaults.configParamValues;
    	      this.parentRef = defaults.parentRef;
        }

        @CustomType.Setter
        public Builder configParamValues(@Nullable WorkspaceTaskOpConfigValuesConfigParamValues configParamValues) {

            this.configParamValues = configParamValues;
            return this;
        }
        @CustomType.Setter
        public Builder parentRef(@Nullable WorkspaceTaskOpConfigValuesParentRef parentRef) {

            this.parentRef = parentRef;
            return this;
        }
        public WorkspaceTaskOpConfigValues build() {
            final var _resultValue = new WorkspaceTaskOpConfigValues();
            _resultValue.configParamValues = configParamValues;
            _resultValue.parentRef = parentRef;
            return _resultValue;
        }
    }
}
