// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValuesConfigParamValues;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValuesParentRef;
import java.util.Objects;

@CustomType
public final class GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValues {
    /**
     * @return The configuration parameter values.
     * 
     */
    private GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValuesConfigParamValues configParamValues;
    /**
     * @return A reference to the object&#39;s parent.
     * 
     */
    private GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValuesParentRef parentRef;

    private GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValues() {}
    /**
     * @return The configuration parameter values.
     * 
     */
    public GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValuesConfigParamValues configParamValues() {
        return this.configParamValues;
    }
    /**
     * @return A reference to the object&#39;s parent.
     * 
     */
    public GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValuesParentRef parentRef() {
        return this.parentRef;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValues defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValuesConfigParamValues configParamValues;
        private GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValuesParentRef parentRef;
        public Builder() {}
        public Builder(GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValues defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configParamValues = defaults.configParamValues;
    	      this.parentRef = defaults.parentRef;
        }

        @CustomType.Setter
        public Builder configParamValues(GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValuesConfigParamValues configParamValues) {
            if (configParamValues == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValues", "configParamValues");
            }
            this.configParamValues = configParamValues;
            return this;
        }
        @CustomType.Setter
        public Builder parentRef(GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValuesParentRef parentRef) {
            if (parentRef == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValues", "parentRef");
            }
            this.parentRef = parentRef;
            return this;
        }
        public GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValues build() {
            final var _resultValue = new GetWorkspaceTasksTaskSummaryCollectionItemInputPortConfigValues();
            _resultValue.configParamValues = configParamValues;
            _resultValue.parentRef = parentRef;
            return _resultValue;
        }
    }
}
