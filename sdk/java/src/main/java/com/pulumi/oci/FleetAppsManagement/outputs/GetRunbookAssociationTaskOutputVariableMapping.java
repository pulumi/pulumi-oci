// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbookAssociationTaskOutputVariableMappingOutputVariableDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRunbookAssociationTaskOutputVariableMapping {
    /**
     * @return The name of the task
     * 
     */
    private String name;
    /**
     * @return The details of the output variable that will be used for mapping.
     * 
     */
    private List<GetRunbookAssociationTaskOutputVariableMappingOutputVariableDetail> outputVariableDetails;

    private GetRunbookAssociationTaskOutputVariableMapping() {}
    /**
     * @return The name of the task
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The details of the output variable that will be used for mapping.
     * 
     */
    public List<GetRunbookAssociationTaskOutputVariableMappingOutputVariableDetail> outputVariableDetails() {
        return this.outputVariableDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRunbookAssociationTaskOutputVariableMapping defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private List<GetRunbookAssociationTaskOutputVariableMappingOutputVariableDetail> outputVariableDetails;
        public Builder() {}
        public Builder(GetRunbookAssociationTaskOutputVariableMapping defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.outputVariableDetails = defaults.outputVariableDetails;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetRunbookAssociationTaskOutputVariableMapping", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder outputVariableDetails(List<GetRunbookAssociationTaskOutputVariableMappingOutputVariableDetail> outputVariableDetails) {
            if (outputVariableDetails == null) {
              throw new MissingRequiredPropertyException("GetRunbookAssociationTaskOutputVariableMapping", "outputVariableDetails");
            }
            this.outputVariableDetails = outputVariableDetails;
            return this;
        }
        public Builder outputVariableDetails(GetRunbookAssociationTaskOutputVariableMappingOutputVariableDetail... outputVariableDetails) {
            return outputVariableDetails(List.of(outputVariableDetails));
        }
        public GetRunbookAssociationTaskOutputVariableMapping build() {
            final var _resultValue = new GetRunbookAssociationTaskOutputVariableMapping();
            _resultValue.name = name;
            _resultValue.outputVariableDetails = outputVariableDetails;
            return _resultValue;
        }
    }
}
