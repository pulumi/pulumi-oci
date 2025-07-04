// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMappingOutputVariableDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMapping {
    /**
     * @return A filter to return only resources that match the entire name given.
     * 
     */
    private String name;
    /**
     * @return The details of the output variable that will be used for mapping.
     * 
     */
    private List<GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMappingOutputVariableDetail> outputVariableDetails;

    private GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMapping() {}
    /**
     * @return A filter to return only resources that match the entire name given.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The details of the output variable that will be used for mapping.
     * 
     */
    public List<GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMappingOutputVariableDetail> outputVariableDetails() {
        return this.outputVariableDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMapping defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private List<GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMappingOutputVariableDetail> outputVariableDetails;
        public Builder() {}
        public Builder(GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMapping defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.outputVariableDetails = defaults.outputVariableDetails;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMapping", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder outputVariableDetails(List<GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMappingOutputVariableDetail> outputVariableDetails) {
            if (outputVariableDetails == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMapping", "outputVariableDetails");
            }
            this.outputVariableDetails = outputVariableDetails;
            return this;
        }
        public Builder outputVariableDetails(GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMappingOutputVariableDetail... outputVariableDetails) {
            return outputVariableDetails(List.of(outputVariableDetails));
        }
        public GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMapping build() {
            final var _resultValue = new GetRunbookVersionsRunbookVersionCollectionItemTaskOutputVariableMapping();
            _resultValue.name = name;
            _resultValue.outputVariableDetails = outputVariableDetails;
            return _resultValue;
        }
    }
}
