// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetailOutputVariableDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetail {
    /**
     * @return The details of the output variable that will be used for mapping.
     * 
     */
    private List<GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetailOutputVariableDetail> outputVariableDetails;
    /**
     * @return Resource Ocid.
     * 
     */
    private String resourceId;
    /**
     * @return Resource Type.
     * 
     */
    private String resourceType;

    private GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetail() {}
    /**
     * @return The details of the output variable that will be used for mapping.
     * 
     */
    public List<GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetailOutputVariableDetail> outputVariableDetails() {
        return this.outputVariableDetails;
    }
    /**
     * @return Resource Ocid.
     * 
     */
    public String resourceId() {
        return this.resourceId;
    }
    /**
     * @return Resource Type.
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetailOutputVariableDetail> outputVariableDetails;
        private String resourceId;
        private String resourceType;
        public Builder() {}
        public Builder(GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.outputVariableDetails = defaults.outputVariableDetails;
    	      this.resourceId = defaults.resourceId;
    	      this.resourceType = defaults.resourceType;
        }

        @CustomType.Setter
        public Builder outputVariableDetails(List<GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetailOutputVariableDetail> outputVariableDetails) {
            if (outputVariableDetails == null) {
              throw new MissingRequiredPropertyException("GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetail", "outputVariableDetails");
            }
            this.outputVariableDetails = outputVariableDetails;
            return this;
        }
        public Builder outputVariableDetails(GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetailOutputVariableDetail... outputVariableDetails) {
            return outputVariableDetails(List.of(outputVariableDetails));
        }
        @CustomType.Setter
        public Builder resourceId(String resourceId) {
            if (resourceId == null) {
              throw new MissingRequiredPropertyException("GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetail", "resourceId");
            }
            this.resourceId = resourceId;
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(String resourceType) {
            if (resourceType == null) {
              throw new MissingRequiredPropertyException("GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetail", "resourceType");
            }
            this.resourceType = resourceType;
            return this;
        }
        public GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetail build() {
            final var _resultValue = new GetRunbookRunbookVersionGroupPropertyRunOnPreviousTaskInstanceDetail();
            _resultValue.outputVariableDetails = outputVariableDetails;
            _resultValue.resourceId = resourceId;
            _resultValue.resourceType = resourceType;
            return _resultValue;
        }
    }
}
