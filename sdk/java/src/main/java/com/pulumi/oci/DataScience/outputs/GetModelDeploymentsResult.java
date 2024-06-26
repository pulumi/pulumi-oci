// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.outputs.GetModelDeploymentsFilter;
import com.pulumi.oci.DataScience.outputs.GetModelDeploymentsModelDeployment;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetModelDeploymentsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment&#39;s compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model deployment.
     * 
     */
    private @Nullable String createdBy;
    /**
     * @return A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetModelDeploymentsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment.
     * 
     */
    private @Nullable String id;
    /**
     * @return The list of model_deployments.
     * 
     */
    private List<GetModelDeploymentsModelDeployment> modelDeployments;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the model deployment.
     * 
     */
    private @Nullable String projectId;
    /**
     * @return The state of the model deployment.
     * 
     */
    private @Nullable String state;

    private GetModelDeploymentsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment&#39;s compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model deployment.
     * 
     */
    public Optional<String> createdBy() {
        return Optional.ofNullable(this.createdBy);
    }
    /**
     * @return A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetModelDeploymentsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The list of model_deployments.
     * 
     */
    public List<GetModelDeploymentsModelDeployment> modelDeployments() {
        return this.modelDeployments;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the model deployment.
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }
    /**
     * @return The state of the model deployment.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelDeploymentsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String createdBy;
        private @Nullable String displayName;
        private @Nullable List<GetModelDeploymentsFilter> filters;
        private @Nullable String id;
        private List<GetModelDeploymentsModelDeployment> modelDeployments;
        private @Nullable String projectId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetModelDeploymentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.createdBy = defaults.createdBy;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.modelDeployments = defaults.modelDeployments;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder createdBy(@Nullable String createdBy) {

            this.createdBy = createdBy;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetModelDeploymentsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetModelDeploymentsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder modelDeployments(List<GetModelDeploymentsModelDeployment> modelDeployments) {
            if (modelDeployments == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentsResult", "modelDeployments");
            }
            this.modelDeployments = modelDeployments;
            return this;
        }
        public Builder modelDeployments(GetModelDeploymentsModelDeployment... modelDeployments) {
            return modelDeployments(List.of(modelDeployments));
        }
        @CustomType.Setter
        public Builder projectId(@Nullable String projectId) {

            this.projectId = projectId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetModelDeploymentsResult build() {
            final var _resultValue = new GetModelDeploymentsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.createdBy = createdBy;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.modelDeployments = modelDeployments;
            _resultValue.projectId = projectId;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
