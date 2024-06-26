// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollection;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDeploymentsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of deployment_collection.
     * 
     */
    private List<GetDeploymentsDeploymentCollection> deploymentCollections;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetDeploymentsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    private @Nullable String gatewayId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the deployment.
     * 
     */
    private @Nullable String state;

    private GetDeploymentsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of deployment_collection.
     * 
     */
    public List<GetDeploymentsDeploymentCollection> deploymentCollections() {
        return this.deploymentCollections;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetDeploymentsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public Optional<String> gatewayId() {
        return Optional.ofNullable(this.gatewayId);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The current state of the deployment.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetDeploymentsDeploymentCollection> deploymentCollections;
        private @Nullable String displayName;
        private @Nullable List<GetDeploymentsFilter> filters;
        private @Nullable String gatewayId;
        private String id;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetDeploymentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.deploymentCollections = defaults.deploymentCollections;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.gatewayId = defaults.gatewayId;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder deploymentCollections(List<GetDeploymentsDeploymentCollection> deploymentCollections) {
            if (deploymentCollections == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsResult", "deploymentCollections");
            }
            this.deploymentCollections = deploymentCollections;
            return this;
        }
        public Builder deploymentCollections(GetDeploymentsDeploymentCollection... deploymentCollections) {
            return deploymentCollections(List.of(deploymentCollections));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDeploymentsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetDeploymentsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder gatewayId(@Nullable String gatewayId) {

            this.gatewayId = gatewayId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetDeploymentsResult build() {
            final var _resultValue = new GetDeploymentsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.deploymentCollections = deploymentCollections;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.gatewayId = gatewayId;
            _resultValue.id = id;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
