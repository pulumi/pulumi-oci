// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GoldenGate.outputs.GetDeploymentsDeploymentCollection;
import com.pulumi.oci.GoldenGate.outputs.GetDeploymentsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDeploymentsResult {
    private @Nullable String assignableConnectionId;
    private @Nullable String assignedConnectionId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of deployment_collection.
     * 
     */
    private List<GetDeploymentsDeploymentCollection> deploymentCollections;
    /**
     * @return An object&#39;s Display Name.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetDeploymentsFilter> filters;
    /**
     * @return A three-label Fully Qualified Domain Name (FQDN) for a resource.
     * 
     */
    private @Nullable String fqdn;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Possible GGS lifecycle sub-states.
     * 
     */
    private @Nullable String lifecycleSubState;
    /**
     * @return Possible lifecycle states.
     * 
     */
    private @Nullable String state;
    private @Nullable String supportedConnectionType;

    private GetDeploymentsResult() {}
    public Optional<String> assignableConnectionId() {
        return Optional.ofNullable(this.assignableConnectionId);
    }
    public Optional<String> assignedConnectionId() {
        return Optional.ofNullable(this.assignedConnectionId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
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
     * @return An object&#39;s Display Name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetDeploymentsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return A three-label Fully Qualified Domain Name (FQDN) for a resource.
     * 
     */
    public Optional<String> fqdn() {
        return Optional.ofNullable(this.fqdn);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Possible GGS lifecycle sub-states.
     * 
     */
    public Optional<String> lifecycleSubState() {
        return Optional.ofNullable(this.lifecycleSubState);
    }
    /**
     * @return Possible lifecycle states.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    public Optional<String> supportedConnectionType() {
        return Optional.ofNullable(this.supportedConnectionType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String assignableConnectionId;
        private @Nullable String assignedConnectionId;
        private String compartmentId;
        private List<GetDeploymentsDeploymentCollection> deploymentCollections;
        private @Nullable String displayName;
        private @Nullable List<GetDeploymentsFilter> filters;
        private @Nullable String fqdn;
        private String id;
        private @Nullable String lifecycleSubState;
        private @Nullable String state;
        private @Nullable String supportedConnectionType;
        public Builder() {}
        public Builder(GetDeploymentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.assignableConnectionId = defaults.assignableConnectionId;
    	      this.assignedConnectionId = defaults.assignedConnectionId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.deploymentCollections = defaults.deploymentCollections;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.fqdn = defaults.fqdn;
    	      this.id = defaults.id;
    	      this.lifecycleSubState = defaults.lifecycleSubState;
    	      this.state = defaults.state;
    	      this.supportedConnectionType = defaults.supportedConnectionType;
        }

        @CustomType.Setter
        public Builder assignableConnectionId(@Nullable String assignableConnectionId) {

            this.assignableConnectionId = assignableConnectionId;
            return this;
        }
        @CustomType.Setter
        public Builder assignedConnectionId(@Nullable String assignedConnectionId) {

            this.assignedConnectionId = assignedConnectionId;
            return this;
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
        public Builder fqdn(@Nullable String fqdn) {

            this.fqdn = fqdn;
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
        public Builder lifecycleSubState(@Nullable String lifecycleSubState) {

            this.lifecycleSubState = lifecycleSubState;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder supportedConnectionType(@Nullable String supportedConnectionType) {

            this.supportedConnectionType = supportedConnectionType;
            return this;
        }
        public GetDeploymentsResult build() {
            final var _resultValue = new GetDeploymentsResult();
            _resultValue.assignableConnectionId = assignableConnectionId;
            _resultValue.assignedConnectionId = assignedConnectionId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.deploymentCollections = deploymentCollections;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.fqdn = fqdn;
            _resultValue.id = id;
            _resultValue.lifecycleSubState = lifecycleSubState;
            _resultValue.state = state;
            _resultValue.supportedConnectionType = supportedConnectionType;
            return _resultValue;
        }
    }
}
