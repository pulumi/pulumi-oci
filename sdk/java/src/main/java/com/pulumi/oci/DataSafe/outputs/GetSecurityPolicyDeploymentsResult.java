// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSecurityPolicyDeploymentsFilter;
import com.pulumi.oci.DataSafe.outputs.GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollection;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSecurityPolicyDeploymentsResult {
    private @Nullable String accessLevel;
    /**
     * @return The OCID of the compartment containing the security policy deployment.
     * 
     */
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    /**
     * @return The display name of the security policy deployment.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetSecurityPolicyDeploymentsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of security_policy_deployment_collection.
     * 
     */
    private List<GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollection> securityPolicyDeploymentCollections;
    private @Nullable String securityPolicyDeploymentId;
    /**
     * @return The OCID of the security policy corresponding to the security policy deployment.
     * 
     */
    private @Nullable String securityPolicyId;
    /**
     * @return The current state of the security policy deployment.
     * 
     */
    private @Nullable String state;
    /**
     * @return The OCID of the target where the security policy is deployed.
     * 
     */
    private @Nullable String targetId;

    private GetSecurityPolicyDeploymentsResult() {}
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    /**
     * @return The OCID of the compartment containing the security policy deployment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    /**
     * @return The display name of the security policy deployment.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetSecurityPolicyDeploymentsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of security_policy_deployment_collection.
     * 
     */
    public List<GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollection> securityPolicyDeploymentCollections() {
        return this.securityPolicyDeploymentCollections;
    }
    public Optional<String> securityPolicyDeploymentId() {
        return Optional.ofNullable(this.securityPolicyDeploymentId);
    }
    /**
     * @return The OCID of the security policy corresponding to the security policy deployment.
     * 
     */
    public Optional<String> securityPolicyId() {
        return Optional.ofNullable(this.securityPolicyId);
    }
    /**
     * @return The current state of the security policy deployment.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The OCID of the target where the security policy is deployed.
     * 
     */
    public Optional<String> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityPolicyDeploymentsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable String displayName;
        private @Nullable List<GetSecurityPolicyDeploymentsFilter> filters;
        private String id;
        private List<GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollection> securityPolicyDeploymentCollections;
        private @Nullable String securityPolicyDeploymentId;
        private @Nullable String securityPolicyId;
        private @Nullable String state;
        private @Nullable String targetId;
        public Builder() {}
        public Builder(GetSecurityPolicyDeploymentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.securityPolicyDeploymentCollections = defaults.securityPolicyDeploymentCollections;
    	      this.securityPolicyDeploymentId = defaults.securityPolicyDeploymentId;
    	      this.securityPolicyId = defaults.securityPolicyId;
    	      this.state = defaults.state;
    	      this.targetId = defaults.targetId;
        }

        @CustomType.Setter
        public Builder accessLevel(@Nullable String accessLevel) {
            this.accessLevel = accessLevel;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSecurityPolicyDeploymentsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetSecurityPolicyDeploymentsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder securityPolicyDeploymentCollections(List<GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollection> securityPolicyDeploymentCollections) {
            this.securityPolicyDeploymentCollections = Objects.requireNonNull(securityPolicyDeploymentCollections);
            return this;
        }
        public Builder securityPolicyDeploymentCollections(GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollection... securityPolicyDeploymentCollections) {
            return securityPolicyDeploymentCollections(List.of(securityPolicyDeploymentCollections));
        }
        @CustomType.Setter
        public Builder securityPolicyDeploymentId(@Nullable String securityPolicyDeploymentId) {
            this.securityPolicyDeploymentId = securityPolicyDeploymentId;
            return this;
        }
        @CustomType.Setter
        public Builder securityPolicyId(@Nullable String securityPolicyId) {
            this.securityPolicyId = securityPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder targetId(@Nullable String targetId) {
            this.targetId = targetId;
            return this;
        }
        public GetSecurityPolicyDeploymentsResult build() {
            final var o = new GetSecurityPolicyDeploymentsResult();
            o.accessLevel = accessLevel;
            o.compartmentId = compartmentId;
            o.compartmentIdInSubtree = compartmentIdInSubtree;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.securityPolicyDeploymentCollections = securityPolicyDeploymentCollections;
            o.securityPolicyDeploymentId = securityPolicyDeploymentId;
            o.securityPolicyId = securityPolicyId;
            o.state = state;
            o.targetId = targetId;
            return o;
        }
    }
}