// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStateEntryDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult {
    /**
     * @return The current deployment status of the security policy deployment and the security policy entry associated.
     * 
     */
    private String deploymentStatus;
    /**
     * @return Details specific to the security policy entry.
     * 
     */
    private List<GetSecurityPolicyDeploymentSecurityPolicyEntryStateEntryDetail> entryDetails;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OCID of the security policy deployment associated.
     * 
     */
    private String securityPolicyDeploymentId;
    /**
     * @return The OCID of the security policy entry type associated.
     * 
     */
    private String securityPolicyEntryId;
    private String securityPolicyEntryStateId;

    private GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult() {}
    /**
     * @return The current deployment status of the security policy deployment and the security policy entry associated.
     * 
     */
    public String deploymentStatus() {
        return this.deploymentStatus;
    }
    /**
     * @return Details specific to the security policy entry.
     * 
     */
    public List<GetSecurityPolicyDeploymentSecurityPolicyEntryStateEntryDetail> entryDetails() {
        return this.entryDetails;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The OCID of the security policy deployment associated.
     * 
     */
    public String securityPolicyDeploymentId() {
        return this.securityPolicyDeploymentId;
    }
    /**
     * @return The OCID of the security policy entry type associated.
     * 
     */
    public String securityPolicyEntryId() {
        return this.securityPolicyEntryId;
    }
    public String securityPolicyEntryStateId() {
        return this.securityPolicyEntryStateId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String deploymentStatus;
        private List<GetSecurityPolicyDeploymentSecurityPolicyEntryStateEntryDetail> entryDetails;
        private String id;
        private String securityPolicyDeploymentId;
        private String securityPolicyEntryId;
        private String securityPolicyEntryStateId;
        public Builder() {}
        public Builder(GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deploymentStatus = defaults.deploymentStatus;
    	      this.entryDetails = defaults.entryDetails;
    	      this.id = defaults.id;
    	      this.securityPolicyDeploymentId = defaults.securityPolicyDeploymentId;
    	      this.securityPolicyEntryId = defaults.securityPolicyEntryId;
    	      this.securityPolicyEntryStateId = defaults.securityPolicyEntryStateId;
        }

        @CustomType.Setter
        public Builder deploymentStatus(String deploymentStatus) {
            this.deploymentStatus = Objects.requireNonNull(deploymentStatus);
            return this;
        }
        @CustomType.Setter
        public Builder entryDetails(List<GetSecurityPolicyDeploymentSecurityPolicyEntryStateEntryDetail> entryDetails) {
            this.entryDetails = Objects.requireNonNull(entryDetails);
            return this;
        }
        public Builder entryDetails(GetSecurityPolicyDeploymentSecurityPolicyEntryStateEntryDetail... entryDetails) {
            return entryDetails(List.of(entryDetails));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder securityPolicyDeploymentId(String securityPolicyDeploymentId) {
            this.securityPolicyDeploymentId = Objects.requireNonNull(securityPolicyDeploymentId);
            return this;
        }
        @CustomType.Setter
        public Builder securityPolicyEntryId(String securityPolicyEntryId) {
            this.securityPolicyEntryId = Objects.requireNonNull(securityPolicyEntryId);
            return this;
        }
        @CustomType.Setter
        public Builder securityPolicyEntryStateId(String securityPolicyEntryStateId) {
            this.securityPolicyEntryStateId = Objects.requireNonNull(securityPolicyEntryStateId);
            return this;
        }
        public GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult build() {
            final var o = new GetSecurityPolicyDeploymentSecurityPolicyEntryStateResult();
            o.deploymentStatus = deploymentStatus;
            o.entryDetails = entryDetails;
            o.id = id;
            o.securityPolicyDeploymentId = securityPolicyDeploymentId;
            o.securityPolicyEntryId = securityPolicyEntryId;
            o.securityPolicyEntryStateId = securityPolicyEntryStateId;
            return o;
        }
    }
}