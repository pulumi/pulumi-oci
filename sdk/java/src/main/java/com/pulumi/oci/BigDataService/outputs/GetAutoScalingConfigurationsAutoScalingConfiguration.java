// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.BigDataService.outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicy;
import com.pulumi.oci.BigDataService.outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetail;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationsAutoScalingConfiguration {
    private String bdsInstanceId;
    private String clusterAdminPassword;
    private String displayName;
    private String id;
    private Boolean isEnabled;
    private String nodeType;
    private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicy> policies;
    private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetail> policyDetails;
    private String state;
    private String timeCreated;
    private String timeUpdated;

    private GetAutoScalingConfigurationsAutoScalingConfiguration() {}
    public String bdsInstanceId() {
        return this.bdsInstanceId;
    }
    public String clusterAdminPassword() {
        return this.clusterAdminPassword;
    }
    public String displayName() {
        return this.displayName;
    }
    public String id() {
        return this.id;
    }
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    public String nodeType() {
        return this.nodeType;
    }
    public List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicy> policies() {
        return this.policies;
    }
    public List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetail> policyDetails() {
        return this.policyDetails;
    }
    public String state() {
        return this.state;
    }
    public String timeCreated() {
        return this.timeCreated;
    }
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutoScalingConfigurationsAutoScalingConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bdsInstanceId;
        private String clusterAdminPassword;
        private String displayName;
        private String id;
        private Boolean isEnabled;
        private String nodeType;
        private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicy> policies;
        private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetail> policyDetails;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationsAutoScalingConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bdsInstanceId = defaults.bdsInstanceId;
    	      this.clusterAdminPassword = defaults.clusterAdminPassword;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.nodeType = defaults.nodeType;
    	      this.policies = defaults.policies;
    	      this.policyDetails = defaults.policyDetails;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder bdsInstanceId(String bdsInstanceId) {
            this.bdsInstanceId = Objects.requireNonNull(bdsInstanceId);
            return this;
        }
        @CustomType.Setter
        public Builder clusterAdminPassword(String clusterAdminPassword) {
            this.clusterAdminPassword = Objects.requireNonNull(clusterAdminPassword);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder nodeType(String nodeType) {
            this.nodeType = Objects.requireNonNull(nodeType);
            return this;
        }
        @CustomType.Setter
        public Builder policies(List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicy> policies) {
            this.policies = Objects.requireNonNull(policies);
            return this;
        }
        public Builder policies(GetAutoScalingConfigurationsAutoScalingConfigurationPolicy... policies) {
            return policies(List.of(policies));
        }
        @CustomType.Setter
        public Builder policyDetails(List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetail> policyDetails) {
            this.policyDetails = Objects.requireNonNull(policyDetails);
            return this;
        }
        public Builder policyDetails(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetail... policyDetails) {
            return policyDetails(List.of(policyDetails));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetAutoScalingConfigurationsAutoScalingConfiguration build() {
            final var o = new GetAutoScalingConfigurationsAutoScalingConfiguration();
            o.bdsInstanceId = bdsInstanceId;
            o.clusterAdminPassword = clusterAdminPassword;
            o.displayName = displayName;
            o.id = id;
            o.isEnabled = isEnabled;
            o.nodeType = nodeType;
            o.policies = policies;
            o.policyDetails = policyDetails;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}