// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetWebAppFirewallResult {
    /**
     * @return Type of the WebAppFirewall, as example LOAD_BALANCER.
     * 
     */
    private String backendType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return WebAppFirewall display name, can be renamed.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return LoadBalancer [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to which the WebAppFirewallPolicy is attached to.
     * 
     */
    private String loadBalancerId;
    /**
     * @return The current state of the WebAppFirewall.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time the WebAppFirewall was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time the WebAppFirewall was updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;
    private String webAppFirewallId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of WebAppFirewallPolicy, which is attached to the resource.
     * 
     */
    private String webAppFirewallPolicyId;

    private GetWebAppFirewallResult() {}
    /**
     * @return Type of the WebAppFirewall, as example LOAD_BALANCER.
     * 
     */
    public String backendType() {
        return this.backendType;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return WebAppFirewall display name, can be renamed.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return LoadBalancer [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to which the WebAppFirewallPolicy is attached to.
     * 
     */
    public String loadBalancerId() {
        return this.loadBalancerId;
    }
    /**
     * @return The current state of the WebAppFirewall.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time the WebAppFirewall was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the WebAppFirewall was updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    public String webAppFirewallId() {
        return this.webAppFirewallId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of WebAppFirewallPolicy, which is attached to the resource.
     * 
     */
    public String webAppFirewallPolicyId() {
        return this.webAppFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWebAppFirewallResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String backendType;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String loadBalancerId;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private String webAppFirewallId;
        private String webAppFirewallPolicyId;
        public Builder() {}
        public Builder(GetWebAppFirewallResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backendType = defaults.backendType;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.loadBalancerId = defaults.loadBalancerId;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.webAppFirewallId = defaults.webAppFirewallId;
    	      this.webAppFirewallPolicyId = defaults.webAppFirewallPolicyId;
        }

        @CustomType.Setter
        public Builder backendType(String backendType) {
            this.backendType = Objects.requireNonNull(backendType);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder loadBalancerId(String loadBalancerId) {
            this.loadBalancerId = Objects.requireNonNull(loadBalancerId);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
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
        @CustomType.Setter
        public Builder webAppFirewallId(String webAppFirewallId) {
            this.webAppFirewallId = Objects.requireNonNull(webAppFirewallId);
            return this;
        }
        @CustomType.Setter
        public Builder webAppFirewallPolicyId(String webAppFirewallPolicyId) {
            this.webAppFirewallPolicyId = Objects.requireNonNull(webAppFirewallPolicyId);
            return this;
        }
        public GetWebAppFirewallResult build() {
            final var o = new GetWebAppFirewallResult();
            o.backendType = backendType;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.loadBalancerId = loadBalancerId;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.webAppFirewallId = webAppFirewallId;
            o.webAppFirewallPolicyId = webAppFirewallPolicyId;
            return o;
        }
    }
}