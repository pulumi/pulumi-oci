// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemAction;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestAccessControl;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtection;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimiting;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseAccessControl;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem {
    /**
     * @return Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
     * 
     */
    private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemAction> actions;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return A filter to return only the WebAppFirewallPolicy with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name &#39;Default Action&#39; are not allowed, since this name is reserved for default action logs.
     * 
     */
    private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestAccessControl> requestAccessControls;
    /**
     * @return Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
     * 
     */
    private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtection> requestProtections;
    /**
     * @return Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
     * 
     */
    private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimiting> requestRateLimitings;
    /**
     * @return Module that allows inspection of HTTP response properties and to return a defined HTTP response.
     * 
     */
    private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseAccessControl> responseAccessControls;
    /**
     * @return Module that allows to enable OCI-managed protection capabilities for HTTP responses.
     * 
     */
    private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection> responseProtections;
    /**
     * @return A filter to return only resources that match the given lifecycleState.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time the WebAppFirewallPolicy was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time the WebAppFirewallPolicy was updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;

    private GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem() {}
    /**
     * @return Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
     * 
     */
    public List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemAction> actions() {
        return this.actions;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
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
     * @return A filter to return only resources that match the entire display name given.
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
     * @return A filter to return only the WebAppFirewallPolicy with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
     * @return Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name &#39;Default Action&#39; are not allowed, since this name is reserved for default action logs.
     * 
     */
    public List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestAccessControl> requestAccessControls() {
        return this.requestAccessControls;
    }
    /**
     * @return Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
     * 
     */
    public List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtection> requestProtections() {
        return this.requestProtections;
    }
    /**
     * @return Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
     * 
     */
    public List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimiting> requestRateLimitings() {
        return this.requestRateLimitings;
    }
    /**
     * @return Module that allows inspection of HTTP response properties and to return a defined HTTP response.
     * 
     */
    public List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseAccessControl> responseAccessControls() {
        return this.responseAccessControls;
    }
    /**
     * @return Module that allows to enable OCI-managed protection capabilities for HTTP responses.
     * 
     */
    public List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection> responseProtections() {
        return this.responseProtections;
    }
    /**
     * @return A filter to return only resources that match the given lifecycleState.
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
     * @return The time the WebAppFirewallPolicy was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the WebAppFirewallPolicy was updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemAction> actions;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestAccessControl> requestAccessControls;
        private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtection> requestProtections;
        private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimiting> requestRateLimitings;
        private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseAccessControl> responseAccessControls;
        private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection> responseProtections;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actions = defaults.actions;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.requestAccessControls = defaults.requestAccessControls;
    	      this.requestProtections = defaults.requestProtections;
    	      this.requestRateLimitings = defaults.requestRateLimitings;
    	      this.responseAccessControls = defaults.responseAccessControls;
    	      this.responseProtections = defaults.responseProtections;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder actions(List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemAction> actions) {
            this.actions = Objects.requireNonNull(actions);
            return this;
        }
        public Builder actions(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemAction... actions) {
            return actions(List.of(actions));
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
        public Builder requestAccessControls(List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestAccessControl> requestAccessControls) {
            this.requestAccessControls = Objects.requireNonNull(requestAccessControls);
            return this;
        }
        public Builder requestAccessControls(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestAccessControl... requestAccessControls) {
            return requestAccessControls(List.of(requestAccessControls));
        }
        @CustomType.Setter
        public Builder requestProtections(List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtection> requestProtections) {
            this.requestProtections = Objects.requireNonNull(requestProtections);
            return this;
        }
        public Builder requestProtections(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtection... requestProtections) {
            return requestProtections(List.of(requestProtections));
        }
        @CustomType.Setter
        public Builder requestRateLimitings(List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimiting> requestRateLimitings) {
            this.requestRateLimitings = Objects.requireNonNull(requestRateLimitings);
            return this;
        }
        public Builder requestRateLimitings(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimiting... requestRateLimitings) {
            return requestRateLimitings(List.of(requestRateLimitings));
        }
        @CustomType.Setter
        public Builder responseAccessControls(List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseAccessControl> responseAccessControls) {
            this.responseAccessControls = Objects.requireNonNull(responseAccessControls);
            return this;
        }
        public Builder responseAccessControls(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseAccessControl... responseAccessControls) {
            return responseAccessControls(List.of(responseAccessControls));
        }
        @CustomType.Setter
        public Builder responseProtections(List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection> responseProtections) {
            this.responseProtections = Objects.requireNonNull(responseProtections);
            return this;
        }
        public Builder responseProtections(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection... responseProtections) {
            return responseProtections(List.of(responseProtections));
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
        public GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem build() {
            final var o = new GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItem();
            o.actions = actions;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.requestAccessControls = requestAccessControls;
            o.requestProtections = requestProtections;
            o.requestRateLimitings = requestRateLimitings;
            o.responseAccessControls = responseAccessControls;
            o.responseProtections = responseProtections;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}