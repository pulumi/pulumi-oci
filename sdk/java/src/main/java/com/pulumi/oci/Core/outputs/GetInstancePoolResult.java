// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstancePoolLoadBalancer;
import com.pulumi.oci.Core.outputs.GetInstancePoolPlacementConfiguration;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetInstancePoolResult {
    private Integer actualSize;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attachment.
     * 
     */
    private String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
     * 
     */
    private String instanceConfigurationId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool of the load balancer attachment.
     * 
     */
    private String instancePoolId;
    /**
     * @return The load balancers attached to the instance pool.
     * 
     */
    private List<GetInstancePoolLoadBalancer> loadBalancers;
    /**
     * @return The placement configurations for the instance pool.
     * 
     */
    private List<GetInstancePoolPlacementConfiguration> placementConfigurations;
    /**
     * @return The number of actual instances in the instance pool on the cloud. This attribute will be different when instance pool is used along with autoScaling Configuration.
     * 
     */
    private Integer size;
    /**
     * @return The current state of the instance pool.
     * 
     */
    private String state;
    /**
     * @return The date and time the instance pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;

    private GetInstancePoolResult() {}
    public Integer actualSize() {
        return this.actualSize;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attachment.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
     * 
     */
    public String instanceConfigurationId() {
        return this.instanceConfigurationId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool of the load balancer attachment.
     * 
     */
    public String instancePoolId() {
        return this.instancePoolId;
    }
    /**
     * @return The load balancers attached to the instance pool.
     * 
     */
    public List<GetInstancePoolLoadBalancer> loadBalancers() {
        return this.loadBalancers;
    }
    /**
     * @return The placement configurations for the instance pool.
     * 
     */
    public List<GetInstancePoolPlacementConfiguration> placementConfigurations() {
        return this.placementConfigurations;
    }
    /**
     * @return The number of actual instances in the instance pool on the cloud. This attribute will be different when instance pool is used along with autoScaling Configuration.
     * 
     */
    public Integer size() {
        return this.size;
    }
    /**
     * @return The current state of the instance pool.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the instance pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstancePoolResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer actualSize;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String instanceConfigurationId;
        private String instancePoolId;
        private List<GetInstancePoolLoadBalancer> loadBalancers;
        private List<GetInstancePoolPlacementConfiguration> placementConfigurations;
        private Integer size;
        private String state;
        private String timeCreated;
        public Builder() {}
        public Builder(GetInstancePoolResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actualSize = defaults.actualSize;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.instanceConfigurationId = defaults.instanceConfigurationId;
    	      this.instancePoolId = defaults.instancePoolId;
    	      this.loadBalancers = defaults.loadBalancers;
    	      this.placementConfigurations = defaults.placementConfigurations;
    	      this.size = defaults.size;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder actualSize(Integer actualSize) {
            this.actualSize = Objects.requireNonNull(actualSize);
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
        public Builder instanceConfigurationId(String instanceConfigurationId) {
            this.instanceConfigurationId = Objects.requireNonNull(instanceConfigurationId);
            return this;
        }
        @CustomType.Setter
        public Builder instancePoolId(String instancePoolId) {
            this.instancePoolId = Objects.requireNonNull(instancePoolId);
            return this;
        }
        @CustomType.Setter
        public Builder loadBalancers(List<GetInstancePoolLoadBalancer> loadBalancers) {
            this.loadBalancers = Objects.requireNonNull(loadBalancers);
            return this;
        }
        public Builder loadBalancers(GetInstancePoolLoadBalancer... loadBalancers) {
            return loadBalancers(List.of(loadBalancers));
        }
        @CustomType.Setter
        public Builder placementConfigurations(List<GetInstancePoolPlacementConfiguration> placementConfigurations) {
            this.placementConfigurations = Objects.requireNonNull(placementConfigurations);
            return this;
        }
        public Builder placementConfigurations(GetInstancePoolPlacementConfiguration... placementConfigurations) {
            return placementConfigurations(List.of(placementConfigurations));
        }
        @CustomType.Setter
        public Builder size(Integer size) {
            this.size = Objects.requireNonNull(size);
            return this;
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
        public GetInstancePoolResult build() {
            final var o = new GetInstancePoolResult();
            o.actualSize = actualSize;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.instanceConfigurationId = instanceConfigurationId;
            o.instancePoolId = instancePoolId;
            o.loadBalancers = loadBalancers;
            o.placementConfigurations = placementConfigurations;
            o.size = size;
            o.state = state;
            o.timeCreated = timeCreated;
            return o;
        }
    }
}