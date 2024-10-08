// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetNetworkSourcesNetworkSourceVirtualSourceList;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetNetworkSourcesNetworkSource {
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The description you assign to the network source. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    private String description;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the network source.
     * 
     */
    private String id;
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    private String inactiveState;
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    private String name;
    /**
     * @return A list of allowed public IP addresses and CIDR ranges.
     * 
     */
    private List<String> publicSourceLists;
    /**
     * @return A list of services allowed to make on-behalf-of requests. These requests can have different source IPs than those specified in the network source. Currently, only `all` and `none` are supported. The default is `all`.
     * 
     */
    private List<String> services;
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    private String state;
    /**
     * @return Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return A list of allowed VCN OCID and IP range pairs. Example:`&#34;vcnId&#34;: &#34;ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID&#34;, &#34;ipRanges&#34;: [ &#34;129.213.39.0/24&#34; ]`
     * 
     */
    private List<GetNetworkSourcesNetworkSourceVirtualSourceList> virtualSourceLists;

    private GetNetworkSourcesNetworkSource() {}
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description you assign to the network source. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the network source.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public String inactiveState() {
        return this.inactiveState;
    }
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return A list of allowed public IP addresses and CIDR ranges.
     * 
     */
    public List<String> publicSourceLists() {
        return this.publicSourceLists;
    }
    /**
     * @return A list of services allowed to make on-behalf-of requests. These requests can have different source IPs than those specified in the network source. Currently, only `all` and `none` are supported. The default is `all`.
     * 
     */
    public List<String> services() {
        return this.services;
    }
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return A list of allowed VCN OCID and IP range pairs. Example:`&#34;vcnId&#34;: &#34;ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID&#34;, &#34;ipRanges&#34;: [ &#34;129.213.39.0/24&#34; ]`
     * 
     */
    public List<GetNetworkSourcesNetworkSourceVirtualSourceList> virtualSourceLists() {
        return this.virtualSourceLists;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkSourcesNetworkSource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private Map<String,String> freeformTags;
        private String id;
        private String inactiveState;
        private String name;
        private List<String> publicSourceLists;
        private List<String> services;
        private String state;
        private String timeCreated;
        private List<GetNetworkSourcesNetworkSourceVirtualSourceList> virtualSourceLists;
        public Builder() {}
        public Builder(GetNetworkSourcesNetworkSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.inactiveState = defaults.inactiveState;
    	      this.name = defaults.name;
    	      this.publicSourceLists = defaults.publicSourceLists;
    	      this.services = defaults.services;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.virtualSourceLists = defaults.virtualSourceLists;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder inactiveState(String inactiveState) {
            if (inactiveState == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "inactiveState");
            }
            this.inactiveState = inactiveState;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder publicSourceLists(List<String> publicSourceLists) {
            if (publicSourceLists == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "publicSourceLists");
            }
            this.publicSourceLists = publicSourceLists;
            return this;
        }
        public Builder publicSourceLists(String... publicSourceLists) {
            return publicSourceLists(List.of(publicSourceLists));
        }
        @CustomType.Setter
        public Builder services(List<String> services) {
            if (services == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "services");
            }
            this.services = services;
            return this;
        }
        public Builder services(String... services) {
            return services(List.of(services));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder virtualSourceLists(List<GetNetworkSourcesNetworkSourceVirtualSourceList> virtualSourceLists) {
            if (virtualSourceLists == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourcesNetworkSource", "virtualSourceLists");
            }
            this.virtualSourceLists = virtualSourceLists;
            return this;
        }
        public Builder virtualSourceLists(GetNetworkSourcesNetworkSourceVirtualSourceList... virtualSourceLists) {
            return virtualSourceLists(List.of(virtualSourceLists));
        }
        public GetNetworkSourcesNetworkSource build() {
            final var _resultValue = new GetNetworkSourcesNetworkSource();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.inactiveState = inactiveState;
            _resultValue.name = name;
            _resultValue.publicSourceLists = publicSourceLists;
            _resultValue.services = services;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.virtualSourceLists = virtualSourceLists;
            return _resultValue;
        }
    }
}
