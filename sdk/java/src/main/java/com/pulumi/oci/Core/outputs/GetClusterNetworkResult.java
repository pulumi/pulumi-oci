// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetClusterNetworkClusterConfiguration;
import com.pulumi.oci.Core.outputs.GetClusterNetworkInstancePool;
import com.pulumi.oci.Core.outputs.GetClusterNetworkPlacementConfiguration;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetClusterNetworkResult {
    private List<GetClusterNetworkClusterConfiguration> clusterConfigurations;
    private String clusterNetworkId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The display name of the VNIC. This is also used to match against the instance configuration defined secondary VNIC.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HPC island used by the cluster network.
     * 
     */
    private String hpcIslandId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attachment.
     * 
     */
    private String id;
    /**
     * @return The instance pools in the cluster network.
     * 
     */
    private List<GetClusterNetworkInstancePool> instancePools;
    /**
     * @return The list of network block OCIDs of the HPC island.
     * 
     */
    private List<String> networkBlockIds;
    /**
     * @return The location for where the instance pools in a cluster network will place instances.
     * 
     */
    private List<GetClusterNetworkPlacementConfiguration> placementConfigurations;
    /**
     * @return The current state of the cluster network.
     * 
     */
    private String state;
    /**
     * @return The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeUpdated;

    private GetClusterNetworkResult() {}
    public List<GetClusterNetworkClusterConfiguration> clusterConfigurations() {
        return this.clusterConfigurations;
    }
    public String clusterNetworkId() {
        return this.clusterNetworkId;
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
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The display name of the VNIC. This is also used to match against the instance configuration defined secondary VNIC.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HPC island used by the cluster network.
     * 
     */
    public String hpcIslandId() {
        return this.hpcIslandId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attachment.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The instance pools in the cluster network.
     * 
     */
    public List<GetClusterNetworkInstancePool> instancePools() {
        return this.instancePools;
    }
    /**
     * @return The list of network block OCIDs of the HPC island.
     * 
     */
    public List<String> networkBlockIds() {
        return this.networkBlockIds;
    }
    /**
     * @return The location for where the instance pools in a cluster network will place instances.
     * 
     */
    public List<GetClusterNetworkPlacementConfiguration> placementConfigurations() {
        return this.placementConfigurations;
    }
    /**
     * @return The current state of the cluster network.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetClusterNetworkResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetClusterNetworkClusterConfiguration> clusterConfigurations;
        private String clusterNetworkId;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String hpcIslandId;
        private String id;
        private List<GetClusterNetworkInstancePool> instancePools;
        private List<String> networkBlockIds;
        private List<GetClusterNetworkPlacementConfiguration> placementConfigurations;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetClusterNetworkResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.clusterConfigurations = defaults.clusterConfigurations;
    	      this.clusterNetworkId = defaults.clusterNetworkId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.hpcIslandId = defaults.hpcIslandId;
    	      this.id = defaults.id;
    	      this.instancePools = defaults.instancePools;
    	      this.networkBlockIds = defaults.networkBlockIds;
    	      this.placementConfigurations = defaults.placementConfigurations;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder clusterConfigurations(List<GetClusterNetworkClusterConfiguration> clusterConfigurations) {
            if (clusterConfigurations == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "clusterConfigurations");
            }
            this.clusterConfigurations = clusterConfigurations;
            return this;
        }
        public Builder clusterConfigurations(GetClusterNetworkClusterConfiguration... clusterConfigurations) {
            return clusterConfigurations(List.of(clusterConfigurations));
        }
        @CustomType.Setter
        public Builder clusterNetworkId(String clusterNetworkId) {
            if (clusterNetworkId == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "clusterNetworkId");
            }
            this.clusterNetworkId = clusterNetworkId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder hpcIslandId(String hpcIslandId) {
            if (hpcIslandId == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "hpcIslandId");
            }
            this.hpcIslandId = hpcIslandId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instancePools(List<GetClusterNetworkInstancePool> instancePools) {
            if (instancePools == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "instancePools");
            }
            this.instancePools = instancePools;
            return this;
        }
        public Builder instancePools(GetClusterNetworkInstancePool... instancePools) {
            return instancePools(List.of(instancePools));
        }
        @CustomType.Setter
        public Builder networkBlockIds(List<String> networkBlockIds) {
            if (networkBlockIds == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "networkBlockIds");
            }
            this.networkBlockIds = networkBlockIds;
            return this;
        }
        public Builder networkBlockIds(String... networkBlockIds) {
            return networkBlockIds(List.of(networkBlockIds));
        }
        @CustomType.Setter
        public Builder placementConfigurations(List<GetClusterNetworkPlacementConfiguration> placementConfigurations) {
            if (placementConfigurations == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "placementConfigurations");
            }
            this.placementConfigurations = placementConfigurations;
            return this;
        }
        public Builder placementConfigurations(GetClusterNetworkPlacementConfiguration... placementConfigurations) {
            return placementConfigurations(List.of(placementConfigurations));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetClusterNetworkResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetClusterNetworkResult build() {
            final var _resultValue = new GetClusterNetworkResult();
            _resultValue.clusterConfigurations = clusterConfigurations;
            _resultValue.clusterNetworkId = clusterNetworkId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.hpcIslandId = hpcIslandId;
            _resultValue.id = id;
            _resultValue.instancePools = instancePools;
            _resultValue.networkBlockIds = networkBlockIds;
            _resultValue.placementConfigurations = placementConfigurations;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
