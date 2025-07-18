// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetComputeHostsComputeHostCollectionItem {
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Capacity Reserver that is currently on host
     * 
     */
    private String capacityReservationId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group.
     * 
     */
    private String computeHostGroupId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    private String displayName;
    /**
     * @return A fault domain is a grouping of hardware and infrastructure within an availability domain. Each availability domain contains three fault domains. Fault domains let you distribute your instances so that they are not on the same physical hardware within a single availability domain. A hardware failure or Compute hardware maintenance that affects one fault domain does not affect instances in other fault domains.
     * 
     */
    private String faultDomain;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique GPU Memory Fabric
     * 
     */
    private String gpuMemoryFabricId;
    private Boolean hasImpactedComponents;
    /**
     * @return The heathy state of the host
     * 
     */
    private String health;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique HPC Island
     * 
     */
    private String hpcIslandId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Customer-unique host
     * 
     */
    private String id;
    /**
     * @return The public [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Virtual Machine or Bare Metal instance
     * 
     */
    private String instanceId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique Local Block
     * 
     */
    private String localBlockId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique Network Block
     * 
     */
    private String networkBlockId;
    /**
     * @return The shape of host
     * 
     */
    private String shape;
    /**
     * @return The lifecycle state of the host
     * 
     */
    private String state;
    /**
     * @return The date and time that the compute host record was created, in the format defined by [RFC3339](https://tools .ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time that the compute host record was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeUpdated;

    private GetComputeHostsComputeHostCollectionItem() {}
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Capacity Reserver that is currently on host
     * 
     */
    public String capacityReservationId() {
        return this.capacityReservationId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group.
     * 
     */
    public String computeHostGroupId() {
        return this.computeHostGroupId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return A fault domain is a grouping of hardware and infrastructure within an availability domain. Each availability domain contains three fault domains. Fault domains let you distribute your instances so that they are not on the same physical hardware within a single availability domain. A hardware failure or Compute hardware maintenance that affects one fault domain does not affect instances in other fault domains.
     * 
     */
    public String faultDomain() {
        return this.faultDomain;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique GPU Memory Fabric
     * 
     */
    public String gpuMemoryFabricId() {
        return this.gpuMemoryFabricId;
    }
    public Boolean hasImpactedComponents() {
        return this.hasImpactedComponents;
    }
    /**
     * @return The heathy state of the host
     * 
     */
    public String health() {
        return this.health;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique HPC Island
     * 
     */
    public String hpcIslandId() {
        return this.hpcIslandId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Customer-unique host
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The public [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Virtual Machine or Bare Metal instance
     * 
     */
    public String instanceId() {
        return this.instanceId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique Local Block
     * 
     */
    public String localBlockId() {
        return this.localBlockId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique Network Block
     * 
     */
    public String networkBlockId() {
        return this.networkBlockId;
    }
    /**
     * @return The shape of host
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return The lifecycle state of the host
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time that the compute host record was created, in the format defined by [RFC3339](https://tools .ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time that the compute host record was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComputeHostsComputeHostCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String capacityReservationId;
        private String compartmentId;
        private String computeHostGroupId;
        private Map<String,String> definedTags;
        private String displayName;
        private String faultDomain;
        private Map<String,String> freeformTags;
        private String gpuMemoryFabricId;
        private Boolean hasImpactedComponents;
        private String health;
        private String hpcIslandId;
        private String id;
        private String instanceId;
        private String localBlockId;
        private String networkBlockId;
        private String shape;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetComputeHostsComputeHostCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.capacityReservationId = defaults.capacityReservationId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.computeHostGroupId = defaults.computeHostGroupId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.faultDomain = defaults.faultDomain;
    	      this.freeformTags = defaults.freeformTags;
    	      this.gpuMemoryFabricId = defaults.gpuMemoryFabricId;
    	      this.hasImpactedComponents = defaults.hasImpactedComponents;
    	      this.health = defaults.health;
    	      this.hpcIslandId = defaults.hpcIslandId;
    	      this.id = defaults.id;
    	      this.instanceId = defaults.instanceId;
    	      this.localBlockId = defaults.localBlockId;
    	      this.networkBlockId = defaults.networkBlockId;
    	      this.shape = defaults.shape;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder capacityReservationId(String capacityReservationId) {
            if (capacityReservationId == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "capacityReservationId");
            }
            this.capacityReservationId = capacityReservationId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder computeHostGroupId(String computeHostGroupId) {
            if (computeHostGroupId == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "computeHostGroupId");
            }
            this.computeHostGroupId = computeHostGroupId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder faultDomain(String faultDomain) {
            if (faultDomain == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "faultDomain");
            }
            this.faultDomain = faultDomain;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder gpuMemoryFabricId(String gpuMemoryFabricId) {
            if (gpuMemoryFabricId == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "gpuMemoryFabricId");
            }
            this.gpuMemoryFabricId = gpuMemoryFabricId;
            return this;
        }
        @CustomType.Setter
        public Builder hasImpactedComponents(Boolean hasImpactedComponents) {
            if (hasImpactedComponents == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "hasImpactedComponents");
            }
            this.hasImpactedComponents = hasImpactedComponents;
            return this;
        }
        @CustomType.Setter
        public Builder health(String health) {
            if (health == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "health");
            }
            this.health = health;
            return this;
        }
        @CustomType.Setter
        public Builder hpcIslandId(String hpcIslandId) {
            if (hpcIslandId == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "hpcIslandId");
            }
            this.hpcIslandId = hpcIslandId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instanceId(String instanceId) {
            if (instanceId == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "instanceId");
            }
            this.instanceId = instanceId;
            return this;
        }
        @CustomType.Setter
        public Builder localBlockId(String localBlockId) {
            if (localBlockId == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "localBlockId");
            }
            this.localBlockId = localBlockId;
            return this;
        }
        @CustomType.Setter
        public Builder networkBlockId(String networkBlockId) {
            if (networkBlockId == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "networkBlockId");
            }
            this.networkBlockId = networkBlockId;
            return this;
        }
        @CustomType.Setter
        public Builder shape(String shape) {
            if (shape == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "shape");
            }
            this.shape = shape;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetComputeHostsComputeHostCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetComputeHostsComputeHostCollectionItem build() {
            final var _resultValue = new GetComputeHostsComputeHostCollectionItem();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.capacityReservationId = capacityReservationId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.computeHostGroupId = computeHostGroupId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.faultDomain = faultDomain;
            _resultValue.freeformTags = freeformTags;
            _resultValue.gpuMemoryFabricId = gpuMemoryFabricId;
            _resultValue.hasImpactedComponents = hasImpactedComponents;
            _resultValue.health = health;
            _resultValue.hpcIslandId = hpcIslandId;
            _resultValue.id = id;
            _resultValue.instanceId = instanceId;
            _resultValue.localBlockId = localBlockId;
            _resultValue.networkBlockId = networkBlockId;
            _resultValue.shape = shape;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
