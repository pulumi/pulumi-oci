// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudMigrations.outputs.GetTargetAssetsTargetAssetCollectionItemTestSpecAgentConfig;
import com.pulumi.oci.CloudMigrations.outputs.GetTargetAssetsTargetAssetCollectionItemTestSpecCreateVnicDetail;
import com.pulumi.oci.CloudMigrations.outputs.GetTargetAssetsTargetAssetCollectionItemTestSpecInstanceOption;
import com.pulumi.oci.CloudMigrations.outputs.GetTargetAssetsTargetAssetCollectionItemTestSpecPreemptibleInstanceConfig;
import com.pulumi.oci.CloudMigrations.outputs.GetTargetAssetsTargetAssetCollectionItemTestSpecShapeConfig;
import com.pulumi.oci.CloudMigrations.outputs.GetTargetAssetsTargetAssetCollectionItemTestSpecSourceDetail;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetTargetAssetsTargetAssetCollectionItemTestSpec {
    /**
     * @return Configuration options for the Oracle Cloud Agent software running on the instance.
     * 
     */
    private List<GetTargetAssetsTargetAssetCollectionItemTestSpecAgentConfig> agentConfigs;
    /**
     * @return The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The OCID of the compute capacity reservation under which this instance is launched. You can opt out of all default reservations by specifying an empty string as input for this field. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     * 
     */
    private String capacityReservationId;
    /**
     * @return The OCID of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    private List<GetTargetAssetsTargetAssetCollectionItemTestSpecCreateVnicDetail> createVnicDetails;
    /**
     * @return The OCID of the dedicated VM host.
     * 
     */
    private String dedicatedVmHostId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A filter to return only resources that match the entire given display name.
     * 
     */
    private String displayName;
    /**
     * @return A fault domain is a grouping of hardware and infrastructure within an availability domain. Each availability domain contains three fault domains. Fault domains lets you distribute your instances so that they are not on the same physical hardware within a single availability domain. A hardware failure or Compute hardware maintenance that affects one fault domain does not affect instances in other fault domains.
     * 
     */
    private String faultDomain;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Deprecated. Instead use `hostnameLabel` in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/). If you provide both, the values must match.
     * 
     */
    private String hostnameLabel;
    /**
     * @return Optional mutable instance options
     * 
     */
    private List<GetTargetAssetsTargetAssetCollectionItemTestSpecInstanceOption> instanceOptions;
    /**
     * @return This is an advanced option.
     * 
     */
    private String ipxeScript;
    /**
     * @return Whether to enable in-transit encryption for the data volume&#39;s paravirtualized attachment. This field applies to both block volumes and boot volumes. By default, the value is false.
     * 
     */
    private Boolean isPvEncryptionInTransitEnabled;
    /**
     * @return Configuration options for preemptible instances.
     * 
     */
    private List<GetTargetAssetsTargetAssetCollectionItemTestSpecPreemptibleInstanceConfig> preemptibleInstanceConfigs;
    /**
     * @return The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    private String shape;
    /**
     * @return The shape configuration requested for the instance.
     * 
     */
    private List<GetTargetAssetsTargetAssetCollectionItemTestSpecShapeConfig> shapeConfigs;
    private List<GetTargetAssetsTargetAssetCollectionItemTestSpecSourceDetail> sourceDetails;

    private GetTargetAssetsTargetAssetCollectionItemTestSpec() {}
    /**
     * @return Configuration options for the Oracle Cloud Agent software running on the instance.
     * 
     */
    public List<GetTargetAssetsTargetAssetCollectionItemTestSpecAgentConfig> agentConfigs() {
        return this.agentConfigs;
    }
    /**
     * @return The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The OCID of the compute capacity reservation under which this instance is launched. You can opt out of all default reservations by specifying an empty string as input for this field. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     * 
     */
    public String capacityReservationId() {
        return this.capacityReservationId;
    }
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    public List<GetTargetAssetsTargetAssetCollectionItemTestSpecCreateVnicDetail> createVnicDetails() {
        return this.createVnicDetails;
    }
    /**
     * @return The OCID of the dedicated VM host.
     * 
     */
    public String dedicatedVmHostId() {
        return this.dedicatedVmHostId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only resources that match the entire given display name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return A fault domain is a grouping of hardware and infrastructure within an availability domain. Each availability domain contains three fault domains. Fault domains lets you distribute your instances so that they are not on the same physical hardware within a single availability domain. A hardware failure or Compute hardware maintenance that affects one fault domain does not affect instances in other fault domains.
     * 
     */
    public String faultDomain() {
        return this.faultDomain;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Deprecated. Instead use `hostnameLabel` in [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/). If you provide both, the values must match.
     * 
     */
    public String hostnameLabel() {
        return this.hostnameLabel;
    }
    /**
     * @return Optional mutable instance options
     * 
     */
    public List<GetTargetAssetsTargetAssetCollectionItemTestSpecInstanceOption> instanceOptions() {
        return this.instanceOptions;
    }
    /**
     * @return This is an advanced option.
     * 
     */
    public String ipxeScript() {
        return this.ipxeScript;
    }
    /**
     * @return Whether to enable in-transit encryption for the data volume&#39;s paravirtualized attachment. This field applies to both block volumes and boot volumes. By default, the value is false.
     * 
     */
    public Boolean isPvEncryptionInTransitEnabled() {
        return this.isPvEncryptionInTransitEnabled;
    }
    /**
     * @return Configuration options for preemptible instances.
     * 
     */
    public List<GetTargetAssetsTargetAssetCollectionItemTestSpecPreemptibleInstanceConfig> preemptibleInstanceConfigs() {
        return this.preemptibleInstanceConfigs;
    }
    /**
     * @return The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return The shape configuration requested for the instance.
     * 
     */
    public List<GetTargetAssetsTargetAssetCollectionItemTestSpecShapeConfig> shapeConfigs() {
        return this.shapeConfigs;
    }
    public List<GetTargetAssetsTargetAssetCollectionItemTestSpecSourceDetail> sourceDetails() {
        return this.sourceDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTargetAssetsTargetAssetCollectionItemTestSpec defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetTargetAssetsTargetAssetCollectionItemTestSpecAgentConfig> agentConfigs;
        private String availabilityDomain;
        private String capacityReservationId;
        private String compartmentId;
        private List<GetTargetAssetsTargetAssetCollectionItemTestSpecCreateVnicDetail> createVnicDetails;
        private String dedicatedVmHostId;
        private Map<String,String> definedTags;
        private String displayName;
        private String faultDomain;
        private Map<String,String> freeformTags;
        private String hostnameLabel;
        private List<GetTargetAssetsTargetAssetCollectionItemTestSpecInstanceOption> instanceOptions;
        private String ipxeScript;
        private Boolean isPvEncryptionInTransitEnabled;
        private List<GetTargetAssetsTargetAssetCollectionItemTestSpecPreemptibleInstanceConfig> preemptibleInstanceConfigs;
        private String shape;
        private List<GetTargetAssetsTargetAssetCollectionItemTestSpecShapeConfig> shapeConfigs;
        private List<GetTargetAssetsTargetAssetCollectionItemTestSpecSourceDetail> sourceDetails;
        public Builder() {}
        public Builder(GetTargetAssetsTargetAssetCollectionItemTestSpec defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.agentConfigs = defaults.agentConfigs;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.capacityReservationId = defaults.capacityReservationId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.createVnicDetails = defaults.createVnicDetails;
    	      this.dedicatedVmHostId = defaults.dedicatedVmHostId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.faultDomain = defaults.faultDomain;
    	      this.freeformTags = defaults.freeformTags;
    	      this.hostnameLabel = defaults.hostnameLabel;
    	      this.instanceOptions = defaults.instanceOptions;
    	      this.ipxeScript = defaults.ipxeScript;
    	      this.isPvEncryptionInTransitEnabled = defaults.isPvEncryptionInTransitEnabled;
    	      this.preemptibleInstanceConfigs = defaults.preemptibleInstanceConfigs;
    	      this.shape = defaults.shape;
    	      this.shapeConfigs = defaults.shapeConfigs;
    	      this.sourceDetails = defaults.sourceDetails;
        }

        @CustomType.Setter
        public Builder agentConfigs(List<GetTargetAssetsTargetAssetCollectionItemTestSpecAgentConfig> agentConfigs) {
            if (agentConfigs == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "agentConfigs");
            }
            this.agentConfigs = agentConfigs;
            return this;
        }
        public Builder agentConfigs(GetTargetAssetsTargetAssetCollectionItemTestSpecAgentConfig... agentConfigs) {
            return agentConfigs(List.of(agentConfigs));
        }
        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder capacityReservationId(String capacityReservationId) {
            if (capacityReservationId == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "capacityReservationId");
            }
            this.capacityReservationId = capacityReservationId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder createVnicDetails(List<GetTargetAssetsTargetAssetCollectionItemTestSpecCreateVnicDetail> createVnicDetails) {
            if (createVnicDetails == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "createVnicDetails");
            }
            this.createVnicDetails = createVnicDetails;
            return this;
        }
        public Builder createVnicDetails(GetTargetAssetsTargetAssetCollectionItemTestSpecCreateVnicDetail... createVnicDetails) {
            return createVnicDetails(List.of(createVnicDetails));
        }
        @CustomType.Setter
        public Builder dedicatedVmHostId(String dedicatedVmHostId) {
            if (dedicatedVmHostId == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "dedicatedVmHostId");
            }
            this.dedicatedVmHostId = dedicatedVmHostId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder faultDomain(String faultDomain) {
            if (faultDomain == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "faultDomain");
            }
            this.faultDomain = faultDomain;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder hostnameLabel(String hostnameLabel) {
            if (hostnameLabel == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "hostnameLabel");
            }
            this.hostnameLabel = hostnameLabel;
            return this;
        }
        @CustomType.Setter
        public Builder instanceOptions(List<GetTargetAssetsTargetAssetCollectionItemTestSpecInstanceOption> instanceOptions) {
            if (instanceOptions == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "instanceOptions");
            }
            this.instanceOptions = instanceOptions;
            return this;
        }
        public Builder instanceOptions(GetTargetAssetsTargetAssetCollectionItemTestSpecInstanceOption... instanceOptions) {
            return instanceOptions(List.of(instanceOptions));
        }
        @CustomType.Setter
        public Builder ipxeScript(String ipxeScript) {
            if (ipxeScript == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "ipxeScript");
            }
            this.ipxeScript = ipxeScript;
            return this;
        }
        @CustomType.Setter
        public Builder isPvEncryptionInTransitEnabled(Boolean isPvEncryptionInTransitEnabled) {
            if (isPvEncryptionInTransitEnabled == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "isPvEncryptionInTransitEnabled");
            }
            this.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder preemptibleInstanceConfigs(List<GetTargetAssetsTargetAssetCollectionItemTestSpecPreemptibleInstanceConfig> preemptibleInstanceConfigs) {
            if (preemptibleInstanceConfigs == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "preemptibleInstanceConfigs");
            }
            this.preemptibleInstanceConfigs = preemptibleInstanceConfigs;
            return this;
        }
        public Builder preemptibleInstanceConfigs(GetTargetAssetsTargetAssetCollectionItemTestSpecPreemptibleInstanceConfig... preemptibleInstanceConfigs) {
            return preemptibleInstanceConfigs(List.of(preemptibleInstanceConfigs));
        }
        @CustomType.Setter
        public Builder shape(String shape) {
            if (shape == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "shape");
            }
            this.shape = shape;
            return this;
        }
        @CustomType.Setter
        public Builder shapeConfigs(List<GetTargetAssetsTargetAssetCollectionItemTestSpecShapeConfig> shapeConfigs) {
            if (shapeConfigs == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "shapeConfigs");
            }
            this.shapeConfigs = shapeConfigs;
            return this;
        }
        public Builder shapeConfigs(GetTargetAssetsTargetAssetCollectionItemTestSpecShapeConfig... shapeConfigs) {
            return shapeConfigs(List.of(shapeConfigs));
        }
        @CustomType.Setter
        public Builder sourceDetails(List<GetTargetAssetsTargetAssetCollectionItemTestSpecSourceDetail> sourceDetails) {
            if (sourceDetails == null) {
              throw new MissingRequiredPropertyException("GetTargetAssetsTargetAssetCollectionItemTestSpec", "sourceDetails");
            }
            this.sourceDetails = sourceDetails;
            return this;
        }
        public Builder sourceDetails(GetTargetAssetsTargetAssetCollectionItemTestSpecSourceDetail... sourceDetails) {
            return sourceDetails(List.of(sourceDetails));
        }
        public GetTargetAssetsTargetAssetCollectionItemTestSpec build() {
            final var _resultValue = new GetTargetAssetsTargetAssetCollectionItemTestSpec();
            _resultValue.agentConfigs = agentConfigs;
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.capacityReservationId = capacityReservationId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.createVnicDetails = createVnicDetails;
            _resultValue.dedicatedVmHostId = dedicatedVmHostId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.faultDomain = faultDomain;
            _resultValue.freeformTags = freeformTags;
            _resultValue.hostnameLabel = hostnameLabel;
            _resultValue.instanceOptions = instanceOptions;
            _resultValue.ipxeScript = ipxeScript;
            _resultValue.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            _resultValue.preemptibleInstanceConfigs = preemptibleInstanceConfigs;
            _resultValue.shape = shape;
            _resultValue.shapeConfigs = shapeConfigs;
            _resultValue.sourceDetails = sourceDetails;
            return _resultValue;
        }
    }
}
