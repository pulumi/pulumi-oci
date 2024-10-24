// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Ocvp.outputs.GetClustersClusterCollectionItemDatastore;
import com.pulumi.oci.Ocvp.outputs.GetClustersClusterCollectionItemNetworkConfiguration;
import com.pulumi.oci.Ocvp.outputs.GetClustersClusterCollectionItemUpgradeLicense;
import com.pulumi.oci.Ocvp.outputs.GetClustersClusterCollectionItemVsphereUpgradeObject;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetClustersClusterCollectionItem {
    private Integer actualEsxiHostsCount;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Capacity Reservation.
     * 
     */
    private String capacityReservationId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment as optional parameter.
     * 
     */
    private String compartmentId;
    /**
     * @return The availability domain the ESXi hosts are running in. For Multi-AD Cluster, it is `multi-AD`.  Example: `Uocm:PHX-AD-1`, `multi-AD`
     * 
     */
    private String computeAvailabilityDomain;
    /**
     * @return Datastores used for the Cluster.
     * 
     */
    private List<GetClustersClusterCollectionItemDatastore> datastores;
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
     * @return The number of ESXi hosts in the Cluster.
     * 
     */
    private Integer esxiHostsCount;
    /**
     * @return In general, this is a specific version of bundled ESXi software supported by Oracle Cloud VMware Solution (see [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions)).
     * 
     */
    private String esxiSoftwareVersion;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cluster.
     * 
     */
    private String id;
    /**
     * @return The billing option selected during Cluster creation. [ListSupportedCommitments](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedCommitmentSummary/ListSupportedCommitments).
     * 
     */
    private String initialCommitment;
    /**
     * @return The initial OCPU count of the Cluster&#39;s ESXi hosts.
     * 
     */
    private Double initialHostOcpuCount;
    /**
     * @return The initial compute shape of the Cluster&#39;s ESXi hosts. [ListSupportedHostShapes](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedHostShapes/ListSupportedHostShapes).
     * 
     */
    private String initialHostShapeName;
    /**
     * @return A prefix used in the name of each ESXi host and Compute instance in the Cluster. If this isn&#39;t set, the Cluster&#39;s `displayName` is used as the prefix.
     * 
     */
    private String instanceDisplayNamePrefix;
    /**
     * @return Indicates whether shielded instance is enabled at the Cluster level.
     * 
     */
    private Boolean isShieldedInstanceEnabled;
    /**
     * @return The network configurations used by Cluster, including [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet and VLANs.
     * 
     */
    private List<GetClustersClusterCollectionItemNetworkConfiguration> networkConfigurations;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
     * 
     */
    private String sddcId;
    /**
     * @return The lifecycle state of the resource.
     * 
     */
    private String state;
    /**
     * @return The date and time the Cluster was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the Cluster was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeUpdated;
    /**
     * @return The vSphere licenses to use when upgrading the Cluster.
     * 
     */
    private List<GetClustersClusterCollectionItemUpgradeLicense> upgradeLicenses;
    /**
     * @return In general, this is a specific version of bundled VMware software supported by Oracle Cloud VMware Solution (see [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions)).
     * 
     */
    private String vmwareSoftwareVersion;
    /**
     * @return vSphere Cluster types.
     * 
     */
    private String vsphereType;
    /**
     * @return The links to binary objects needed to upgrade vSphere.
     * 
     */
    private List<GetClustersClusterCollectionItemVsphereUpgradeObject> vsphereUpgradeObjects;
    /**
     * @return The CIDR block for the IP addresses that VMware VMs in the SDDC use to run application workloads.
     * 
     */
    private String workloadNetworkCidr;

    private GetClustersClusterCollectionItem() {}
    public Integer actualEsxiHostsCount() {
        return this.actualEsxiHostsCount;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Capacity Reservation.
     * 
     */
    public String capacityReservationId() {
        return this.capacityReservationId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment as optional parameter.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The availability domain the ESXi hosts are running in. For Multi-AD Cluster, it is `multi-AD`.  Example: `Uocm:PHX-AD-1`, `multi-AD`
     * 
     */
    public String computeAvailabilityDomain() {
        return this.computeAvailabilityDomain;
    }
    /**
     * @return Datastores used for the Cluster.
     * 
     */
    public List<GetClustersClusterCollectionItemDatastore> datastores() {
        return this.datastores;
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
     * @return The number of ESXi hosts in the Cluster.
     * 
     */
    public Integer esxiHostsCount() {
        return this.esxiHostsCount;
    }
    /**
     * @return In general, this is a specific version of bundled ESXi software supported by Oracle Cloud VMware Solution (see [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions)).
     * 
     */
    public String esxiSoftwareVersion() {
        return this.esxiSoftwareVersion;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cluster.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The billing option selected during Cluster creation. [ListSupportedCommitments](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedCommitmentSummary/ListSupportedCommitments).
     * 
     */
    public String initialCommitment() {
        return this.initialCommitment;
    }
    /**
     * @return The initial OCPU count of the Cluster&#39;s ESXi hosts.
     * 
     */
    public Double initialHostOcpuCount() {
        return this.initialHostOcpuCount;
    }
    /**
     * @return The initial compute shape of the Cluster&#39;s ESXi hosts. [ListSupportedHostShapes](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedHostShapes/ListSupportedHostShapes).
     * 
     */
    public String initialHostShapeName() {
        return this.initialHostShapeName;
    }
    /**
     * @return A prefix used in the name of each ESXi host and Compute instance in the Cluster. If this isn&#39;t set, the Cluster&#39;s `displayName` is used as the prefix.
     * 
     */
    public String instanceDisplayNamePrefix() {
        return this.instanceDisplayNamePrefix;
    }
    /**
     * @return Indicates whether shielded instance is enabled at the Cluster level.
     * 
     */
    public Boolean isShieldedInstanceEnabled() {
        return this.isShieldedInstanceEnabled;
    }
    /**
     * @return The network configurations used by Cluster, including [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet and VLANs.
     * 
     */
    public List<GetClustersClusterCollectionItemNetworkConfiguration> networkConfigurations() {
        return this.networkConfigurations;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
     * 
     */
    public String sddcId() {
        return this.sddcId;
    }
    /**
     * @return The lifecycle state of the resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the Cluster was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the Cluster was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The vSphere licenses to use when upgrading the Cluster.
     * 
     */
    public List<GetClustersClusterCollectionItemUpgradeLicense> upgradeLicenses() {
        return this.upgradeLicenses;
    }
    /**
     * @return In general, this is a specific version of bundled VMware software supported by Oracle Cloud VMware Solution (see [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions)).
     * 
     */
    public String vmwareSoftwareVersion() {
        return this.vmwareSoftwareVersion;
    }
    /**
     * @return vSphere Cluster types.
     * 
     */
    public String vsphereType() {
        return this.vsphereType;
    }
    /**
     * @return The links to binary objects needed to upgrade vSphere.
     * 
     */
    public List<GetClustersClusterCollectionItemVsphereUpgradeObject> vsphereUpgradeObjects() {
        return this.vsphereUpgradeObjects;
    }
    /**
     * @return The CIDR block for the IP addresses that VMware VMs in the SDDC use to run application workloads.
     * 
     */
    public String workloadNetworkCidr() {
        return this.workloadNetworkCidr;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetClustersClusterCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer actualEsxiHostsCount;
        private String capacityReservationId;
        private String compartmentId;
        private String computeAvailabilityDomain;
        private List<GetClustersClusterCollectionItemDatastore> datastores;
        private Map<String,String> definedTags;
        private String displayName;
        private Integer esxiHostsCount;
        private String esxiSoftwareVersion;
        private Map<String,String> freeformTags;
        private String id;
        private String initialCommitment;
        private Double initialHostOcpuCount;
        private String initialHostShapeName;
        private String instanceDisplayNamePrefix;
        private Boolean isShieldedInstanceEnabled;
        private List<GetClustersClusterCollectionItemNetworkConfiguration> networkConfigurations;
        private String sddcId;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        private List<GetClustersClusterCollectionItemUpgradeLicense> upgradeLicenses;
        private String vmwareSoftwareVersion;
        private String vsphereType;
        private List<GetClustersClusterCollectionItemVsphereUpgradeObject> vsphereUpgradeObjects;
        private String workloadNetworkCidr;
        public Builder() {}
        public Builder(GetClustersClusterCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actualEsxiHostsCount = defaults.actualEsxiHostsCount;
    	      this.capacityReservationId = defaults.capacityReservationId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.computeAvailabilityDomain = defaults.computeAvailabilityDomain;
    	      this.datastores = defaults.datastores;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.esxiHostsCount = defaults.esxiHostsCount;
    	      this.esxiSoftwareVersion = defaults.esxiSoftwareVersion;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.initialCommitment = defaults.initialCommitment;
    	      this.initialHostOcpuCount = defaults.initialHostOcpuCount;
    	      this.initialHostShapeName = defaults.initialHostShapeName;
    	      this.instanceDisplayNamePrefix = defaults.instanceDisplayNamePrefix;
    	      this.isShieldedInstanceEnabled = defaults.isShieldedInstanceEnabled;
    	      this.networkConfigurations = defaults.networkConfigurations;
    	      this.sddcId = defaults.sddcId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.upgradeLicenses = defaults.upgradeLicenses;
    	      this.vmwareSoftwareVersion = defaults.vmwareSoftwareVersion;
    	      this.vsphereType = defaults.vsphereType;
    	      this.vsphereUpgradeObjects = defaults.vsphereUpgradeObjects;
    	      this.workloadNetworkCidr = defaults.workloadNetworkCidr;
        }

        @CustomType.Setter
        public Builder actualEsxiHostsCount(Integer actualEsxiHostsCount) {
            if (actualEsxiHostsCount == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "actualEsxiHostsCount");
            }
            this.actualEsxiHostsCount = actualEsxiHostsCount;
            return this;
        }
        @CustomType.Setter
        public Builder capacityReservationId(String capacityReservationId) {
            if (capacityReservationId == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "capacityReservationId");
            }
            this.capacityReservationId = capacityReservationId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder computeAvailabilityDomain(String computeAvailabilityDomain) {
            if (computeAvailabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "computeAvailabilityDomain");
            }
            this.computeAvailabilityDomain = computeAvailabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder datastores(List<GetClustersClusterCollectionItemDatastore> datastores) {
            if (datastores == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "datastores");
            }
            this.datastores = datastores;
            return this;
        }
        public Builder datastores(GetClustersClusterCollectionItemDatastore... datastores) {
            return datastores(List.of(datastores));
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder esxiHostsCount(Integer esxiHostsCount) {
            if (esxiHostsCount == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "esxiHostsCount");
            }
            this.esxiHostsCount = esxiHostsCount;
            return this;
        }
        @CustomType.Setter
        public Builder esxiSoftwareVersion(String esxiSoftwareVersion) {
            if (esxiSoftwareVersion == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "esxiSoftwareVersion");
            }
            this.esxiSoftwareVersion = esxiSoftwareVersion;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder initialCommitment(String initialCommitment) {
            if (initialCommitment == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "initialCommitment");
            }
            this.initialCommitment = initialCommitment;
            return this;
        }
        @CustomType.Setter
        public Builder initialHostOcpuCount(Double initialHostOcpuCount) {
            if (initialHostOcpuCount == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "initialHostOcpuCount");
            }
            this.initialHostOcpuCount = initialHostOcpuCount;
            return this;
        }
        @CustomType.Setter
        public Builder initialHostShapeName(String initialHostShapeName) {
            if (initialHostShapeName == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "initialHostShapeName");
            }
            this.initialHostShapeName = initialHostShapeName;
            return this;
        }
        @CustomType.Setter
        public Builder instanceDisplayNamePrefix(String instanceDisplayNamePrefix) {
            if (instanceDisplayNamePrefix == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "instanceDisplayNamePrefix");
            }
            this.instanceDisplayNamePrefix = instanceDisplayNamePrefix;
            return this;
        }
        @CustomType.Setter
        public Builder isShieldedInstanceEnabled(Boolean isShieldedInstanceEnabled) {
            if (isShieldedInstanceEnabled == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "isShieldedInstanceEnabled");
            }
            this.isShieldedInstanceEnabled = isShieldedInstanceEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder networkConfigurations(List<GetClustersClusterCollectionItemNetworkConfiguration> networkConfigurations) {
            if (networkConfigurations == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "networkConfigurations");
            }
            this.networkConfigurations = networkConfigurations;
            return this;
        }
        public Builder networkConfigurations(GetClustersClusterCollectionItemNetworkConfiguration... networkConfigurations) {
            return networkConfigurations(List.of(networkConfigurations));
        }
        @CustomType.Setter
        public Builder sddcId(String sddcId) {
            if (sddcId == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "sddcId");
            }
            this.sddcId = sddcId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder upgradeLicenses(List<GetClustersClusterCollectionItemUpgradeLicense> upgradeLicenses) {
            if (upgradeLicenses == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "upgradeLicenses");
            }
            this.upgradeLicenses = upgradeLicenses;
            return this;
        }
        public Builder upgradeLicenses(GetClustersClusterCollectionItemUpgradeLicense... upgradeLicenses) {
            return upgradeLicenses(List.of(upgradeLicenses));
        }
        @CustomType.Setter
        public Builder vmwareSoftwareVersion(String vmwareSoftwareVersion) {
            if (vmwareSoftwareVersion == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "vmwareSoftwareVersion");
            }
            this.vmwareSoftwareVersion = vmwareSoftwareVersion;
            return this;
        }
        @CustomType.Setter
        public Builder vsphereType(String vsphereType) {
            if (vsphereType == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "vsphereType");
            }
            this.vsphereType = vsphereType;
            return this;
        }
        @CustomType.Setter
        public Builder vsphereUpgradeObjects(List<GetClustersClusterCollectionItemVsphereUpgradeObject> vsphereUpgradeObjects) {
            if (vsphereUpgradeObjects == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "vsphereUpgradeObjects");
            }
            this.vsphereUpgradeObjects = vsphereUpgradeObjects;
            return this;
        }
        public Builder vsphereUpgradeObjects(GetClustersClusterCollectionItemVsphereUpgradeObject... vsphereUpgradeObjects) {
            return vsphereUpgradeObjects(List.of(vsphereUpgradeObjects));
        }
        @CustomType.Setter
        public Builder workloadNetworkCidr(String workloadNetworkCidr) {
            if (workloadNetworkCidr == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterCollectionItem", "workloadNetworkCidr");
            }
            this.workloadNetworkCidr = workloadNetworkCidr;
            return this;
        }
        public GetClustersClusterCollectionItem build() {
            final var _resultValue = new GetClustersClusterCollectionItem();
            _resultValue.actualEsxiHostsCount = actualEsxiHostsCount;
            _resultValue.capacityReservationId = capacityReservationId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.computeAvailabilityDomain = computeAvailabilityDomain;
            _resultValue.datastores = datastores;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.esxiHostsCount = esxiHostsCount;
            _resultValue.esxiSoftwareVersion = esxiSoftwareVersion;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.initialCommitment = initialCommitment;
            _resultValue.initialHostOcpuCount = initialHostOcpuCount;
            _resultValue.initialHostShapeName = initialHostShapeName;
            _resultValue.instanceDisplayNamePrefix = instanceDisplayNamePrefix;
            _resultValue.isShieldedInstanceEnabled = isShieldedInstanceEnabled;
            _resultValue.networkConfigurations = networkConfigurations;
            _resultValue.sddcId = sddcId;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.upgradeLicenses = upgradeLicenses;
            _resultValue.vmwareSoftwareVersion = vmwareSoftwareVersion;
            _resultValue.vsphereType = vsphereType;
            _resultValue.vsphereUpgradeObjects = vsphereUpgradeObjects;
            _resultValue.workloadNetworkCidr = workloadNetworkCidr;
            return _resultValue;
        }
    }
}
