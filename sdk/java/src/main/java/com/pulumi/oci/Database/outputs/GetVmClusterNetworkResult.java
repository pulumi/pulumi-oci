// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetVmClusterNetworkScan;
import com.pulumi.oci.Database.outputs.GetVmClusterNetworkVmNetwork;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetVmClusterNetworkResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The user-friendly name for the VM cluster network. The name does not need to be unique.
     * 
     */
    private String displayName;
    /**
     * @return The list of DNS server IP addresses. Maximum of 3 allowed.
     * 
     */
    private List<String> dns;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    private String exadataInfrastructureId;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     * 
     */
    private String id;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The list of NTP server IP addresses. Maximum of 3 allowed.
     * 
     */
    private List<String> ntps;
    /**
     * @return The SCAN details.
     * 
     */
    private List<GetVmClusterNetworkScan> scans;
    /**
     * @return The current state of the VM cluster network.
     * 
     */
    private String state;
    /**
     * @return The date and time when the VM cluster network was created.
     * 
     */
    private String timeCreated;
    private Boolean validateVmClusterNetwork;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated VM Cluster.
     * 
     */
    private String vmClusterId;
    private String vmClusterNetworkId;
    /**
     * @return Details of the client and backup networks.
     * 
     */
    private List<GetVmClusterNetworkVmNetwork> vmNetworks;

    private GetVmClusterNetworkResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The user-friendly name for the VM cluster network. The name does not need to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The list of DNS server IP addresses. Maximum of 3 allowed.
     * 
     */
    public List<String> dns() {
        return this.dns;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    public String exadataInfrastructureId() {
        return this.exadataInfrastructureId;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The list of NTP server IP addresses. Maximum of 3 allowed.
     * 
     */
    public List<String> ntps() {
        return this.ntps;
    }
    /**
     * @return The SCAN details.
     * 
     */
    public List<GetVmClusterNetworkScan> scans() {
        return this.scans;
    }
    /**
     * @return The current state of the VM cluster network.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time when the VM cluster network was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    public Boolean validateVmClusterNetwork() {
        return this.validateVmClusterNetwork;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated VM Cluster.
     * 
     */
    public String vmClusterId() {
        return this.vmClusterId;
    }
    public String vmClusterNetworkId() {
        return this.vmClusterNetworkId;
    }
    /**
     * @return Details of the client and backup networks.
     * 
     */
    public List<GetVmClusterNetworkVmNetwork> vmNetworks() {
        return this.vmNetworks;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVmClusterNetworkResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private List<String> dns;
        private String exadataInfrastructureId;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private List<String> ntps;
        private List<GetVmClusterNetworkScan> scans;
        private String state;
        private String timeCreated;
        private Boolean validateVmClusterNetwork;
        private String vmClusterId;
        private String vmClusterNetworkId;
        private List<GetVmClusterNetworkVmNetwork> vmNetworks;
        public Builder() {}
        public Builder(GetVmClusterNetworkResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.dns = defaults.dns;
    	      this.exadataInfrastructureId = defaults.exadataInfrastructureId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.ntps = defaults.ntps;
    	      this.scans = defaults.scans;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.validateVmClusterNetwork = defaults.validateVmClusterNetwork;
    	      this.vmClusterId = defaults.vmClusterId;
    	      this.vmClusterNetworkId = defaults.vmClusterNetworkId;
    	      this.vmNetworks = defaults.vmNetworks;
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
        public Builder dns(List<String> dns) {
            this.dns = Objects.requireNonNull(dns);
            return this;
        }
        public Builder dns(String... dns) {
            return dns(List.of(dns));
        }
        @CustomType.Setter
        public Builder exadataInfrastructureId(String exadataInfrastructureId) {
            this.exadataInfrastructureId = Objects.requireNonNull(exadataInfrastructureId);
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
        public Builder ntps(List<String> ntps) {
            this.ntps = Objects.requireNonNull(ntps);
            return this;
        }
        public Builder ntps(String... ntps) {
            return ntps(List.of(ntps));
        }
        @CustomType.Setter
        public Builder scans(List<GetVmClusterNetworkScan> scans) {
            this.scans = Objects.requireNonNull(scans);
            return this;
        }
        public Builder scans(GetVmClusterNetworkScan... scans) {
            return scans(List.of(scans));
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
        public Builder validateVmClusterNetwork(Boolean validateVmClusterNetwork) {
            this.validateVmClusterNetwork = Objects.requireNonNull(validateVmClusterNetwork);
            return this;
        }
        @CustomType.Setter
        public Builder vmClusterId(String vmClusterId) {
            this.vmClusterId = Objects.requireNonNull(vmClusterId);
            return this;
        }
        @CustomType.Setter
        public Builder vmClusterNetworkId(String vmClusterNetworkId) {
            this.vmClusterNetworkId = Objects.requireNonNull(vmClusterNetworkId);
            return this;
        }
        @CustomType.Setter
        public Builder vmNetworks(List<GetVmClusterNetworkVmNetwork> vmNetworks) {
            this.vmNetworks = Objects.requireNonNull(vmNetworks);
            return this;
        }
        public Builder vmNetworks(GetVmClusterNetworkVmNetwork... vmNetworks) {
            return vmNetworks(List.of(vmNetworks));
        }
        public GetVmClusterNetworkResult build() {
            final var o = new GetVmClusterNetworkResult();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.dns = dns;
            o.exadataInfrastructureId = exadataInfrastructureId;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.ntps = ntps;
            o.scans = scans;
            o.state = state;
            o.timeCreated = timeCreated;
            o.validateVmClusterNetwork = validateVmClusterNetwork;
            o.vmClusterId = vmClusterId;
            o.vmClusterNetworkId = vmClusterNetworkId;
            o.vmNetworks = vmNetworks;
            return o;
        }
    }
}