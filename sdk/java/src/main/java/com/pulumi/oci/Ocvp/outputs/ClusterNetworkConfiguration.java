// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ClusterNetworkConfiguration {
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the HCX component of the VMware environment. This VLAN is a mandatory attribute  for Management Cluster when HCX is enabled.
     * 
     * This attribute is not guaranteed to reflect the HCX VLAN currently used by the ESXi hosts in the SDDC. The purpose of this attribute is to show the HCX VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this SDDC in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the SDDC to use a different VLAN for the HCX component of the VMware environment, you should use [UpdateSddc](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/Sddc/UpdateSddc) to update the SDDC&#39;s `hcxVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    private @Nullable String hcxVlanId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX Edge Uplink 1 component of the VMware environment. This VLAN is a mandatory attribute for Management Cluster.
     * 
     * This attribute is not guaranteed to reflect the NSX Edge Uplink 1 VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the NSX Edge Uplink 1 VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the NSX Edge Uplink 1 component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Cluster/UpdateCluster) to update the Cluster&#39;s `nsxEdgeUplink1VlanId` with that new VLAN&#39;s OCID.
     * 
     */
    private @Nullable String nsxEdgeUplink1vlanId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC  for the NSX Edge Uplink 2 component of the VMware environment. This VLAN is a mandatory attribute for Management Cluster.
     * 
     * This attribute is not guaranteed to reflect the NSX Edge Uplink 2 VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the NSX Edge Uplink 2 VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the NSX Edge Uplink 2 component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Cluster/UpdateCluster) to update the Cluster&#39;s `nsxEdgeUplink2VlanId` with that new VLAN&#39;s OCID.
     * 
     */
    private @Nullable String nsxEdgeUplink2vlanId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the NSX Edge VTEP component of the VMware environment.
     * 
     * This attribute is not guaranteed to reflect the NSX Edge VTEP VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the NSX Edge VTEP VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the NSX Edge VTEP component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Cluster/UpdateCluster) to update the Cluster&#39;s `nsxEdgeVTepVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    private String nsxEdgeVtepVlanId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the NSX VTEP component of the VMware environment.
     * 
     * This attribute is not guaranteed to reflect the NSX VTEP VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the NSX VTEP VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the NSX VTEP component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Cluster/UpdateCluster) to update the Cluster&#39;s `nsxVTepVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    private String nsxVtepVlanId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet used to provision the Cluster.
     * 
     */
    private String provisioningSubnetId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the Provisioning component of the VMware environment.
     * 
     */
    private @Nullable String provisioningVlanId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the vSphere Replication component of the VMware environment.
     * 
     */
    private @Nullable String replicationVlanId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the vMotion component of the VMware environment.
     * 
     * This attribute is not guaranteed to reflect the vMotion VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the vMotion VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the vMotion component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Sddc/UpdateCluster) to update the Cluster&#39;s `vmotionVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    private String vmotionVlanId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the vSAN component of the VMware environment.
     * 
     * This attribute is not guaranteed to reflect the vSAN VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the vSAN VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the vSAN component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Cluster/UpdateCluster) to update the Cluster&#39;s `vsanVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    private String vsanVlanId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vSphere component of the VMware environment. This VLAN is a mandatory attribute for Management Cluster.
     * 
     * This attribute is not guaranteed to reflect the vSphere VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the vSphere VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the vSphere component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Sddc/UpdateSddc) to update the Cluster&#39;s `vsphereVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    private @Nullable String vsphereVlanId;

    private ClusterNetworkConfiguration() {}
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the HCX component of the VMware environment. This VLAN is a mandatory attribute  for Management Cluster when HCX is enabled.
     * 
     * This attribute is not guaranteed to reflect the HCX VLAN currently used by the ESXi hosts in the SDDC. The purpose of this attribute is to show the HCX VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this SDDC in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the SDDC to use a different VLAN for the HCX component of the VMware environment, you should use [UpdateSddc](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/Sddc/UpdateSddc) to update the SDDC&#39;s `hcxVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    public Optional<String> hcxVlanId() {
        return Optional.ofNullable(this.hcxVlanId);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX Edge Uplink 1 component of the VMware environment. This VLAN is a mandatory attribute for Management Cluster.
     * 
     * This attribute is not guaranteed to reflect the NSX Edge Uplink 1 VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the NSX Edge Uplink 1 VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the NSX Edge Uplink 1 component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Cluster/UpdateCluster) to update the Cluster&#39;s `nsxEdgeUplink1VlanId` with that new VLAN&#39;s OCID.
     * 
     */
    public Optional<String> nsxEdgeUplink1vlanId() {
        return Optional.ofNullable(this.nsxEdgeUplink1vlanId);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC  for the NSX Edge Uplink 2 component of the VMware environment. This VLAN is a mandatory attribute for Management Cluster.
     * 
     * This attribute is not guaranteed to reflect the NSX Edge Uplink 2 VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the NSX Edge Uplink 2 VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the NSX Edge Uplink 2 component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Cluster/UpdateCluster) to update the Cluster&#39;s `nsxEdgeUplink2VlanId` with that new VLAN&#39;s OCID.
     * 
     */
    public Optional<String> nsxEdgeUplink2vlanId() {
        return Optional.ofNullable(this.nsxEdgeUplink2vlanId);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the NSX Edge VTEP component of the VMware environment.
     * 
     * This attribute is not guaranteed to reflect the NSX Edge VTEP VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the NSX Edge VTEP VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the NSX Edge VTEP component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Cluster/UpdateCluster) to update the Cluster&#39;s `nsxEdgeVTepVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    public String nsxEdgeVtepVlanId() {
        return this.nsxEdgeVtepVlanId;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the NSX VTEP component of the VMware environment.
     * 
     * This attribute is not guaranteed to reflect the NSX VTEP VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the NSX VTEP VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the NSX VTEP component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Cluster/UpdateCluster) to update the Cluster&#39;s `nsxVTepVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    public String nsxVtepVlanId() {
        return this.nsxVtepVlanId;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet used to provision the Cluster.
     * 
     */
    public String provisioningSubnetId() {
        return this.provisioningSubnetId;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the Provisioning component of the VMware environment.
     * 
     */
    public Optional<String> provisioningVlanId() {
        return Optional.ofNullable(this.provisioningVlanId);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the vSphere Replication component of the VMware environment.
     * 
     */
    public Optional<String> replicationVlanId() {
        return Optional.ofNullable(this.replicationVlanId);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the vMotion component of the VMware environment.
     * 
     * This attribute is not guaranteed to reflect the vMotion VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the vMotion VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the vMotion component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Sddc/UpdateCluster) to update the Cluster&#39;s `vmotionVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    public String vmotionVlanId() {
        return this.vmotionVlanId;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the vSAN component of the VMware environment.
     * 
     * This attribute is not guaranteed to reflect the vSAN VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the vSAN VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the vSAN component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Cluster/UpdateCluster) to update the Cluster&#39;s `vsanVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    public String vsanVlanId() {
        return this.vsanVlanId;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vSphere component of the VMware environment. This VLAN is a mandatory attribute for Management Cluster.
     * 
     * This attribute is not guaranteed to reflect the vSphere VLAN currently used by the ESXi hosts in the Cluster. The purpose of this attribute is to show the vSphere VLAN that the Oracle Cloud VMware Solution will use for any new ESXi hosts that you *add to this Cluster in the future* with [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost).
     * 
     * Therefore, if you change the existing ESXi hosts in the Cluster to use a different VLAN for the vSphere component of the VMware environment, you should use [UpdateCluster](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/Sddc/UpdateSddc) to update the Cluster&#39;s `vsphereVlanId` with that new VLAN&#39;s OCID.
     * 
     */
    public Optional<String> vsphereVlanId() {
        return Optional.ofNullable(this.vsphereVlanId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ClusterNetworkConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String hcxVlanId;
        private @Nullable String nsxEdgeUplink1vlanId;
        private @Nullable String nsxEdgeUplink2vlanId;
        private String nsxEdgeVtepVlanId;
        private String nsxVtepVlanId;
        private String provisioningSubnetId;
        private @Nullable String provisioningVlanId;
        private @Nullable String replicationVlanId;
        private String vmotionVlanId;
        private String vsanVlanId;
        private @Nullable String vsphereVlanId;
        public Builder() {}
        public Builder(ClusterNetworkConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hcxVlanId = defaults.hcxVlanId;
    	      this.nsxEdgeUplink1vlanId = defaults.nsxEdgeUplink1vlanId;
    	      this.nsxEdgeUplink2vlanId = defaults.nsxEdgeUplink2vlanId;
    	      this.nsxEdgeVtepVlanId = defaults.nsxEdgeVtepVlanId;
    	      this.nsxVtepVlanId = defaults.nsxVtepVlanId;
    	      this.provisioningSubnetId = defaults.provisioningSubnetId;
    	      this.provisioningVlanId = defaults.provisioningVlanId;
    	      this.replicationVlanId = defaults.replicationVlanId;
    	      this.vmotionVlanId = defaults.vmotionVlanId;
    	      this.vsanVlanId = defaults.vsanVlanId;
    	      this.vsphereVlanId = defaults.vsphereVlanId;
        }

        @CustomType.Setter
        public Builder hcxVlanId(@Nullable String hcxVlanId) {

            this.hcxVlanId = hcxVlanId;
            return this;
        }
        @CustomType.Setter
        public Builder nsxEdgeUplink1vlanId(@Nullable String nsxEdgeUplink1vlanId) {

            this.nsxEdgeUplink1vlanId = nsxEdgeUplink1vlanId;
            return this;
        }
        @CustomType.Setter
        public Builder nsxEdgeUplink2vlanId(@Nullable String nsxEdgeUplink2vlanId) {

            this.nsxEdgeUplink2vlanId = nsxEdgeUplink2vlanId;
            return this;
        }
        @CustomType.Setter
        public Builder nsxEdgeVtepVlanId(String nsxEdgeVtepVlanId) {
            if (nsxEdgeVtepVlanId == null) {
              throw new MissingRequiredPropertyException("ClusterNetworkConfiguration", "nsxEdgeVtepVlanId");
            }
            this.nsxEdgeVtepVlanId = nsxEdgeVtepVlanId;
            return this;
        }
        @CustomType.Setter
        public Builder nsxVtepVlanId(String nsxVtepVlanId) {
            if (nsxVtepVlanId == null) {
              throw new MissingRequiredPropertyException("ClusterNetworkConfiguration", "nsxVtepVlanId");
            }
            this.nsxVtepVlanId = nsxVtepVlanId;
            return this;
        }
        @CustomType.Setter
        public Builder provisioningSubnetId(String provisioningSubnetId) {
            if (provisioningSubnetId == null) {
              throw new MissingRequiredPropertyException("ClusterNetworkConfiguration", "provisioningSubnetId");
            }
            this.provisioningSubnetId = provisioningSubnetId;
            return this;
        }
        @CustomType.Setter
        public Builder provisioningVlanId(@Nullable String provisioningVlanId) {

            this.provisioningVlanId = provisioningVlanId;
            return this;
        }
        @CustomType.Setter
        public Builder replicationVlanId(@Nullable String replicationVlanId) {

            this.replicationVlanId = replicationVlanId;
            return this;
        }
        @CustomType.Setter
        public Builder vmotionVlanId(String vmotionVlanId) {
            if (vmotionVlanId == null) {
              throw new MissingRequiredPropertyException("ClusterNetworkConfiguration", "vmotionVlanId");
            }
            this.vmotionVlanId = vmotionVlanId;
            return this;
        }
        @CustomType.Setter
        public Builder vsanVlanId(String vsanVlanId) {
            if (vsanVlanId == null) {
              throw new MissingRequiredPropertyException("ClusterNetworkConfiguration", "vsanVlanId");
            }
            this.vsanVlanId = vsanVlanId;
            return this;
        }
        @CustomType.Setter
        public Builder vsphereVlanId(@Nullable String vsphereVlanId) {

            this.vsphereVlanId = vsphereVlanId;
            return this;
        }
        public ClusterNetworkConfiguration build() {
            final var _resultValue = new ClusterNetworkConfiguration();
            _resultValue.hcxVlanId = hcxVlanId;
            _resultValue.nsxEdgeUplink1vlanId = nsxEdgeUplink1vlanId;
            _resultValue.nsxEdgeUplink2vlanId = nsxEdgeUplink2vlanId;
            _resultValue.nsxEdgeVtepVlanId = nsxEdgeVtepVlanId;
            _resultValue.nsxVtepVlanId = nsxVtepVlanId;
            _resultValue.provisioningSubnetId = provisioningSubnetId;
            _resultValue.provisioningVlanId = provisioningVlanId;
            _resultValue.replicationVlanId = replicationVlanId;
            _resultValue.vmotionVlanId = vmotionVlanId;
            _resultValue.vsanVlanId = vsanVlanId;
            _resultValue.vsphereVlanId = vsphereVlanId;
            return _resultValue;
        }
    }
}
