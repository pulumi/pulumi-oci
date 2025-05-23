// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Ocvp.inputs.ClusterDatastoreArgs;
import com.pulumi.oci.Ocvp.inputs.ClusterNetworkConfigurationArgs;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ClusterArgs extends com.pulumi.resources.ResourceArgs {

    public static final ClusterArgs Empty = new ClusterArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Capacity Reservation.
     * 
     */
    @Import(name="capacityReservationId")
    private @Nullable Output<String> capacityReservationId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Capacity Reservation.
     * 
     */
    public Optional<Output<String>> capacityReservationId() {
        return Optional.ofNullable(this.capacityReservationId);
    }

    /**
     * The availability domain to create the Cluster&#39;s ESXi hosts in. For multi-AD Cluster deployment, set to `multi-AD`.
     * 
     */
    @Import(name="computeAvailabilityDomain", required=true)
    private Output<String> computeAvailabilityDomain;

    /**
     * @return The availability domain to create the Cluster&#39;s ESXi hosts in. For multi-AD Cluster deployment, set to `multi-AD`.
     * 
     */
    public Output<String> computeAvailabilityDomain() {
        return this.computeAvailabilityDomain;
    }

    /**
     * A list of datastore info for the Cluster. This value is required only when `initialHostShapeName` is a standard shape.
     * 
     */
    @Import(name="datastores")
    private @Nullable Output<List<ClusterDatastoreArgs>> datastores;

    /**
     * @return A list of datastore info for the Cluster. This value is required only when `initialHostShapeName` is a standard shape.
     * 
     */
    public Optional<Output<List<ClusterDatastoreArgs>>> datastores() {
        return Optional.ofNullable(this.datastores);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A descriptive name for the Cluster. Cluster name requirements are 1-16 character length limit, Must start with a letter, Must be English letters, numbers, - only, No repeating hyphens, Must be unique within the region. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A descriptive name for the Cluster. Cluster name requirements are 1-16 character length limit, Must start with a letter, Must be English letters, numbers, - only, No repeating hyphens, Must be unique within the region. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The number of ESXi hosts to create in the Cluster. You can add more hosts later (see [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost)).
     * 
     * **Note:** If you later delete EXSi hosts from a production Cluster to make SDDC total host count less than 3, you are still billed for the 3 minimum recommended  ESXi hosts. Also, you cannot add more VMware workloads to the Cluster until the  SDDC again has at least 3 ESXi hosts.
     * 
     */
    @Import(name="esxiHostsCount", required=true)
    private Output<Integer> esxiHostsCount;

    /**
     * @return The number of ESXi hosts to create in the Cluster. You can add more hosts later (see [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost)).
     * 
     * **Note:** If you later delete EXSi hosts from a production Cluster to make SDDC total host count less than 3, you are still billed for the 3 minimum recommended  ESXi hosts. Also, you cannot add more VMware workloads to the Cluster until the  SDDC again has at least 3 ESXi hosts.
     * 
     */
    public Output<Integer> esxiHostsCount() {
        return this.esxiHostsCount;
    }

    /**
     * (Updatable) The ESXi software bundle to install on the ESXi hosts in the Cluster.  Only versions under the same vmwareSoftwareVersion and have been validate by Oracle Cloud VMware Solution will be accepted. To get a list of the available versions, use [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions).
     * 
     */
    @Import(name="esxiSoftwareVersion")
    private @Nullable Output<String> esxiSoftwareVersion;

    /**
     * @return (Updatable) The ESXi software bundle to install on the ESXi hosts in the Cluster.  Only versions under the same vmwareSoftwareVersion and have been validate by Oracle Cloud VMware Solution will be accepted. To get a list of the available versions, use [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions).
     * 
     */
    public Optional<Output<String>> esxiSoftwareVersion() {
        return Optional.ofNullable(this.esxiSoftwareVersion);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The billing option selected during Cluster creation. [ListSupportedCommitments](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedCommitmentSummary/ListSupportedCommitments).
     * 
     */
    @Import(name="initialCommitment")
    private @Nullable Output<String> initialCommitment;

    /**
     * @return The billing option selected during Cluster creation. [ListSupportedCommitments](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedCommitmentSummary/ListSupportedCommitments).
     * 
     */
    public Optional<Output<String>> initialCommitment() {
        return Optional.ofNullable(this.initialCommitment);
    }

    /**
     * The initial OCPU count of the Cluster&#39;s ESXi hosts.
     * 
     */
    @Import(name="initialHostOcpuCount")
    private @Nullable Output<Double> initialHostOcpuCount;

    /**
     * @return The initial OCPU count of the Cluster&#39;s ESXi hosts.
     * 
     */
    public Optional<Output<Double>> initialHostOcpuCount() {
        return Optional.ofNullable(this.initialHostOcpuCount);
    }

    /**
     * The initial compute shape of the Cluster&#39;s ESXi hosts. [ListSupportedHostShapes](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedHostShapes/ListSupportedHostShapes).
     * 
     */
    @Import(name="initialHostShapeName")
    private @Nullable Output<String> initialHostShapeName;

    /**
     * @return The initial compute shape of the Cluster&#39;s ESXi hosts. [ListSupportedHostShapes](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedHostShapes/ListSupportedHostShapes).
     * 
     */
    public Optional<Output<String>> initialHostShapeName() {
        return Optional.ofNullable(this.initialHostShapeName);
    }

    /**
     * A prefix used in the name of each ESXi host and Compute instance in the Cluster. If this isn&#39;t set, the Cluster&#39;s `displayName` is used as the prefix.
     * 
     * For example, if the value is `myCluster`, the ESXi hosts are named `myCluster-1`, `myCluster-2`, and so on.
     * 
     */
    @Import(name="instanceDisplayNamePrefix")
    private @Nullable Output<String> instanceDisplayNamePrefix;

    /**
     * @return A prefix used in the name of each ESXi host and Compute instance in the Cluster. If this isn&#39;t set, the Cluster&#39;s `displayName` is used as the prefix.
     * 
     * For example, if the value is `myCluster`, the ESXi hosts are named `myCluster-1`, `myCluster-2`, and so on.
     * 
     */
    public Optional<Output<String>> instanceDisplayNamePrefix() {
        return Optional.ofNullable(this.instanceDisplayNamePrefix);
    }

    /**
     * Indicates whether shielded instance is enabled for this Cluster.
     * 
     */
    @Import(name="isShieldedInstanceEnabled")
    private @Nullable Output<Boolean> isShieldedInstanceEnabled;

    /**
     * @return Indicates whether shielded instance is enabled for this Cluster.
     * 
     */
    public Optional<Output<Boolean>> isShieldedInstanceEnabled() {
        return Optional.ofNullable(this.isShieldedInstanceEnabled);
    }

    /**
     * (Updatable) The network configurations used by Cluster, including [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet and VLANs.
     * 
     */
    @Import(name="networkConfiguration", required=true)
    private Output<ClusterNetworkConfigurationArgs> networkConfiguration;

    /**
     * @return (Updatable) The network configurations used by Cluster, including [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet and VLANs.
     * 
     */
    public Output<ClusterNetworkConfigurationArgs> networkConfiguration() {
        return this.networkConfiguration;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the Cluster belongs to.
     * 
     */
    @Import(name="sddcId", required=true)
    private Output<String> sddcId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the Cluster belongs to.
     * 
     */
    public Output<String> sddcId() {
        return this.sddcId;
    }

    /**
     * (Updatable) The VMware software bundle to install on the ESXi hosts in the Cluster. To get a list of the available versions, use [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions).
     * 
     */
    @Import(name="vmwareSoftwareVersion")
    private @Nullable Output<String> vmwareSoftwareVersion;

    /**
     * @return (Updatable) The VMware software bundle to install on the ESXi hosts in the Cluster. To get a list of the available versions, use [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions).
     * 
     */
    public Optional<Output<String>> vmwareSoftwareVersion() {
        return Optional.ofNullable(this.vmwareSoftwareVersion);
    }

    /**
     * The CIDR block for the IP addresses that VMware VMs in the Cluster use to run application workloads.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="workloadNetworkCidr")
    private @Nullable Output<String> workloadNetworkCidr;

    /**
     * @return The CIDR block for the IP addresses that VMware VMs in the Cluster use to run application workloads.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> workloadNetworkCidr() {
        return Optional.ofNullable(this.workloadNetworkCidr);
    }

    private ClusterArgs() {}

    private ClusterArgs(ClusterArgs $) {
        this.capacityReservationId = $.capacityReservationId;
        this.computeAvailabilityDomain = $.computeAvailabilityDomain;
        this.datastores = $.datastores;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.esxiHostsCount = $.esxiHostsCount;
        this.esxiSoftwareVersion = $.esxiSoftwareVersion;
        this.freeformTags = $.freeformTags;
        this.initialCommitment = $.initialCommitment;
        this.initialHostOcpuCount = $.initialHostOcpuCount;
        this.initialHostShapeName = $.initialHostShapeName;
        this.instanceDisplayNamePrefix = $.instanceDisplayNamePrefix;
        this.isShieldedInstanceEnabled = $.isShieldedInstanceEnabled;
        this.networkConfiguration = $.networkConfiguration;
        this.sddcId = $.sddcId;
        this.vmwareSoftwareVersion = $.vmwareSoftwareVersion;
        this.workloadNetworkCidr = $.workloadNetworkCidr;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ClusterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ClusterArgs $;

        public Builder() {
            $ = new ClusterArgs();
        }

        public Builder(ClusterArgs defaults) {
            $ = new ClusterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param capacityReservationId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Capacity Reservation.
         * 
         * @return builder
         * 
         */
        public Builder capacityReservationId(@Nullable Output<String> capacityReservationId) {
            $.capacityReservationId = capacityReservationId;
            return this;
        }

        /**
         * @param capacityReservationId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Capacity Reservation.
         * 
         * @return builder
         * 
         */
        public Builder capacityReservationId(String capacityReservationId) {
            return capacityReservationId(Output.of(capacityReservationId));
        }

        /**
         * @param computeAvailabilityDomain The availability domain to create the Cluster&#39;s ESXi hosts in. For multi-AD Cluster deployment, set to `multi-AD`.
         * 
         * @return builder
         * 
         */
        public Builder computeAvailabilityDomain(Output<String> computeAvailabilityDomain) {
            $.computeAvailabilityDomain = computeAvailabilityDomain;
            return this;
        }

        /**
         * @param computeAvailabilityDomain The availability domain to create the Cluster&#39;s ESXi hosts in. For multi-AD Cluster deployment, set to `multi-AD`.
         * 
         * @return builder
         * 
         */
        public Builder computeAvailabilityDomain(String computeAvailabilityDomain) {
            return computeAvailabilityDomain(Output.of(computeAvailabilityDomain));
        }

        /**
         * @param datastores A list of datastore info for the Cluster. This value is required only when `initialHostShapeName` is a standard shape.
         * 
         * @return builder
         * 
         */
        public Builder datastores(@Nullable Output<List<ClusterDatastoreArgs>> datastores) {
            $.datastores = datastores;
            return this;
        }

        /**
         * @param datastores A list of datastore info for the Cluster. This value is required only when `initialHostShapeName` is a standard shape.
         * 
         * @return builder
         * 
         */
        public Builder datastores(List<ClusterDatastoreArgs> datastores) {
            return datastores(Output.of(datastores));
        }

        /**
         * @param datastores A list of datastore info for the Cluster. This value is required only when `initialHostShapeName` is a standard shape.
         * 
         * @return builder
         * 
         */
        public Builder datastores(ClusterDatastoreArgs... datastores) {
            return datastores(List.of(datastores));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A descriptive name for the Cluster. Cluster name requirements are 1-16 character length limit, Must start with a letter, Must be English letters, numbers, - only, No repeating hyphens, Must be unique within the region. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A descriptive name for the Cluster. Cluster name requirements are 1-16 character length limit, Must start with a letter, Must be English letters, numbers, - only, No repeating hyphens, Must be unique within the region. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param esxiHostsCount The number of ESXi hosts to create in the Cluster. You can add more hosts later (see [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost)).
         * 
         * **Note:** If you later delete EXSi hosts from a production Cluster to make SDDC total host count less than 3, you are still billed for the 3 minimum recommended  ESXi hosts. Also, you cannot add more VMware workloads to the Cluster until the  SDDC again has at least 3 ESXi hosts.
         * 
         * @return builder
         * 
         */
        public Builder esxiHostsCount(Output<Integer> esxiHostsCount) {
            $.esxiHostsCount = esxiHostsCount;
            return this;
        }

        /**
         * @param esxiHostsCount The number of ESXi hosts to create in the Cluster. You can add more hosts later (see [CreateEsxiHost](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/EsxiHost/CreateEsxiHost)).
         * 
         * **Note:** If you later delete EXSi hosts from a production Cluster to make SDDC total host count less than 3, you are still billed for the 3 minimum recommended  ESXi hosts. Also, you cannot add more VMware workloads to the Cluster until the  SDDC again has at least 3 ESXi hosts.
         * 
         * @return builder
         * 
         */
        public Builder esxiHostsCount(Integer esxiHostsCount) {
            return esxiHostsCount(Output.of(esxiHostsCount));
        }

        /**
         * @param esxiSoftwareVersion (Updatable) The ESXi software bundle to install on the ESXi hosts in the Cluster.  Only versions under the same vmwareSoftwareVersion and have been validate by Oracle Cloud VMware Solution will be accepted. To get a list of the available versions, use [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions).
         * 
         * @return builder
         * 
         */
        public Builder esxiSoftwareVersion(@Nullable Output<String> esxiSoftwareVersion) {
            $.esxiSoftwareVersion = esxiSoftwareVersion;
            return this;
        }

        /**
         * @param esxiSoftwareVersion (Updatable) The ESXi software bundle to install on the ESXi hosts in the Cluster.  Only versions under the same vmwareSoftwareVersion and have been validate by Oracle Cloud VMware Solution will be accepted. To get a list of the available versions, use [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions).
         * 
         * @return builder
         * 
         */
        public Builder esxiSoftwareVersion(String esxiSoftwareVersion) {
            return esxiSoftwareVersion(Output.of(esxiSoftwareVersion));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param initialCommitment The billing option selected during Cluster creation. [ListSupportedCommitments](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedCommitmentSummary/ListSupportedCommitments).
         * 
         * @return builder
         * 
         */
        public Builder initialCommitment(@Nullable Output<String> initialCommitment) {
            $.initialCommitment = initialCommitment;
            return this;
        }

        /**
         * @param initialCommitment The billing option selected during Cluster creation. [ListSupportedCommitments](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedCommitmentSummary/ListSupportedCommitments).
         * 
         * @return builder
         * 
         */
        public Builder initialCommitment(String initialCommitment) {
            return initialCommitment(Output.of(initialCommitment));
        }

        /**
         * @param initialHostOcpuCount The initial OCPU count of the Cluster&#39;s ESXi hosts.
         * 
         * @return builder
         * 
         */
        public Builder initialHostOcpuCount(@Nullable Output<Double> initialHostOcpuCount) {
            $.initialHostOcpuCount = initialHostOcpuCount;
            return this;
        }

        /**
         * @param initialHostOcpuCount The initial OCPU count of the Cluster&#39;s ESXi hosts.
         * 
         * @return builder
         * 
         */
        public Builder initialHostOcpuCount(Double initialHostOcpuCount) {
            return initialHostOcpuCount(Output.of(initialHostOcpuCount));
        }

        /**
         * @param initialHostShapeName The initial compute shape of the Cluster&#39;s ESXi hosts. [ListSupportedHostShapes](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedHostShapes/ListSupportedHostShapes).
         * 
         * @return builder
         * 
         */
        public Builder initialHostShapeName(@Nullable Output<String> initialHostShapeName) {
            $.initialHostShapeName = initialHostShapeName;
            return this;
        }

        /**
         * @param initialHostShapeName The initial compute shape of the Cluster&#39;s ESXi hosts. [ListSupportedHostShapes](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedHostShapes/ListSupportedHostShapes).
         * 
         * @return builder
         * 
         */
        public Builder initialHostShapeName(String initialHostShapeName) {
            return initialHostShapeName(Output.of(initialHostShapeName));
        }

        /**
         * @param instanceDisplayNamePrefix A prefix used in the name of each ESXi host and Compute instance in the Cluster. If this isn&#39;t set, the Cluster&#39;s `displayName` is used as the prefix.
         * 
         * For example, if the value is `myCluster`, the ESXi hosts are named `myCluster-1`, `myCluster-2`, and so on.
         * 
         * @return builder
         * 
         */
        public Builder instanceDisplayNamePrefix(@Nullable Output<String> instanceDisplayNamePrefix) {
            $.instanceDisplayNamePrefix = instanceDisplayNamePrefix;
            return this;
        }

        /**
         * @param instanceDisplayNamePrefix A prefix used in the name of each ESXi host and Compute instance in the Cluster. If this isn&#39;t set, the Cluster&#39;s `displayName` is used as the prefix.
         * 
         * For example, if the value is `myCluster`, the ESXi hosts are named `myCluster-1`, `myCluster-2`, and so on.
         * 
         * @return builder
         * 
         */
        public Builder instanceDisplayNamePrefix(String instanceDisplayNamePrefix) {
            return instanceDisplayNamePrefix(Output.of(instanceDisplayNamePrefix));
        }

        /**
         * @param isShieldedInstanceEnabled Indicates whether shielded instance is enabled for this Cluster.
         * 
         * @return builder
         * 
         */
        public Builder isShieldedInstanceEnabled(@Nullable Output<Boolean> isShieldedInstanceEnabled) {
            $.isShieldedInstanceEnabled = isShieldedInstanceEnabled;
            return this;
        }

        /**
         * @param isShieldedInstanceEnabled Indicates whether shielded instance is enabled for this Cluster.
         * 
         * @return builder
         * 
         */
        public Builder isShieldedInstanceEnabled(Boolean isShieldedInstanceEnabled) {
            return isShieldedInstanceEnabled(Output.of(isShieldedInstanceEnabled));
        }

        /**
         * @param networkConfiguration (Updatable) The network configurations used by Cluster, including [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet and VLANs.
         * 
         * @return builder
         * 
         */
        public Builder networkConfiguration(Output<ClusterNetworkConfigurationArgs> networkConfiguration) {
            $.networkConfiguration = networkConfiguration;
            return this;
        }

        /**
         * @param networkConfiguration (Updatable) The network configurations used by Cluster, including [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet and VLANs.
         * 
         * @return builder
         * 
         */
        public Builder networkConfiguration(ClusterNetworkConfigurationArgs networkConfiguration) {
            return networkConfiguration(Output.of(networkConfiguration));
        }

        /**
         * @param sddcId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the Cluster belongs to.
         * 
         * @return builder
         * 
         */
        public Builder sddcId(Output<String> sddcId) {
            $.sddcId = sddcId;
            return this;
        }

        /**
         * @param sddcId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the Cluster belongs to.
         * 
         * @return builder
         * 
         */
        public Builder sddcId(String sddcId) {
            return sddcId(Output.of(sddcId));
        }

        /**
         * @param vmwareSoftwareVersion (Updatable) The VMware software bundle to install on the ESXi hosts in the Cluster. To get a list of the available versions, use [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions).
         * 
         * @return builder
         * 
         */
        public Builder vmwareSoftwareVersion(@Nullable Output<String> vmwareSoftwareVersion) {
            $.vmwareSoftwareVersion = vmwareSoftwareVersion;
            return this;
        }

        /**
         * @param vmwareSoftwareVersion (Updatable) The VMware software bundle to install on the ESXi hosts in the Cluster. To get a list of the available versions, use [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions).
         * 
         * @return builder
         * 
         */
        public Builder vmwareSoftwareVersion(String vmwareSoftwareVersion) {
            return vmwareSoftwareVersion(Output.of(vmwareSoftwareVersion));
        }

        /**
         * @param workloadNetworkCidr The CIDR block for the IP addresses that VMware VMs in the Cluster use to run application workloads.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder workloadNetworkCidr(@Nullable Output<String> workloadNetworkCidr) {
            $.workloadNetworkCidr = workloadNetworkCidr;
            return this;
        }

        /**
         * @param workloadNetworkCidr The CIDR block for the IP addresses that VMware VMs in the Cluster use to run application workloads.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder workloadNetworkCidr(String workloadNetworkCidr) {
            return workloadNetworkCidr(Output.of(workloadNetworkCidr));
        }

        public ClusterArgs build() {
            if ($.computeAvailabilityDomain == null) {
                throw new MissingRequiredPropertyException("ClusterArgs", "computeAvailabilityDomain");
            }
            if ($.esxiHostsCount == null) {
                throw new MissingRequiredPropertyException("ClusterArgs", "esxiHostsCount");
            }
            if ($.networkConfiguration == null) {
                throw new MissingRequiredPropertyException("ClusterArgs", "networkConfiguration");
            }
            if ($.sddcId == null) {
                throw new MissingRequiredPropertyException("ClusterArgs", "sddcId");
            }
            return $;
        }
    }

}
