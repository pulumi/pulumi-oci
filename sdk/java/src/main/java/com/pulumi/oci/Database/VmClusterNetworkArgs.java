// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.VmClusterNetworkScanArgs;
import com.pulumi.oci.Database.inputs.VmClusterNetworkVmNetworkArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VmClusterNetworkArgs extends com.pulumi.resources.ResourceArgs {

    public static final VmClusterNetworkArgs Empty = new VmClusterNetworkArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * The user-friendly name for the Exadata Cloud@Customer VM cluster network. The name does not need to be unique.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return The user-friendly name for the Exadata Cloud@Customer VM cluster network. The name does not need to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) The list of DNS server IP addresses. Maximum of 3 allowed.
     * 
     */
    @Import(name="dns")
    private @Nullable Output<List<String>> dns;

    /**
     * @return (Updatable) The list of DNS server IP addresses. Maximum of 3 allowed.
     * 
     */
    public Optional<Output<List<String>>> dns() {
        return Optional.ofNullable(this.dns);
    }

    /**
     * The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="exadataInfrastructureId", required=true)
    private Output<String> exadataInfrastructureId;

    /**
     * @return The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> exadataInfrastructureId() {
        return this.exadataInfrastructureId;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The list of NTP server IP addresses. Maximum of 3 allowed.
     * 
     */
    @Import(name="ntps")
    private @Nullable Output<List<String>> ntps;

    /**
     * @return (Updatable) The list of NTP server IP addresses. Maximum of 3 allowed.
     * 
     */
    public Optional<Output<List<String>>> ntps() {
        return Optional.ofNullable(this.ntps);
    }

    /**
     * (Updatable) The SCAN details.
     * 
     */
    @Import(name="scans", required=true)
    private Output<List<VmClusterNetworkScanArgs>> scans;

    /**
     * @return (Updatable) The SCAN details.
     * 
     */
    public Output<List<VmClusterNetworkScanArgs>> scans() {
        return this.scans;
    }

    @Import(name="validateVmClusterNetwork")
    private @Nullable Output<Boolean> validateVmClusterNetwork;

    public Optional<Output<Boolean>> validateVmClusterNetwork() {
        return Optional.ofNullable(this.validateVmClusterNetwork);
    }

    /**
     * (Updatable) Details of the client and backup networks.
     * 
     */
    @Import(name="vmNetworks", required=true)
    private Output<List<VmClusterNetworkVmNetworkArgs>> vmNetworks;

    /**
     * @return (Updatable) Details of the client and backup networks.
     * 
     */
    public Output<List<VmClusterNetworkVmNetworkArgs>> vmNetworks() {
        return this.vmNetworks;
    }

    private VmClusterNetworkArgs() {}

    private VmClusterNetworkArgs(VmClusterNetworkArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.dns = $.dns;
        this.exadataInfrastructureId = $.exadataInfrastructureId;
        this.freeformTags = $.freeformTags;
        this.ntps = $.ntps;
        this.scans = $.scans;
        this.validateVmClusterNetwork = $.validateVmClusterNetwork;
        this.vmNetworks = $.vmNetworks;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VmClusterNetworkArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VmClusterNetworkArgs $;

        public Builder() {
            $ = new VmClusterNetworkArgs();
        }

        public Builder(VmClusterNetworkArgs defaults) {
            $ = new VmClusterNetworkArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName The user-friendly name for the Exadata Cloud@Customer VM cluster network. The name does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The user-friendly name for the Exadata Cloud@Customer VM cluster network. The name does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param dns (Updatable) The list of DNS server IP addresses. Maximum of 3 allowed.
         * 
         * @return builder
         * 
         */
        public Builder dns(@Nullable Output<List<String>> dns) {
            $.dns = dns;
            return this;
        }

        /**
         * @param dns (Updatable) The list of DNS server IP addresses. Maximum of 3 allowed.
         * 
         * @return builder
         * 
         */
        public Builder dns(List<String> dns) {
            return dns(Output.of(dns));
        }

        /**
         * @param dns (Updatable) The list of DNS server IP addresses. Maximum of 3 allowed.
         * 
         * @return builder
         * 
         */
        public Builder dns(String... dns) {
            return dns(List.of(dns));
        }

        /**
         * @param exadataInfrastructureId The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder exadataInfrastructureId(Output<String> exadataInfrastructureId) {
            $.exadataInfrastructureId = exadataInfrastructureId;
            return this;
        }

        /**
         * @param exadataInfrastructureId The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder exadataInfrastructureId(String exadataInfrastructureId) {
            return exadataInfrastructureId(Output.of(exadataInfrastructureId));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param ntps (Updatable) The list of NTP server IP addresses. Maximum of 3 allowed.
         * 
         * @return builder
         * 
         */
        public Builder ntps(@Nullable Output<List<String>> ntps) {
            $.ntps = ntps;
            return this;
        }

        /**
         * @param ntps (Updatable) The list of NTP server IP addresses. Maximum of 3 allowed.
         * 
         * @return builder
         * 
         */
        public Builder ntps(List<String> ntps) {
            return ntps(Output.of(ntps));
        }

        /**
         * @param ntps (Updatable) The list of NTP server IP addresses. Maximum of 3 allowed.
         * 
         * @return builder
         * 
         */
        public Builder ntps(String... ntps) {
            return ntps(List.of(ntps));
        }

        /**
         * @param scans (Updatable) The SCAN details.
         * 
         * @return builder
         * 
         */
        public Builder scans(Output<List<VmClusterNetworkScanArgs>> scans) {
            $.scans = scans;
            return this;
        }

        /**
         * @param scans (Updatable) The SCAN details.
         * 
         * @return builder
         * 
         */
        public Builder scans(List<VmClusterNetworkScanArgs> scans) {
            return scans(Output.of(scans));
        }

        /**
         * @param scans (Updatable) The SCAN details.
         * 
         * @return builder
         * 
         */
        public Builder scans(VmClusterNetworkScanArgs... scans) {
            return scans(List.of(scans));
        }

        public Builder validateVmClusterNetwork(@Nullable Output<Boolean> validateVmClusterNetwork) {
            $.validateVmClusterNetwork = validateVmClusterNetwork;
            return this;
        }

        public Builder validateVmClusterNetwork(Boolean validateVmClusterNetwork) {
            return validateVmClusterNetwork(Output.of(validateVmClusterNetwork));
        }

        /**
         * @param vmNetworks (Updatable) Details of the client and backup networks.
         * 
         * @return builder
         * 
         */
        public Builder vmNetworks(Output<List<VmClusterNetworkVmNetworkArgs>> vmNetworks) {
            $.vmNetworks = vmNetworks;
            return this;
        }

        /**
         * @param vmNetworks (Updatable) Details of the client and backup networks.
         * 
         * @return builder
         * 
         */
        public Builder vmNetworks(List<VmClusterNetworkVmNetworkArgs> vmNetworks) {
            return vmNetworks(Output.of(vmNetworks));
        }

        /**
         * @param vmNetworks (Updatable) Details of the client and backup networks.
         * 
         * @return builder
         * 
         */
        public Builder vmNetworks(VmClusterNetworkVmNetworkArgs... vmNetworks) {
            return vmNetworks(List.of(vmNetworks));
        }

        public VmClusterNetworkArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.exadataInfrastructureId = Objects.requireNonNull($.exadataInfrastructureId, "expected parameter 'exadataInfrastructureId' to be non-null");
            $.scans = Objects.requireNonNull($.scans, "expected parameter 'scans' to be non-null");
            $.vmNetworks = Objects.requireNonNull($.vmNetworks, "expected parameter 'vmNetworks' to be non-null");
            return $;
        }
    }

}