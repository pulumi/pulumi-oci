// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VmClusterArgs extends com.pulumi.resources.ResourceArgs {

    public static final VmClusterArgs Empty = new VmClusterArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="cpuCoreCount", required=true)
    private Output<Integer> cpuCoreCount;

    public Output<Integer> cpuCoreCount() {
        return this.cpuCoreCount;
    }

    @Import(name="dataStorageSizeInGb")
    private @Nullable Output<Double> dataStorageSizeInGb;

    public Optional<Output<Double>> dataStorageSizeInGb() {
        return Optional.ofNullable(this.dataStorageSizeInGb);
    }

    /**
     * (Updatable) The data disk group size to be allocated in TBs.
     * 
     */
    @Import(name="dataStorageSizeInTbs")
    private @Nullable Output<Double> dataStorageSizeInTbs;

    /**
     * @return (Updatable) The data disk group size to be allocated in TBs.
     * 
     */
    public Optional<Output<Double>> dataStorageSizeInTbs() {
        return Optional.ofNullable(this.dataStorageSizeInTbs);
    }

    /**
     * (Updatable) The local node storage to be allocated in GBs.
     * 
     */
    @Import(name="dbNodeStorageSizeInGbs")
    private @Nullable Output<Integer> dbNodeStorageSizeInGbs;

    /**
     * @return (Updatable) The local node storage to be allocated in GBs.
     * 
     */
    public Optional<Output<Integer>> dbNodeStorageSizeInGbs() {
        return Optional.ofNullable(this.dbNodeStorageSizeInGbs);
    }

    /**
     * The list of Db server.
     * 
     */
    @Import(name="dbServers")
    private @Nullable Output<List<String>> dbServers;

    /**
     * @return The list of Db server.
     * 
     */
    public Optional<Output<List<String>>> dbServers() {
        return Optional.ofNullable(this.dbServers);
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
     * The user-friendly name for the VM cluster. The name does not need to be unique.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return The user-friendly name for the VM cluster. The name does not need to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    @Import(name="exadataInfrastructureId", required=true)
    private Output<String> exadataInfrastructureId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
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
     * The Oracle Grid Infrastructure software version for the VM cluster.
     * 
     */
    @Import(name="giVersion", required=true)
    private Output<String> giVersion;

    /**
     * @return The Oracle Grid Infrastructure software version for the VM cluster.
     * 
     */
    public Output<String> giVersion() {
        return this.giVersion;
    }

    /**
     * If true, database backup on local Exadata storage is configured for the VM cluster. If false, database backup on local Exadata storage is not available in the VM cluster.
     * 
     */
    @Import(name="isLocalBackupEnabled")
    private @Nullable Output<Boolean> isLocalBackupEnabled;

    /**
     * @return If true, database backup on local Exadata storage is configured for the VM cluster. If false, database backup on local Exadata storage is not available in the VM cluster.
     * 
     */
    public Optional<Output<Boolean>> isLocalBackupEnabled() {
        return Optional.ofNullable(this.isLocalBackupEnabled);
    }

    /**
     * If true, the sparse disk group is configured for the VM cluster. If false, the sparse disk group is not created.
     * 
     */
    @Import(name="isSparseDiskgroupEnabled")
    private @Nullable Output<Boolean> isSparseDiskgroupEnabled;

    /**
     * @return If true, the sparse disk group is configured for the VM cluster. If false, the sparse disk group is not created.
     * 
     */
    public Optional<Output<Boolean>> isSparseDiskgroupEnabled() {
        return Optional.ofNullable(this.isSparseDiskgroupEnabled);
    }

    /**
     * (Updatable) The Oracle license model that applies to the VM cluster. The default is BRING_YOUR_OWN_LICENSE.
     * 
     */
    @Import(name="licenseModel")
    private @Nullable Output<String> licenseModel;

    /**
     * @return (Updatable) The Oracle license model that applies to the VM cluster. The default is BRING_YOUR_OWN_LICENSE.
     * 
     */
    public Optional<Output<String>> licenseModel() {
        return Optional.ofNullable(this.licenseModel);
    }

    /**
     * (Updatable) The memory to be allocated in GBs.
     * 
     */
    @Import(name="memorySizeInGbs")
    private @Nullable Output<Integer> memorySizeInGbs;

    /**
     * @return (Updatable) The memory to be allocated in GBs.
     * 
     */
    public Optional<Output<Integer>> memorySizeInGbs() {
        return Optional.ofNullable(this.memorySizeInGbs);
    }

    @Import(name="ocpuCount")
    private @Nullable Output<Double> ocpuCount;

    public Optional<Output<Double>> ocpuCount() {
        return Optional.ofNullable(this.ocpuCount);
    }

    /**
     * (Updatable) The public key portion of one or more key pairs used for SSH access to the VM cluster.
     * 
     */
    @Import(name="sshPublicKeys", required=true)
    private Output<List<String>> sshPublicKeys;

    /**
     * @return (Updatable) The public key portion of one or more key pairs used for SSH access to the VM cluster.
     * 
     */
    public Output<List<String>> sshPublicKeys() {
        return this.sshPublicKeys;
    }

    /**
     * The time zone to use for the VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     * 
     */
    @Import(name="timeZone")
    private @Nullable Output<String> timeZone;

    /**
     * @return The time zone to use for the VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     * 
     */
    public Optional<Output<String>> timeZone() {
        return Optional.ofNullable(this.timeZone);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     * 
     */
    @Import(name="vmClusterNetworkId", required=true)
    private Output<String> vmClusterNetworkId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     * 
     */
    public Output<String> vmClusterNetworkId() {
        return this.vmClusterNetworkId;
    }

    private VmClusterArgs() {}

    private VmClusterArgs(VmClusterArgs $) {
        this.compartmentId = $.compartmentId;
        this.cpuCoreCount = $.cpuCoreCount;
        this.dataStorageSizeInGb = $.dataStorageSizeInGb;
        this.dataStorageSizeInTbs = $.dataStorageSizeInTbs;
        this.dbNodeStorageSizeInGbs = $.dbNodeStorageSizeInGbs;
        this.dbServers = $.dbServers;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.exadataInfrastructureId = $.exadataInfrastructureId;
        this.freeformTags = $.freeformTags;
        this.giVersion = $.giVersion;
        this.isLocalBackupEnabled = $.isLocalBackupEnabled;
        this.isSparseDiskgroupEnabled = $.isSparseDiskgroupEnabled;
        this.licenseModel = $.licenseModel;
        this.memorySizeInGbs = $.memorySizeInGbs;
        this.ocpuCount = $.ocpuCount;
        this.sshPublicKeys = $.sshPublicKeys;
        this.timeZone = $.timeZone;
        this.vmClusterNetworkId = $.vmClusterNetworkId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VmClusterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VmClusterArgs $;

        public Builder() {
            $ = new VmClusterArgs();
        }

        public Builder(VmClusterArgs defaults) {
            $ = new VmClusterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder cpuCoreCount(Output<Integer> cpuCoreCount) {
            $.cpuCoreCount = cpuCoreCount;
            return this;
        }

        public Builder cpuCoreCount(Integer cpuCoreCount) {
            return cpuCoreCount(Output.of(cpuCoreCount));
        }

        public Builder dataStorageSizeInGb(@Nullable Output<Double> dataStorageSizeInGb) {
            $.dataStorageSizeInGb = dataStorageSizeInGb;
            return this;
        }

        public Builder dataStorageSizeInGb(Double dataStorageSizeInGb) {
            return dataStorageSizeInGb(Output.of(dataStorageSizeInGb));
        }

        /**
         * @param dataStorageSizeInTbs (Updatable) The data disk group size to be allocated in TBs.
         * 
         * @return builder
         * 
         */
        public Builder dataStorageSizeInTbs(@Nullable Output<Double> dataStorageSizeInTbs) {
            $.dataStorageSizeInTbs = dataStorageSizeInTbs;
            return this;
        }

        /**
         * @param dataStorageSizeInTbs (Updatable) The data disk group size to be allocated in TBs.
         * 
         * @return builder
         * 
         */
        public Builder dataStorageSizeInTbs(Double dataStorageSizeInTbs) {
            return dataStorageSizeInTbs(Output.of(dataStorageSizeInTbs));
        }

        /**
         * @param dbNodeStorageSizeInGbs (Updatable) The local node storage to be allocated in GBs.
         * 
         * @return builder
         * 
         */
        public Builder dbNodeStorageSizeInGbs(@Nullable Output<Integer> dbNodeStorageSizeInGbs) {
            $.dbNodeStorageSizeInGbs = dbNodeStorageSizeInGbs;
            return this;
        }

        /**
         * @param dbNodeStorageSizeInGbs (Updatable) The local node storage to be allocated in GBs.
         * 
         * @return builder
         * 
         */
        public Builder dbNodeStorageSizeInGbs(Integer dbNodeStorageSizeInGbs) {
            return dbNodeStorageSizeInGbs(Output.of(dbNodeStorageSizeInGbs));
        }

        /**
         * @param dbServers The list of Db server.
         * 
         * @return builder
         * 
         */
        public Builder dbServers(@Nullable Output<List<String>> dbServers) {
            $.dbServers = dbServers;
            return this;
        }

        /**
         * @param dbServers The list of Db server.
         * 
         * @return builder
         * 
         */
        public Builder dbServers(List<String> dbServers) {
            return dbServers(Output.of(dbServers));
        }

        /**
         * @param dbServers The list of Db server.
         * 
         * @return builder
         * 
         */
        public Builder dbServers(String... dbServers) {
            return dbServers(List.of(dbServers));
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
         * @param displayName The user-friendly name for the VM cluster. The name does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The user-friendly name for the VM cluster. The name does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param exadataInfrastructureId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder exadataInfrastructureId(Output<String> exadataInfrastructureId) {
            $.exadataInfrastructureId = exadataInfrastructureId;
            return this;
        }

        /**
         * @param exadataInfrastructureId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
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
         * @param giVersion The Oracle Grid Infrastructure software version for the VM cluster.
         * 
         * @return builder
         * 
         */
        public Builder giVersion(Output<String> giVersion) {
            $.giVersion = giVersion;
            return this;
        }

        /**
         * @param giVersion The Oracle Grid Infrastructure software version for the VM cluster.
         * 
         * @return builder
         * 
         */
        public Builder giVersion(String giVersion) {
            return giVersion(Output.of(giVersion));
        }

        /**
         * @param isLocalBackupEnabled If true, database backup on local Exadata storage is configured for the VM cluster. If false, database backup on local Exadata storage is not available in the VM cluster.
         * 
         * @return builder
         * 
         */
        public Builder isLocalBackupEnabled(@Nullable Output<Boolean> isLocalBackupEnabled) {
            $.isLocalBackupEnabled = isLocalBackupEnabled;
            return this;
        }

        /**
         * @param isLocalBackupEnabled If true, database backup on local Exadata storage is configured for the VM cluster. If false, database backup on local Exadata storage is not available in the VM cluster.
         * 
         * @return builder
         * 
         */
        public Builder isLocalBackupEnabled(Boolean isLocalBackupEnabled) {
            return isLocalBackupEnabled(Output.of(isLocalBackupEnabled));
        }

        /**
         * @param isSparseDiskgroupEnabled If true, the sparse disk group is configured for the VM cluster. If false, the sparse disk group is not created.
         * 
         * @return builder
         * 
         */
        public Builder isSparseDiskgroupEnabled(@Nullable Output<Boolean> isSparseDiskgroupEnabled) {
            $.isSparseDiskgroupEnabled = isSparseDiskgroupEnabled;
            return this;
        }

        /**
         * @param isSparseDiskgroupEnabled If true, the sparse disk group is configured for the VM cluster. If false, the sparse disk group is not created.
         * 
         * @return builder
         * 
         */
        public Builder isSparseDiskgroupEnabled(Boolean isSparseDiskgroupEnabled) {
            return isSparseDiskgroupEnabled(Output.of(isSparseDiskgroupEnabled));
        }

        /**
         * @param licenseModel (Updatable) The Oracle license model that applies to the VM cluster. The default is BRING_YOUR_OWN_LICENSE.
         * 
         * @return builder
         * 
         */
        public Builder licenseModel(@Nullable Output<String> licenseModel) {
            $.licenseModel = licenseModel;
            return this;
        }

        /**
         * @param licenseModel (Updatable) The Oracle license model that applies to the VM cluster. The default is BRING_YOUR_OWN_LICENSE.
         * 
         * @return builder
         * 
         */
        public Builder licenseModel(String licenseModel) {
            return licenseModel(Output.of(licenseModel));
        }

        /**
         * @param memorySizeInGbs (Updatable) The memory to be allocated in GBs.
         * 
         * @return builder
         * 
         */
        public Builder memorySizeInGbs(@Nullable Output<Integer> memorySizeInGbs) {
            $.memorySizeInGbs = memorySizeInGbs;
            return this;
        }

        /**
         * @param memorySizeInGbs (Updatable) The memory to be allocated in GBs.
         * 
         * @return builder
         * 
         */
        public Builder memorySizeInGbs(Integer memorySizeInGbs) {
            return memorySizeInGbs(Output.of(memorySizeInGbs));
        }

        public Builder ocpuCount(@Nullable Output<Double> ocpuCount) {
            $.ocpuCount = ocpuCount;
            return this;
        }

        public Builder ocpuCount(Double ocpuCount) {
            return ocpuCount(Output.of(ocpuCount));
        }

        /**
         * @param sshPublicKeys (Updatable) The public key portion of one or more key pairs used for SSH access to the VM cluster.
         * 
         * @return builder
         * 
         */
        public Builder sshPublicKeys(Output<List<String>> sshPublicKeys) {
            $.sshPublicKeys = sshPublicKeys;
            return this;
        }

        /**
         * @param sshPublicKeys (Updatable) The public key portion of one or more key pairs used for SSH access to the VM cluster.
         * 
         * @return builder
         * 
         */
        public Builder sshPublicKeys(List<String> sshPublicKeys) {
            return sshPublicKeys(Output.of(sshPublicKeys));
        }

        /**
         * @param sshPublicKeys (Updatable) The public key portion of one or more key pairs used for SSH access to the VM cluster.
         * 
         * @return builder
         * 
         */
        public Builder sshPublicKeys(String... sshPublicKeys) {
            return sshPublicKeys(List.of(sshPublicKeys));
        }

        /**
         * @param timeZone The time zone to use for the VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
         * 
         * @return builder
         * 
         */
        public Builder timeZone(@Nullable Output<String> timeZone) {
            $.timeZone = timeZone;
            return this;
        }

        /**
         * @param timeZone The time zone to use for the VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
         * 
         * @return builder
         * 
         */
        public Builder timeZone(String timeZone) {
            return timeZone(Output.of(timeZone));
        }

        /**
         * @param vmClusterNetworkId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
         * 
         * @return builder
         * 
         */
        public Builder vmClusterNetworkId(Output<String> vmClusterNetworkId) {
            $.vmClusterNetworkId = vmClusterNetworkId;
            return this;
        }

        /**
         * @param vmClusterNetworkId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
         * 
         * @return builder
         * 
         */
        public Builder vmClusterNetworkId(String vmClusterNetworkId) {
            return vmClusterNetworkId(Output.of(vmClusterNetworkId));
        }

        public VmClusterArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.cpuCoreCount = Objects.requireNonNull($.cpuCoreCount, "expected parameter 'cpuCoreCount' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.exadataInfrastructureId = Objects.requireNonNull($.exadataInfrastructureId, "expected parameter 'exadataInfrastructureId' to be non-null");
            $.giVersion = Objects.requireNonNull($.giVersion, "expected parameter 'giVersion' to be non-null");
            $.sshPublicKeys = Objects.requireNonNull($.sshPublicKeys, "expected parameter 'sshPublicKeys' to be non-null");
            $.vmClusterNetworkId = Objects.requireNonNull($.vmClusterNetworkId, "expected parameter 'vmClusterNetworkId' to be non-null");
            return $;
        }
    }

}
