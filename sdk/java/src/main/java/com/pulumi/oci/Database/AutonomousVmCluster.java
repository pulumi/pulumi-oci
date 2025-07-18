// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.AutonomousVmClusterArgs;
import com.pulumi.oci.Database.inputs.AutonomousVmClusterState;
import com.pulumi.oci.Database.outputs.AutonomousVmClusterMaintenanceWindow;
import com.pulumi.oci.Database.outputs.AutonomousVmClusterMaintenanceWindowDetail;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Autonomous Vm Cluster resource in Oracle Cloud Infrastructure Database service.
 * 
 * Creates an Autonomous VM cluster for Exadata Cloud{@literal @}Customer. To create an Autonomous VM Cluster in the Oracle cloud, see [CreateCloudAutonomousVmCluster](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudAutonomousVmCluster/CreateCloudAutonomousVmCluster).
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Database.AutonomousVmCluster;
 * import com.pulumi.oci.Database.AutonomousVmClusterArgs;
 * import com.pulumi.oci.Database.inputs.AutonomousVmClusterMaintenanceWindowDetailArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testAutonomousVmCluster = new AutonomousVmCluster("testAutonomousVmCluster", AutonomousVmClusterArgs.builder()
 *             .compartmentId(compartmentId)
 *             .displayName(autonomousVmClusterDisplayName)
 *             .exadataInfrastructureId(testExadataInfrastructure.id())
 *             .vmClusterNetworkId(testVmClusterNetwork.id())
 *             .autonomousDataStorageSizeInTbs(autonomousVmClusterAutonomousDataStorageSizeInTbs)
 *             .computeModel(autonomousVmClusterComputeModel)
 *             .cpuCoreCountPerNode(autonomousVmClusterCpuCoreCountPerNode)
 *             .dbServers(autonomousVmClusterDbServers)
 *             .definedTags(autonomousVmClusterDefinedTags)
 *             .freeformTags(Map.of("Department", "Finance"))
 *             .isLocalBackupEnabled(autonomousVmClusterIsLocalBackupEnabled)
 *             .isMtlsEnabled(autonomousVmClusterIsMtlsEnabled)
 *             .licenseModel(autonomousVmClusterLicenseModel)
 *             .maintenanceWindowDetails(AutonomousVmClusterMaintenanceWindowDetailArgs.builder()
 *                 .daysOfWeeks(AutonomousVmClusterMaintenanceWindowDetailDaysOfWeekArgs.builder()
 *                     .name(autonomousVmClusterMaintenanceWindowDetailsDaysOfWeekName)
 *                     .build())
 *                 .hoursOfDays(autonomousVmClusterMaintenanceWindowDetailsHoursOfDay)
 *                 .leadTimeInWeeks(autonomousVmClusterMaintenanceWindowDetailsLeadTimeInWeeks)
 *                 .months(AutonomousVmClusterMaintenanceWindowDetailMonthArgs.builder()
 *                     .name(autonomousVmClusterMaintenanceWindowDetailsMonthsName)
 *                     .build())
 *                 .patchingMode(autonomousVmClusterMaintenanceWindowDetailsPatchingMode)
 *                 .preference(autonomousVmClusterMaintenanceWindowDetailsPreference)
 *                 .weeksOfMonths(autonomousVmClusterMaintenanceWindowDetailsWeeksOfMonth)
 *                 .build())
 *             .memoryPerOracleComputeUnitInGbs(autonomousVmClusterMemoryPerOracleComputeUnitInGbs)
 *             .scanListenerPortNonTls(autonomousVmClusterScanListenerPortNonTls)
 *             .scanListenerPortTls(autonomousVmClusterScanListenerPortTls)
 *             .timeZone(autonomousVmClusterTimeZone)
 *             .totalContainerDatabases(autonomousVmClusterTotalContainerDatabases)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * AutonomousVmClusters can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Database/autonomousVmCluster:AutonomousVmCluster test_autonomous_vm_cluster &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Database/autonomousVmCluster:AutonomousVmCluster")
public class AutonomousVmCluster extends com.pulumi.resources.CustomResource {
    @Export(name="autonomousDataStoragePercentage", refs={Double.class}, tree="[0]")
    private Output<Double> autonomousDataStoragePercentage;

    public Output<Double> autonomousDataStoragePercentage() {
        return this.autonomousDataStoragePercentage;
    }
    /**
     * (Updatable) The data disk group size to be allocated for Autonomous Databases, in TBs.
     * 
     */
    @Export(name="autonomousDataStorageSizeInTbs", refs={Double.class}, tree="[0]")
    private Output<Double> autonomousDataStorageSizeInTbs;

    /**
     * @return (Updatable) The data disk group size to be allocated for Autonomous Databases, in TBs.
     * 
     */
    public Output<Double> autonomousDataStorageSizeInTbs() {
        return this.autonomousDataStorageSizeInTbs;
    }
    /**
     * The data disk group size available for Autonomous Databases, in TBs.
     * 
     */
    @Export(name="availableAutonomousDataStorageSizeInTbs", refs={Double.class}, tree="[0]")
    private Output<Double> availableAutonomousDataStorageSizeInTbs;

    /**
     * @return The data disk group size available for Autonomous Databases, in TBs.
     * 
     */
    public Output<Double> availableAutonomousDataStorageSizeInTbs() {
        return this.availableAutonomousDataStorageSizeInTbs;
    }
    /**
     * The number of Autonomous Container Databases that can be created with the currently available local storage.
     * 
     */
    @Export(name="availableContainerDatabases", refs={Integer.class}, tree="[0]")
    private Output<Integer> availableContainerDatabases;

    /**
     * @return The number of Autonomous Container Databases that can be created with the currently available local storage.
     * 
     */
    public Output<Integer> availableContainerDatabases() {
        return this.availableContainerDatabases;
    }
    /**
     * The numnber of CPU cores available.
     * 
     */
    @Export(name="availableCpus", refs={Integer.class}, tree="[0]")
    private Output<Integer> availableCpus;

    /**
     * @return The numnber of CPU cores available.
     * 
     */
    public Output<Integer> availableCpus() {
        return this.availableCpus;
    }
    /**
     * **Deprecated.** Use `availableAutonomousDataStorageSizeInTBs` for Autonomous Databases&#39; data storage availability in TBs.
     * 
     */
    @Export(name="availableDataStorageSizeInTbs", refs={Double.class}, tree="[0]")
    private Output<Double> availableDataStorageSizeInTbs;

    /**
     * @return **Deprecated.** Use `availableAutonomousDataStorageSizeInTBs` for Autonomous Databases&#39; data storage availability in TBs.
     * 
     */
    public Output<Double> availableDataStorageSizeInTbs() {
        return this.availableDataStorageSizeInTbs;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The compute model of the Autonomous VM Cluster. ECPU compute model is the recommended model and OCPU compute model is legacy.
     * 
     */
    @Export(name="computeModel", refs={String.class}, tree="[0]")
    private Output<String> computeModel;

    /**
     * @return The compute model of the Autonomous VM Cluster. ECPU compute model is the recommended model and OCPU compute model is legacy.
     * 
     */
    public Output<String> computeModel() {
        return this.computeModel;
    }
    /**
     * (Updatable) The number of CPU cores to enable per VM cluster node.
     * 
     */
    @Export(name="cpuCoreCountPerNode", refs={Integer.class}, tree="[0]")
    private Output<Integer> cpuCoreCountPerNode;

    /**
     * @return (Updatable) The number of CPU cores to enable per VM cluster node.
     * 
     */
    public Output<Integer> cpuCoreCountPerNode() {
        return this.cpuCoreCountPerNode;
    }
    @Export(name="cpuPercentage", refs={Double.class}, tree="[0]")
    private Output<Double> cpuPercentage;

    public Output<Double> cpuPercentage() {
        return this.cpuPercentage;
    }
    /**
     * The number of enabled CPU cores.
     * 
     */
    @Export(name="cpusEnabled", refs={Integer.class}, tree="[0]")
    private Output<Integer> cpusEnabled;

    /**
     * @return The number of enabled CPU cores.
     * 
     */
    public Output<Integer> cpusEnabled() {
        return this.cpusEnabled;
    }
    @Export(name="cpusLowestScaledValue", refs={Integer.class}, tree="[0]")
    private Output<Integer> cpusLowestScaledValue;

    public Output<Integer> cpusLowestScaledValue() {
        return this.cpusLowestScaledValue;
    }
    @Export(name="dataStorageSizeInGb", refs={Double.class}, tree="[0]")
    private Output<Double> dataStorageSizeInGb;

    public Output<Double> dataStorageSizeInGb() {
        return this.dataStorageSizeInGb;
    }
    /**
     * The total data storage allocated in TBs
     * 
     */
    @Export(name="dataStorageSizeInTbs", refs={Double.class}, tree="[0]")
    private Output<Double> dataStorageSizeInTbs;

    /**
     * @return The total data storage allocated in TBs
     * 
     */
    public Output<Double> dataStorageSizeInTbs() {
        return this.dataStorageSizeInTbs;
    }
    /**
     * The local node storage allocated in GBs.
     * 
     */
    @Export(name="dbNodeStorageSizeInGbs", refs={Integer.class}, tree="[0]")
    private Output<Integer> dbNodeStorageSizeInGbs;

    /**
     * @return The local node storage allocated in GBs.
     * 
     */
    public Output<Integer> dbNodeStorageSizeInGbs() {
        return this.dbNodeStorageSizeInGbs;
    }
    /**
     * The list of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Db servers.
     * 
     */
    @Export(name="dbServers", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> dbServers;

    /**
     * @return The list of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Db servers.
     * 
     */
    public Output<List<String>> dbServers() {
        return this.dbServers;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    @Export(name="exadataInfrastructureId", refs={String.class}, tree="[0]")
    private Output<String> exadataInfrastructureId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    public Output<String> exadataInfrastructureId() {
        return this.exadataInfrastructureId;
    }
    /**
     * The lowest value to which exadataStorage(in TBs) can be scaled down.
     * 
     */
    @Export(name="exadataStorageInTbsLowestScaledValue", refs={Double.class}, tree="[0]")
    private Output<Double> exadataStorageInTbsLowestScaledValue;

    /**
     * @return The lowest value to which exadataStorage(in TBs) can be scaled down.
     * 
     */
    public Output<Double> exadataStorageInTbsLowestScaledValue() {
        return this.exadataStorageInTbsLowestScaledValue;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * If true, database backup on local Exadata storage is configured for the Autonomous VM cluster. If false, database backup on local Exadata storage is not available in the Autonomous VM cluster.
     * 
     */
    @Export(name="isLocalBackupEnabled", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isLocalBackupEnabled;

    /**
     * @return If true, database backup on local Exadata storage is configured for the Autonomous VM cluster. If false, database backup on local Exadata storage is not available in the Autonomous VM cluster.
     * 
     */
    public Output<Boolean> isLocalBackupEnabled() {
        return this.isLocalBackupEnabled;
    }
    /**
     * Enable mutual TLS(mTLS) authentication for database while provisioning a VMCluster. Default is TLS.
     * 
     */
    @Export(name="isMtlsEnabled", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isMtlsEnabled;

    /**
     * @return Enable mutual TLS(mTLS) authentication for database while provisioning a VMCluster. Default is TLS.
     * 
     */
    public Output<Boolean> isMtlsEnabled() {
        return this.isMtlsEnabled;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     * 
     */
    @Export(name="lastMaintenanceRunId", refs={String.class}, tree="[0]")
    private Output<String> lastMaintenanceRunId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     * 
     */
    public Output<String> lastMaintenanceRunId() {
        return this.lastMaintenanceRunId;
    }
    /**
     * (Updatable) The Oracle license model that applies to the Autonomous VM cluster. The default is BRING_YOUR_OWN_LICENSE.
     * 
     */
    @Export(name="licenseModel", refs={String.class}, tree="[0]")
    private Output<String> licenseModel;

    /**
     * @return (Updatable) The Oracle license model that applies to the Autonomous VM cluster. The default is BRING_YOUR_OWN_LICENSE.
     * 
     */
    public Output<String> licenseModel() {
        return this.licenseModel;
    }
    /**
     * Additional information about the current lifecycle state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     * 
     */
    @Export(name="maintenanceWindowDetails", refs={List.class,AutonomousVmClusterMaintenanceWindowDetail.class}, tree="[0,1]")
    private Output<List<AutonomousVmClusterMaintenanceWindowDetail>> maintenanceWindowDetails;

    /**
     * @return (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     * 
     */
    public Output<List<AutonomousVmClusterMaintenanceWindowDetail>> maintenanceWindowDetails() {
        return this.maintenanceWindowDetails;
    }
    /**
     * The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     * 
     */
    @Export(name="maintenanceWindows", refs={List.class,AutonomousVmClusterMaintenanceWindow.class}, tree="[0,1]")
    private Output<List<AutonomousVmClusterMaintenanceWindow>> maintenanceWindows;

    /**
     * @return The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     * 
     */
    public Output<List<AutonomousVmClusterMaintenanceWindow>> maintenanceWindows() {
        return this.maintenanceWindows;
    }
    /**
     * The lowest value to which maximum number of ACDs can be scaled down.
     * 
     */
    @Export(name="maxAcdsLowestScaledValue", refs={Integer.class}, tree="[0]")
    private Output<Integer> maxAcdsLowestScaledValue;

    /**
     * @return The lowest value to which maximum number of ACDs can be scaled down.
     * 
     */
    public Output<Integer> maxAcdsLowestScaledValue() {
        return this.maxAcdsLowestScaledValue;
    }
    /**
     * The amount of memory (in GBs) to be enabled per OCPU or ECPU.
     * 
     */
    @Export(name="memoryPerOracleComputeUnitInGbs", refs={Integer.class}, tree="[0]")
    private Output<Integer> memoryPerOracleComputeUnitInGbs;

    /**
     * @return The amount of memory (in GBs) to be enabled per OCPU or ECPU.
     * 
     */
    public Output<Integer> memoryPerOracleComputeUnitInGbs() {
        return this.memoryPerOracleComputeUnitInGbs;
    }
    /**
     * The memory allocated in GBs.
     * 
     */
    @Export(name="memorySizeInGbs", refs={Integer.class}, tree="[0]")
    private Output<Integer> memorySizeInGbs;

    /**
     * @return The memory allocated in GBs.
     * 
     */
    public Output<Integer> memorySizeInGbs() {
        return this.memorySizeInGbs;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     * 
     */
    @Export(name="nextMaintenanceRunId", refs={String.class}, tree="[0]")
    private Output<String> nextMaintenanceRunId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     * 
     */
    public Output<String> nextMaintenanceRunId() {
        return this.nextMaintenanceRunId;
    }
    /**
     * The number of nodes in the Autonomous VM Cluster.
     * 
     */
    @Export(name="nodeCount", refs={Integer.class}, tree="[0]")
    private Output<Integer> nodeCount;

    /**
     * @return The number of nodes in the Autonomous VM Cluster.
     * 
     */
    public Output<Integer> nodeCount() {
        return this.nodeCount;
    }
    @Export(name="nonProvisionableAutonomousContainerDatabases", refs={Integer.class}, tree="[0]")
    private Output<Integer> nonProvisionableAutonomousContainerDatabases;

    public Output<Integer> nonProvisionableAutonomousContainerDatabases() {
        return this.nonProvisionableAutonomousContainerDatabases;
    }
    /**
     * The number of enabled OCPU cores.
     * 
     */
    @Export(name="ocpusEnabled", refs={Double.class}, tree="[0]")
    private Output<Double> ocpusEnabled;

    /**
     * @return The number of enabled OCPU cores.
     * 
     */
    public Output<Double> ocpusEnabled() {
        return this.ocpusEnabled;
    }
    /**
     * **Deprecated.** Use field totalContainerDatabases.
     * 
     */
    @Export(name="provisionableAutonomousContainerDatabases", refs={Integer.class}, tree="[0]")
    private Output<Integer> provisionableAutonomousContainerDatabases;

    /**
     * @return **Deprecated.** Use field totalContainerDatabases.
     * 
     */
    public Output<Integer> provisionableAutonomousContainerDatabases() {
        return this.provisionableAutonomousContainerDatabases;
    }
    /**
     * The number of provisioned Autonomous Container Databases in an Autonomous VM Cluster.
     * 
     */
    @Export(name="provisionedAutonomousContainerDatabases", refs={Integer.class}, tree="[0]")
    private Output<Integer> provisionedAutonomousContainerDatabases;

    /**
     * @return The number of provisioned Autonomous Container Databases in an Autonomous VM Cluster.
     * 
     */
    public Output<Integer> provisionedAutonomousContainerDatabases() {
        return this.provisionedAutonomousContainerDatabases;
    }
    /**
     * The number of CPUs provisioned in an Autonomous VM Cluster.
     * 
     */
    @Export(name="provisionedCpus", refs={Double.class}, tree="[0]")
    private Output<Double> provisionedCpus;

    /**
     * @return The number of CPUs provisioned in an Autonomous VM Cluster.
     * 
     */
    public Output<Double> provisionedCpus() {
        return this.provisionedCpus;
    }
    /**
     * For Autonomous Databases on Dedicated Exadata Infrastructure:
     * * These are the CPUs that continue to be included in the count of CPUs available to the Autonomous Container Database even after one of its Autonomous Database is terminated or scaled down. You can release them to the available CPUs at its parent Autonomous VM Cluster level by restarting the Autonomous Container Database.
     * * The CPU type (OCPUs or ECPUs) is determined by the parent Autonomous Exadata VM Cluster&#39;s compute model.
     * 
     */
    @Export(name="reclaimableCpus", refs={Integer.class}, tree="[0]")
    private Output<Integer> reclaimableCpus;

    /**
     * @return For Autonomous Databases on Dedicated Exadata Infrastructure:
     * * These are the CPUs that continue to be included in the count of CPUs available to the Autonomous Container Database even after one of its Autonomous Database is terminated or scaled down. You can release them to the available CPUs at its parent Autonomous VM Cluster level by restarting the Autonomous Container Database.
     * * The CPU type (OCPUs or ECPUs) is determined by the parent Autonomous Exadata VM Cluster&#39;s compute model.
     * 
     */
    public Output<Integer> reclaimableCpus() {
        return this.reclaimableCpus;
    }
    /**
     * The number of CPUs reserved in an Autonomous VM Cluster.
     * 
     */
    @Export(name="reservedCpus", refs={Double.class}, tree="[0]")
    private Output<Double> reservedCpus;

    /**
     * @return The number of CPUs reserved in an Autonomous VM Cluster.
     * 
     */
    public Output<Double> reservedCpus() {
        return this.reservedCpus;
    }
    /**
     * The SCAN Listener Non TLS port number. Default value is 1521.
     * 
     */
    @Export(name="scanListenerPortNonTls", refs={Integer.class}, tree="[0]")
    private Output<Integer> scanListenerPortNonTls;

    /**
     * @return The SCAN Listener Non TLS port number. Default value is 1521.
     * 
     */
    public Output<Integer> scanListenerPortNonTls() {
        return this.scanListenerPortNonTls;
    }
    /**
     * The SCAN Listener TLS port number. Default value is 2484.
     * 
     */
    @Export(name="scanListenerPortTls", refs={Integer.class}, tree="[0]")
    private Output<Integer> scanListenerPortTls;

    /**
     * @return The SCAN Listener TLS port number. Default value is 2484.
     * 
     */
    public Output<Integer> scanListenerPortTls() {
        return this.scanListenerPortTls;
    }
    /**
     * The current state of the Autonomous VM cluster.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the Autonomous VM cluster.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time that the Autonomous VM cluster was created.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time that the Autonomous VM cluster was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time of Database SSL certificate expiration.
     * 
     */
    @Export(name="timeDatabaseSslCertificateExpires", refs={String.class}, tree="[0]")
    private Output<String> timeDatabaseSslCertificateExpires;

    /**
     * @return The date and time of Database SSL certificate expiration.
     * 
     */
    public Output<String> timeDatabaseSslCertificateExpires() {
        return this.timeDatabaseSslCertificateExpires;
    }
    /**
     * The date and time of ORDS certificate expiration.
     * 
     */
    @Export(name="timeOrdsCertificateExpires", refs={String.class}, tree="[0]")
    private Output<String> timeOrdsCertificateExpires;

    /**
     * @return The date and time of ORDS certificate expiration.
     * 
     */
    public Output<String> timeOrdsCertificateExpires() {
        return this.timeOrdsCertificateExpires;
    }
    /**
     * The time zone to use for the Autonomous VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     * 
     */
    @Export(name="timeZone", refs={String.class}, tree="[0]")
    private Output<String> timeZone;

    /**
     * @return The time zone to use for the Autonomous VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     * 
     */
    public Output<String> timeZone() {
        return this.timeZone;
    }
    @Export(name="totalAutonomousDataStorageInTbs", refs={Double.class}, tree="[0]")
    private Output<Double> totalAutonomousDataStorageInTbs;

    public Output<Double> totalAutonomousDataStorageInTbs() {
        return this.totalAutonomousDataStorageInTbs;
    }
    /**
     * (Updatable) The total number of Autonomous Container Databases that can be created.
     * 
     */
    @Export(name="totalContainerDatabases", refs={Integer.class}, tree="[0]")
    private Output<Integer> totalContainerDatabases;

    /**
     * @return (Updatable) The total number of Autonomous Container Databases that can be created.
     * 
     */
    public Output<Integer> totalContainerDatabases() {
        return this.totalContainerDatabases;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="vmClusterNetworkId", refs={String.class}, tree="[0]")
    private Output<String> vmClusterNetworkId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> vmClusterNetworkId() {
        return this.vmClusterNetworkId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public AutonomousVmCluster(java.lang.String name) {
        this(name, AutonomousVmClusterArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public AutonomousVmCluster(java.lang.String name, AutonomousVmClusterArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public AutonomousVmCluster(java.lang.String name, AutonomousVmClusterArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/autonomousVmCluster:AutonomousVmCluster", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private AutonomousVmCluster(java.lang.String name, Output<java.lang.String> id, @Nullable AutonomousVmClusterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/autonomousVmCluster:AutonomousVmCluster", name, state, makeResourceOptions(options, id), false);
    }

    private static AutonomousVmClusterArgs makeArgs(AutonomousVmClusterArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? AutonomousVmClusterArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static AutonomousVmCluster get(java.lang.String name, Output<java.lang.String> id, @Nullable AutonomousVmClusterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new AutonomousVmCluster(name, id, state, options);
    }
}
