// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Cloud Autonomous Vm Cluster resource in Oracle Cloud Infrastructure Database service.
 *
 * Creates an Autonomous Exadata VM cluster in the Oracle cloud. For Exadata Cloud@Customer systems, see [CreateAutonomousVmCluster](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/AutonomousVmCluster/CreateAutonomousVmCluster).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCloudAutonomousVmCluster = new oci.database.CloudAutonomousVmCluster("testCloudAutonomousVmCluster", {
 *     cloudExadataInfrastructureId: oci_database_cloud_exadata_infrastructure.test_cloud_exadata_infrastructure.id,
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.cloud_autonomous_vm_cluster_display_name,
 *     subnetId: oci_core_subnet.test_subnet.id,
 *     definedTags: _var.cloud_autonomous_vm_cluster_defined_tags,
 *     description: _var.cloud_autonomous_vm_cluster_description,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     licenseModel: _var.cloud_autonomous_vm_cluster_license_model,
 *     nsgIds: _var.cloud_autonomous_vm_cluster_nsg_ids,
 * });
 * ```
 *
 * ## Import
 *
 * CloudAutonomousVmClusters can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Database/cloudAutonomousVmCluster:CloudAutonomousVmCluster test_cloud_autonomous_vm_cluster "id"
 * ```
 */
export class CloudAutonomousVmCluster extends pulumi.CustomResource {
    /**
     * Get an existing CloudAutonomousVmCluster resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: CloudAutonomousVmClusterState, opts?: pulumi.CustomResourceOptions): CloudAutonomousVmCluster {
        return new CloudAutonomousVmCluster(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/cloudAutonomousVmCluster:CloudAutonomousVmCluster';

    /**
     * Returns true if the given object is an instance of CloudAutonomousVmCluster.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is CloudAutonomousVmCluster {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === CloudAutonomousVmCluster.__pulumiType;
    }

    /**
     * The name of the availability domain that the cloud Autonomous VM cluster is located in.
     */
    public /*out*/ readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure.
     */
    public readonly cloudExadataInfrastructureId!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The number of CPU cores enabled on the cloud Autonomous VM cluster.
     */
    public /*out*/ readonly cpuCoreCount!: pulumi.Output<number>;
    /**
     * The total data storage allocated, in gigabytes (GB).
     */
    public /*out*/ readonly dataStorageSizeInGb!: pulumi.Output<number>;
    /**
     * The total data storage allocated, in terabytes (TB).
     */
    public /*out*/ readonly dataStorageSizeInTbs!: pulumi.Output<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) User defined description of the cloud Autonomous VM cluster.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The user-friendly name for the cloud Autonomous VM cluster. The name does not need to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The domain name for the cloud Autonomous VM cluster.
     */
    public /*out*/ readonly domain!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The hostname for the cloud Autonomous VM cluster.
     */
    public /*out*/ readonly hostname!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     */
    public /*out*/ readonly lastMaintenanceRunId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance update history. This value is updated when a maintenance update starts.
     */
    public /*out*/ readonly lastUpdateHistoryEntryId!: pulumi.Output<string>;
    /**
     * (Updatable) The Oracle license model that applies to the Oracle Autonomous Database. Bring your own license (BYOL) allows you to apply your current on-premises Oracle software licenses to equivalent, highly automated Oracle PaaS and IaaS services in the cloud. License Included allows you to subscribe to new Oracle Database software licenses and the Database service. Note that when provisioning an Autonomous Database on [dedicated Exadata infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html), this attribute must be null because the attribute is already set at the Autonomous Exadata Infrastructure level. When using [shared Exadata infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html), if a value is not specified, the system will supply the value of `BRING_YOUR_OWN_LICENSE`.
     */
    public readonly licenseModel!: pulumi.Output<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The memory allocated in GBs.
     */
    public /*out*/ readonly memorySizeInGbs!: pulumi.Output<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     */
    public /*out*/ readonly nextMaintenanceRunId!: pulumi.Output<string>;
    /**
     * The number of database servers in the cloud VM cluster.
     */
    public /*out*/ readonly nodeCount!: pulumi.Output<number>;
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
     * * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
     */
    public readonly nsgIds!: pulumi.Output<string[]>;
    /**
     * The number of CPU cores enabled on the cloud Autonomous VM cluster. Only 1 decimal place is allowed for the fractional part.
     */
    public /*out*/ readonly ocpuCount!: pulumi.Output<number>;
    public readonly rotateOrdsCertsTrigger!: pulumi.Output<boolean | undefined>;
    public readonly rotateSslCertsTrigger!: pulumi.Output<boolean | undefined>;
    /**
     * The model name of the Exadata hardware running the cloud Autonomous VM cluster.
     */
    public /*out*/ readonly shape!: pulumi.Output<string>;
    /**
     * The current state of the cloud Autonomous VM cluster.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the cloud Autonomous VM Cluster is associated with.
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * The date and time that the cloud Autonomous VM cluster was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The last date and time that the cloud Autonomous VM cluster was updated.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a CloudAutonomousVmCluster resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: CloudAutonomousVmClusterArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: CloudAutonomousVmClusterArgs | CloudAutonomousVmClusterState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as CloudAutonomousVmClusterState | undefined;
            resourceInputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            resourceInputs["cloudExadataInfrastructureId"] = state ? state.cloudExadataInfrastructureId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["cpuCoreCount"] = state ? state.cpuCoreCount : undefined;
            resourceInputs["dataStorageSizeInGb"] = state ? state.dataStorageSizeInGb : undefined;
            resourceInputs["dataStorageSizeInTbs"] = state ? state.dataStorageSizeInTbs : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["domain"] = state ? state.domain : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["hostname"] = state ? state.hostname : undefined;
            resourceInputs["lastMaintenanceRunId"] = state ? state.lastMaintenanceRunId : undefined;
            resourceInputs["lastUpdateHistoryEntryId"] = state ? state.lastUpdateHistoryEntryId : undefined;
            resourceInputs["licenseModel"] = state ? state.licenseModel : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["memorySizeInGbs"] = state ? state.memorySizeInGbs : undefined;
            resourceInputs["nextMaintenanceRunId"] = state ? state.nextMaintenanceRunId : undefined;
            resourceInputs["nodeCount"] = state ? state.nodeCount : undefined;
            resourceInputs["nsgIds"] = state ? state.nsgIds : undefined;
            resourceInputs["ocpuCount"] = state ? state.ocpuCount : undefined;
            resourceInputs["rotateOrdsCertsTrigger"] = state ? state.rotateOrdsCertsTrigger : undefined;
            resourceInputs["rotateSslCertsTrigger"] = state ? state.rotateSslCertsTrigger : undefined;
            resourceInputs["shape"] = state ? state.shape : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subnetId"] = state ? state.subnetId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as CloudAutonomousVmClusterArgs | undefined;
            if ((!args || args.cloudExadataInfrastructureId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'cloudExadataInfrastructureId'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            resourceInputs["cloudExadataInfrastructureId"] = args ? args.cloudExadataInfrastructureId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["licenseModel"] = args ? args.licenseModel : undefined;
            resourceInputs["nsgIds"] = args ? args.nsgIds : undefined;
            resourceInputs["rotateOrdsCertsTrigger"] = args ? args.rotateOrdsCertsTrigger : undefined;
            resourceInputs["rotateSslCertsTrigger"] = args ? args.rotateSslCertsTrigger : undefined;
            resourceInputs["subnetId"] = args ? args.subnetId : undefined;
            resourceInputs["availabilityDomain"] = undefined /*out*/;
            resourceInputs["cpuCoreCount"] = undefined /*out*/;
            resourceInputs["dataStorageSizeInGb"] = undefined /*out*/;
            resourceInputs["dataStorageSizeInTbs"] = undefined /*out*/;
            resourceInputs["domain"] = undefined /*out*/;
            resourceInputs["hostname"] = undefined /*out*/;
            resourceInputs["lastMaintenanceRunId"] = undefined /*out*/;
            resourceInputs["lastUpdateHistoryEntryId"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["memorySizeInGbs"] = undefined /*out*/;
            resourceInputs["nextMaintenanceRunId"] = undefined /*out*/;
            resourceInputs["nodeCount"] = undefined /*out*/;
            resourceInputs["ocpuCount"] = undefined /*out*/;
            resourceInputs["shape"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(CloudAutonomousVmCluster.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering CloudAutonomousVmCluster resources.
 */
export interface CloudAutonomousVmClusterState {
    /**
     * The name of the availability domain that the cloud Autonomous VM cluster is located in.
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure.
     */
    cloudExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The number of CPU cores enabled on the cloud Autonomous VM cluster.
     */
    cpuCoreCount?: pulumi.Input<number>;
    /**
     * The total data storage allocated, in gigabytes (GB).
     */
    dataStorageSizeInGb?: pulumi.Input<number>;
    /**
     * The total data storage allocated, in terabytes (TB).
     */
    dataStorageSizeInTbs?: pulumi.Input<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) User defined description of the cloud Autonomous VM cluster.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly name for the cloud Autonomous VM cluster. The name does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The domain name for the cloud Autonomous VM cluster.
     */
    domain?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The hostname for the cloud Autonomous VM cluster.
     */
    hostname?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     */
    lastMaintenanceRunId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance update history. This value is updated when a maintenance update starts.
     */
    lastUpdateHistoryEntryId?: pulumi.Input<string>;
    /**
     * (Updatable) The Oracle license model that applies to the Oracle Autonomous Database. Bring your own license (BYOL) allows you to apply your current on-premises Oracle software licenses to equivalent, highly automated Oracle PaaS and IaaS services in the cloud. License Included allows you to subscribe to new Oracle Database software licenses and the Database service. Note that when provisioning an Autonomous Database on [dedicated Exadata infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html), this attribute must be null because the attribute is already set at the Autonomous Exadata Infrastructure level. When using [shared Exadata infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html), if a value is not specified, the system will supply the value of `BRING_YOUR_OWN_LICENSE`.
     */
    licenseModel?: pulumi.Input<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The memory allocated in GBs.
     */
    memorySizeInGbs?: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     */
    nextMaintenanceRunId?: pulumi.Input<string>;
    /**
     * The number of database servers in the cloud VM cluster.
     */
    nodeCount?: pulumi.Input<number>;
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
     * * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The number of CPU cores enabled on the cloud Autonomous VM cluster. Only 1 decimal place is allowed for the fractional part.
     */
    ocpuCount?: pulumi.Input<number>;
    rotateOrdsCertsTrigger?: pulumi.Input<boolean>;
    rotateSslCertsTrigger?: pulumi.Input<boolean>;
    /**
     * The model name of the Exadata hardware running the cloud Autonomous VM cluster.
     */
    shape?: pulumi.Input<string>;
    /**
     * The current state of the cloud Autonomous VM cluster.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the cloud Autonomous VM Cluster is associated with.
     */
    subnetId?: pulumi.Input<string>;
    /**
     * The date and time that the cloud Autonomous VM cluster was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The last date and time that the cloud Autonomous VM cluster was updated.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a CloudAutonomousVmCluster resource.
 */
export interface CloudAutonomousVmClusterArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure.
     */
    cloudExadataInfrastructureId: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) User defined description of the cloud Autonomous VM cluster.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly name for the cloud Autonomous VM cluster. The name does not need to be unique.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The Oracle license model that applies to the Oracle Autonomous Database. Bring your own license (BYOL) allows you to apply your current on-premises Oracle software licenses to equivalent, highly automated Oracle PaaS and IaaS services in the cloud. License Included allows you to subscribe to new Oracle Database software licenses and the Database service. Note that when provisioning an Autonomous Database on [dedicated Exadata infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html), this attribute must be null because the attribute is already set at the Autonomous Exadata Infrastructure level. When using [shared Exadata infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html), if a value is not specified, the system will supply the value of `BRING_YOUR_OWN_LICENSE`.
     */
    licenseModel?: pulumi.Input<string>;
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
     * * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    rotateOrdsCertsTrigger?: pulumi.Input<boolean>;
    rotateSslCertsTrigger?: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the cloud Autonomous VM Cluster is associated with.
     */
    subnetId: pulumi.Input<string>;
}
