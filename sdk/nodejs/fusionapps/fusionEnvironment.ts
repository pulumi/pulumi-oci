// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Fusion Environment resource in Oracle Cloud Infrastructure Fusion Apps service.
 *
 * Creates a new FusionEnvironment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFusionEnvironment = new oci.fusionapps.FusionEnvironment("testFusionEnvironment", {
 *     compartmentId: _var.compartment_id,
 *     createFusionEnvironmentAdminUserDetails: {
 *         emailAddress: _var.fusion_environment_create_fusion_environment_admin_user_details_email_address,
 *         firstName: _var.fusion_environment_create_fusion_environment_admin_user_details_first_name,
 *         lastName: _var.fusion_environment_create_fusion_environment_admin_user_details_last_name,
 *         password: _var.fusion_environment_create_fusion_environment_admin_user_details_password,
 *         username: _var.fusion_environment_create_fusion_environment_admin_user_details_username,
 *     },
 *     displayName: _var.fusion_environment_display_name,
 *     fusionEnvironmentFamilyId: oci_fusion_apps_fusion_environment_family.test_fusion_environment_family.id,
 *     fusionEnvironmentType: _var.fusion_environment_fusion_environment_type,
 *     additionalLanguagePacks: _var.fusion_environment_additional_language_packs,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     dnsPrefix: _var.fusion_environment_dns_prefix,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     kmsKeyId: oci_kms_key.test_key.id,
 *     maintenancePolicy: {
 *         environmentMaintenanceOverride: _var.fusion_environment_maintenance_policy_environment_maintenance_override,
 *         monthlyPatchingOverride: _var.fusion_environment_maintenance_policy_monthly_patching_override,
 *     },
 *     rules: [{
 *         action: _var.fusion_environment_rules_action,
 *         conditions: [{
 *             attributeName: _var.fusion_environment_rules_conditions_attribute_name,
 *             attributeValue: _var.fusion_environment_rules_conditions_attribute_value,
 *         }],
 *         description: _var.fusion_environment_rules_description,
 *     }],
 * });
 * ```
 *
 * ## Import
 *
 * FusionEnvironments can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:FusionApps/fusionEnvironment:FusionEnvironment test_fusion_environment "id"
 * ```
 */
export class FusionEnvironment extends pulumi.CustomResource {
    /**
     * Get an existing FusionEnvironment resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: FusionEnvironmentState, opts?: pulumi.CustomResourceOptions): FusionEnvironment {
        return new FusionEnvironment(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:FusionApps/fusionEnvironment:FusionEnvironment';

    /**
     * Returns true if the given object is an instance of FusionEnvironment.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is FusionEnvironment {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === FusionEnvironment.__pulumiType;
    }

    /**
     * (Updatable) Language packs.
     */
    public readonly additionalLanguagePacks!: pulumi.Output<string[]>;
    /**
     * Patch bundle names
     */
    public /*out*/ readonly appliedPatchBundles!: pulumi.Output<string[]>;
    /**
     * (Updatable) The unique identifier (OCID) of the compartment where the Fusion Environment is located.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The credentials for the Fusion Applications service administrator.
     */
    public readonly createFusionEnvironmentAdminUserDetails!: pulumi.Output<outputs.FusionApps.FusionEnvironmentCreateFusionEnvironmentAdminUserDetails>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) FusionEnvironment Identifier can be renamed.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * DNS prefix.
     */
    public readonly dnsPrefix!: pulumi.Output<string>;
    /**
     * The IDCS domain created for the fusion instance
     */
    public /*out*/ readonly domainId!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The unique identifier (OCID) of the Fusion Environment Family that the Fusion Environment belongs to.
     */
    public readonly fusionEnvironmentFamilyId!: pulumi.Output<string>;
    /**
     * The type of environment. Valid values are Production, Test, or Development.
     */
    public readonly fusionEnvironmentType!: pulumi.Output<string>;
    /**
     * The IDCS Domain URL
     */
    public /*out*/ readonly idcsDomainUrl!: pulumi.Output<string>;
    /**
     * (Updatable) byok kms keyId
     */
    public readonly kmsKeyId!: pulumi.Output<string>;
    /**
     * BYOK key info
     */
    public /*out*/ readonly kmsKeyInfos!: pulumi.Output<string[]>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
     */
    public readonly maintenancePolicy!: pulumi.Output<outputs.FusionApps.FusionEnvironmentMaintenancePolicy>;
    /**
     * Public URL
     */
    public /*out*/ readonly publicUrl!: pulumi.Output<string>;
    /**
     * Describes a refresh of a fusion environment
     */
    public /*out*/ readonly refreshes!: pulumi.Output<outputs.FusionApps.FusionEnvironmentRefresh[]>;
    /**
     * (Updatable) Rules.
     */
    public readonly rules!: pulumi.Output<outputs.FusionApps.FusionEnvironmentRule[]>;
    /**
     * The current state of the ServiceInstance.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * List of subscription IDs.
     */
    public /*out*/ readonly subscriptionIds!: pulumi.Output<string[]>;
    /**
     * Environment Specific Guid/ System Name
     */
    public /*out*/ readonly systemName!: pulumi.Output<string>;
    /**
     * The time the the FusionEnvironment was created. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The next maintenance for this environment
     */
    public /*out*/ readonly timeUpcomingMaintenance!: pulumi.Output<string>;
    /**
     * The time the FusionEnvironment was updated. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * Version of Fusion Apps used by this environment
     */
    public /*out*/ readonly version!: pulumi.Output<string>;

    /**
     * Create a FusionEnvironment resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: FusionEnvironmentArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: FusionEnvironmentArgs | FusionEnvironmentState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as FusionEnvironmentState | undefined;
            resourceInputs["additionalLanguagePacks"] = state ? state.additionalLanguagePacks : undefined;
            resourceInputs["appliedPatchBundles"] = state ? state.appliedPatchBundles : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["createFusionEnvironmentAdminUserDetails"] = state ? state.createFusionEnvironmentAdminUserDetails : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["dnsPrefix"] = state ? state.dnsPrefix : undefined;
            resourceInputs["domainId"] = state ? state.domainId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["fusionEnvironmentFamilyId"] = state ? state.fusionEnvironmentFamilyId : undefined;
            resourceInputs["fusionEnvironmentType"] = state ? state.fusionEnvironmentType : undefined;
            resourceInputs["idcsDomainUrl"] = state ? state.idcsDomainUrl : undefined;
            resourceInputs["kmsKeyId"] = state ? state.kmsKeyId : undefined;
            resourceInputs["kmsKeyInfos"] = state ? state.kmsKeyInfos : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["maintenancePolicy"] = state ? state.maintenancePolicy : undefined;
            resourceInputs["publicUrl"] = state ? state.publicUrl : undefined;
            resourceInputs["refreshes"] = state ? state.refreshes : undefined;
            resourceInputs["rules"] = state ? state.rules : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subscriptionIds"] = state ? state.subscriptionIds : undefined;
            resourceInputs["systemName"] = state ? state.systemName : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpcomingMaintenance"] = state ? state.timeUpcomingMaintenance : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["version"] = state ? state.version : undefined;
        } else {
            const args = argsOrState as FusionEnvironmentArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.createFusionEnvironmentAdminUserDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'createFusionEnvironmentAdminUserDetails'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.fusionEnvironmentFamilyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'fusionEnvironmentFamilyId'");
            }
            if ((!args || args.fusionEnvironmentType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'fusionEnvironmentType'");
            }
            resourceInputs["additionalLanguagePacks"] = args ? args.additionalLanguagePacks : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["createFusionEnvironmentAdminUserDetails"] = args ? args.createFusionEnvironmentAdminUserDetails : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["dnsPrefix"] = args ? args.dnsPrefix : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["fusionEnvironmentFamilyId"] = args ? args.fusionEnvironmentFamilyId : undefined;
            resourceInputs["fusionEnvironmentType"] = args ? args.fusionEnvironmentType : undefined;
            resourceInputs["kmsKeyId"] = args ? args.kmsKeyId : undefined;
            resourceInputs["maintenancePolicy"] = args ? args.maintenancePolicy : undefined;
            resourceInputs["rules"] = args ? args.rules : undefined;
            resourceInputs["appliedPatchBundles"] = undefined /*out*/;
            resourceInputs["domainId"] = undefined /*out*/;
            resourceInputs["idcsDomainUrl"] = undefined /*out*/;
            resourceInputs["kmsKeyInfos"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["publicUrl"] = undefined /*out*/;
            resourceInputs["refreshes"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["subscriptionIds"] = undefined /*out*/;
            resourceInputs["systemName"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpcomingMaintenance"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["version"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(FusionEnvironment.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering FusionEnvironment resources.
 */
export interface FusionEnvironmentState {
    /**
     * (Updatable) Language packs.
     */
    additionalLanguagePacks?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Patch bundle names
     */
    appliedPatchBundles?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The unique identifier (OCID) of the compartment where the Fusion Environment is located.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The credentials for the Fusion Applications service administrator.
     */
    createFusionEnvironmentAdminUserDetails?: pulumi.Input<inputs.FusionApps.FusionEnvironmentCreateFusionEnvironmentAdminUserDetails>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) FusionEnvironment Identifier can be renamed.
     */
    displayName?: pulumi.Input<string>;
    /**
     * DNS prefix.
     */
    dnsPrefix?: pulumi.Input<string>;
    /**
     * The IDCS domain created for the fusion instance
     */
    domainId?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The unique identifier (OCID) of the Fusion Environment Family that the Fusion Environment belongs to.
     */
    fusionEnvironmentFamilyId?: pulumi.Input<string>;
    /**
     * The type of environment. Valid values are Production, Test, or Development.
     */
    fusionEnvironmentType?: pulumi.Input<string>;
    /**
     * The IDCS Domain URL
     */
    idcsDomainUrl?: pulumi.Input<string>;
    /**
     * (Updatable) byok kms keyId
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * BYOK key info
     */
    kmsKeyInfos?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
     */
    maintenancePolicy?: pulumi.Input<inputs.FusionApps.FusionEnvironmentMaintenancePolicy>;
    /**
     * Public URL
     */
    publicUrl?: pulumi.Input<string>;
    /**
     * Describes a refresh of a fusion environment
     */
    refreshes?: pulumi.Input<pulumi.Input<inputs.FusionApps.FusionEnvironmentRefresh>[]>;
    /**
     * (Updatable) Rules.
     */
    rules?: pulumi.Input<pulumi.Input<inputs.FusionApps.FusionEnvironmentRule>[]>;
    /**
     * The current state of the ServiceInstance.
     */
    state?: pulumi.Input<string>;
    /**
     * List of subscription IDs.
     */
    subscriptionIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Environment Specific Guid/ System Name
     */
    systemName?: pulumi.Input<string>;
    /**
     * The time the the FusionEnvironment was created. An RFC3339 formatted datetime string
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The next maintenance for this environment
     */
    timeUpcomingMaintenance?: pulumi.Input<string>;
    /**
     * The time the FusionEnvironment was updated. An RFC3339 formatted datetime string
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * Version of Fusion Apps used by this environment
     */
    version?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a FusionEnvironment resource.
 */
export interface FusionEnvironmentArgs {
    /**
     * (Updatable) Language packs.
     */
    additionalLanguagePacks?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The unique identifier (OCID) of the compartment where the Fusion Environment is located.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The credentials for the Fusion Applications service administrator.
     */
    createFusionEnvironmentAdminUserDetails: pulumi.Input<inputs.FusionApps.FusionEnvironmentCreateFusionEnvironmentAdminUserDetails>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) FusionEnvironment Identifier can be renamed.
     */
    displayName: pulumi.Input<string>;
    /**
     * DNS prefix.
     */
    dnsPrefix?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The unique identifier (OCID) of the Fusion Environment Family that the Fusion Environment belongs to.
     */
    fusionEnvironmentFamilyId: pulumi.Input<string>;
    /**
     * The type of environment. Valid values are Production, Test, or Development.
     */
    fusionEnvironmentType: pulumi.Input<string>;
    /**
     * (Updatable) byok kms keyId
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
     */
    maintenancePolicy?: pulumi.Input<inputs.FusionApps.FusionEnvironmentMaintenancePolicy>;
    /**
     * (Updatable) Rules.
     */
    rules?: pulumi.Input<pulumi.Input<inputs.FusionApps.FusionEnvironmentRule>[]>;
}