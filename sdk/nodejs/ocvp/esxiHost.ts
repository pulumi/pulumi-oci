// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Esxi Host resource in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
 *
 * Adds another ESXi host to an existing SDDC. The attributes of the specified
 * `Sddc` determine the VMware software and other configuration settings used
 * by the ESXi host.
 *
 * Use the [WorkRequest](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/WorkRequest/) operations to track the
 * creation of the ESXi host.
 *
 * ## Import
 *
 * EsxiHosts can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Ocvp/esxiHost:EsxiHost test_esxi_host "id"
 * ```
 */
export class EsxiHost extends pulumi.CustomResource {
    /**
     * Get an existing EsxiHost resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: EsxiHostState, opts?: pulumi.CustomResourceOptions): EsxiHost {
        return new EsxiHost(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Ocvp/esxiHost:EsxiHost';

    /**
     * Returns true if the given object is an instance of EsxiHost.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is EsxiHost {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === EsxiHost.__pulumiType;
    }

    /**
     * Current billing cycle end date. If the value in `currentSku` and `nextSku` are different, the value specified in `nextSku` becomes the new `currentSKU` when the `contractEndDate` is reached. Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly billingContractEndDate!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the SDDC.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * The availability domain to create the ESXi host in. If keep empty, for AD-specific SDDC, new ESXi host will be created in the same availability domain; for multi-AD SDDC, new ESXi host will be auto assigned to the next availability domain following evenly distribution strategy.
     */
    public readonly computeAvailabilityDomain!: pulumi.Output<string>;
    /**
     * In terms of implementation, an ESXi host is a Compute instance that is configured with the chosen bundle of VMware software. The `computeInstanceId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of that Compute instance.
     */
    public /*out*/ readonly computeInstanceId!: pulumi.Output<string>;
    /**
     * The billing option currently used by the ESXi host. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
     */
    public readonly currentSku!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A descriptive name for the ESXi host. It's changeable. Esxi Host name requirements are 1-16 character length limit, Must start with a letter, Must be English letters, numbers, - only, No repeating hyphens, Must be unique within the SDDC.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ESXi host that is failed. This is an optional parameter. If this parameter is specified, a new ESXi host will be created to replace the failed one, and the `failedEsxiHostId` field will be udpated in the newly created Esxi host.
     */
    public readonly failedEsxiHostId!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The date and time when the new esxi host should start billing cycle. [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2021-07-25T21:10:29.600Z`
     */
    public /*out*/ readonly gracePeriodEndDate!: pulumi.Output<string>;
    /**
     * (Updatable) The billing option to switch to after the existing billing cycle ends. If `nextSku` is null or empty, `currentSku` continues to the next billing cycle. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
     */
    public readonly nextSku!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the esxi host that is newly created to replace the failed node.
     */
    public /*out*/ readonly replacementEsxiHostId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC to add the ESXi host to.
     */
    public readonly sddcId!: pulumi.Output<string>;
    /**
     * The current state of the ESXi host.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the ESXi host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the ESXi host was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a EsxiHost resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: EsxiHostArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: EsxiHostArgs | EsxiHostState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as EsxiHostState | undefined;
            resourceInputs["billingContractEndDate"] = state ? state.billingContractEndDate : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["computeAvailabilityDomain"] = state ? state.computeAvailabilityDomain : undefined;
            resourceInputs["computeInstanceId"] = state ? state.computeInstanceId : undefined;
            resourceInputs["currentSku"] = state ? state.currentSku : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["failedEsxiHostId"] = state ? state.failedEsxiHostId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["gracePeriodEndDate"] = state ? state.gracePeriodEndDate : undefined;
            resourceInputs["nextSku"] = state ? state.nextSku : undefined;
            resourceInputs["replacementEsxiHostId"] = state ? state.replacementEsxiHostId : undefined;
            resourceInputs["sddcId"] = state ? state.sddcId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as EsxiHostArgs | undefined;
            if ((!args || args.sddcId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'sddcId'");
            }
            resourceInputs["computeAvailabilityDomain"] = args ? args.computeAvailabilityDomain : undefined;
            resourceInputs["currentSku"] = args ? args.currentSku : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["failedEsxiHostId"] = args ? args.failedEsxiHostId : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["nextSku"] = args ? args.nextSku : undefined;
            resourceInputs["sddcId"] = args ? args.sddcId : undefined;
            resourceInputs["billingContractEndDate"] = undefined /*out*/;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["computeInstanceId"] = undefined /*out*/;
            resourceInputs["gracePeriodEndDate"] = undefined /*out*/;
            resourceInputs["replacementEsxiHostId"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(EsxiHost.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering EsxiHost resources.
 */
export interface EsxiHostState {
    /**
     * Current billing cycle end date. If the value in `currentSku` and `nextSku` are different, the value specified in `nextSku` becomes the new `currentSKU` when the `contractEndDate` is reached. Example: `2016-08-25T21:10:29.600Z`
     */
    billingContractEndDate?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the SDDC.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The availability domain to create the ESXi host in. If keep empty, for AD-specific SDDC, new ESXi host will be created in the same availability domain; for multi-AD SDDC, new ESXi host will be auto assigned to the next availability domain following evenly distribution strategy.
     */
    computeAvailabilityDomain?: pulumi.Input<string>;
    /**
     * In terms of implementation, an ESXi host is a Compute instance that is configured with the chosen bundle of VMware software. The `computeInstanceId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of that Compute instance.
     */
    computeInstanceId?: pulumi.Input<string>;
    /**
     * The billing option currently used by the ESXi host. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
     */
    currentSku?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A descriptive name for the ESXi host. It's changeable. Esxi Host name requirements are 1-16 character length limit, Must start with a letter, Must be English letters, numbers, - only, No repeating hyphens, Must be unique within the SDDC.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ESXi host that is failed. This is an optional parameter. If this parameter is specified, a new ESXi host will be created to replace the failed one, and the `failedEsxiHostId` field will be udpated in the newly created Esxi host.
     */
    failedEsxiHostId?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The date and time when the new esxi host should start billing cycle. [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2021-07-25T21:10:29.600Z`
     */
    gracePeriodEndDate?: pulumi.Input<string>;
    /**
     * (Updatable) The billing option to switch to after the existing billing cycle ends. If `nextSku` is null or empty, `currentSku` continues to the next billing cycle. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
     */
    nextSku?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the esxi host that is newly created to replace the failed node.
     */
    replacementEsxiHostId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC to add the ESXi host to.
     */
    sddcId?: pulumi.Input<string>;
    /**
     * The current state of the ESXi host.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the ESXi host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the ESXi host was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a EsxiHost resource.
 */
export interface EsxiHostArgs {
    /**
     * The availability domain to create the ESXi host in. If keep empty, for AD-specific SDDC, new ESXi host will be created in the same availability domain; for multi-AD SDDC, new ESXi host will be auto assigned to the next availability domain following evenly distribution strategy.
     */
    computeAvailabilityDomain?: pulumi.Input<string>;
    /**
     * The billing option currently used by the ESXi host. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
     */
    currentSku?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A descriptive name for the ESXi host. It's changeable. Esxi Host name requirements are 1-16 character length limit, Must start with a letter, Must be English letters, numbers, - only, No repeating hyphens, Must be unique within the SDDC.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ESXi host that is failed. This is an optional parameter. If this parameter is specified, a new ESXi host will be created to replace the failed one, and the `failedEsxiHostId` field will be udpated in the newly created Esxi host.
     */
    failedEsxiHostId?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The billing option to switch to after the existing billing cycle ends. If `nextSku` is null or empty, `currentSku` continues to the next billing cycle. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
     */
    nextSku?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC to add the ESXi host to.
     */
    sddcId: pulumi.Input<string>;
}
