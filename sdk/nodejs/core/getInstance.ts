// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Instance resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets information about the specified instance.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInstance = oci.Core.getInstance({
 *     instanceId: oci_core_instance.test_instance.id,
 * });
 * ```
 */
export function getInstance(args: GetInstanceArgs, opts?: pulumi.InvokeOptions): Promise<GetInstanceResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getInstance:getInstance", {
        "instanceId": args.instanceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInstance.
 */
export interface GetInstanceArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
     */
    instanceId: string;
}

/**
 * A collection of values returned by getInstance.
 */
export interface GetInstanceResult {
    /**
     * Configuration options for the Oracle Cloud Agent software running on the instance.
     */
    readonly agentConfigs: outputs.Core.GetInstanceAgentConfig[];
    readonly async: boolean;
    /**
     * Options for defining the availabiity of a VM instance after a maintenance event that impacts the underlying hardware.
     */
    readonly availabilityConfigs: outputs.Core.GetInstanceAvailabilityConfig[];
    /**
     * The availability domain the instance is running in.  Example: `Uocm:PHX-AD-1`
     */
    readonly availabilityDomain: string;
    /**
     * The OCID of the attached boot volume. If the `sourceType` is `bootVolume`, this will be the same OCID as the `sourceId`.
     */
    readonly bootVolumeId: string;
    /**
     * The OCID of the compute capacity reservation this instance is launched under. When this field contains an empty string or is null, the instance is not currently in a capacity reservation. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     */
    readonly capacityReservationId: string;
    /**
     * The OCID of the compartment that contains the instance.
     */
    readonly compartmentId: string;
    readonly createVnicDetails: outputs.Core.GetInstanceCreateVnicDetail[];
    /**
     * The OCID of dedicated VM host.
     */
    readonly dedicatedVmHostId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     */
    readonly extendedMetadata: {[key: string]: any};
    /**
     * The name of the fault domain the instance is running in.
     */
    readonly faultDomain: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The hostname for the instance VNIC's primary private IP.
     *
     * @deprecated The 'hostname_label' field has been deprecated. Please use 'hostname_label under create_vnic_details' instead.
     */
    readonly hostnameLabel: string;
    /**
     * The OCID of the instance.
     */
    readonly id: string;
    /**
     * Deprecated. Use `sourceDetails` instead.
     *
     * @deprecated The 'image' field has been deprecated. Please use 'source_details' instead. If both fields are specified, then 'source_details' will be used.
     */
    readonly image: string;
    readonly instanceId: string;
    /**
     * Optional mutable instance options
     */
    readonly instanceOptions: outputs.Core.GetInstanceInstanceOption[];
    /**
     * When a bare metal or virtual machine instance boots, the iPXE firmware that runs on the instance is configured to run an iPXE script to continue the boot process.
     */
    readonly ipxeScript: string;
    /**
     * Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/LaunchInstanceDetails).
     */
    readonly isPvEncryptionInTransitEnabled: boolean;
    /**
     * Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
     */
    readonly launchMode: string;
    /**
     * Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
     */
    readonly launchOptions: outputs.Core.GetInstanceLaunchOption[];
    /**
     * Custom metadata that you provide.
     */
    readonly metadata: {[key: string]: any};
    /**
     * The platform configuration for the instance.
     */
    readonly platformConfigs: outputs.Core.GetInstancePlatformConfig[];
    /**
     * (Optional) Configuration options for preemptible instances.
     */
    readonly preemptibleInstanceConfigs: outputs.Core.GetInstancePreemptibleInstanceConfig[];
    /**
     * (Optional) Whether to preserve the boot volume that was used to launch the preemptible instance when the instance is terminated. Defaults to false if not specified.
     */
    readonly preserveBootVolume: boolean;
    /**
     * The private IP address of instance VNIC. To set the private IP address, use the `privateIp` argument in create_vnic_details.
     */
    readonly privateIp: string;
    /**
     * The public IP address of instance VNIC (if enabled).
     */
    readonly publicIp: string;
    /**
     * The region that contains the availability domain the instance is running in.
     */
    readonly region: string;
    /**
     * The shape of the instance. The shape determines the number of CPUs and the amount of memory allocated to the instance. You can enumerate all available shapes by calling [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Shape/ListShapes).
     */
    readonly shape: string;
    /**
     * The shape configuration for an instance. The shape configuration determines the resources allocated to an instance.
     */
    readonly shapeConfigs: outputs.Core.GetInstanceShapeConfig[];
    readonly sourceDetails: outputs.Core.GetInstanceSourceDetail[];
    /**
     * The current state of the instance.
     */
    readonly state: string;
    /**
     * @deprecated The 'subnet_id' field has been deprecated. Please use 'subnet_id under create_vnic_details' instead.
     */
    readonly subnetId: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The date and time the instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * The date and time the instance is expected to be stopped / started,  in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). After that time if instance hasn't been rebooted, Oracle will reboot the instance within 24 hours of the due time. Regardless of how the instance was stopped, the flag will be reset to empty as soon as instance reaches Stopped state. Example: `2018-05-25T21:10:29.600Z`
     */
    readonly timeMaintenanceRebootDue: string;
}

export function getInstanceOutput(args: GetInstanceOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetInstanceResult> {
    return pulumi.output(args).apply(a => getInstance(a, opts))
}

/**
 * A collection of arguments for invoking getInstance.
 */
export interface GetInstanceOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
     */
    instanceId: pulumi.Input<string>;
}
