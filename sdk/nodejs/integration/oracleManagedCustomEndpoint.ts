// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

export class OracleManagedCustomEndpoint extends pulumi.CustomResource {
    /**
     * Get an existing OracleManagedCustomEndpoint resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: OracleManagedCustomEndpointState, opts?: pulumi.CustomResourceOptions): OracleManagedCustomEndpoint {
        return new OracleManagedCustomEndpoint(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Integration/oracleManagedCustomEndpoint:OracleManagedCustomEndpoint';

    /**
     * Returns true if the given object is an instance of OracleManagedCustomEndpoint.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is OracleManagedCustomEndpoint {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === OracleManagedCustomEndpoint.__pulumiType;
    }

    public readonly dnsType!: pulumi.Output<string>;
    public readonly dnsZoneName!: pulumi.Output<string | undefined>;
    public readonly hostname!: pulumi.Output<string>;
    public readonly integrationInstanceId!: pulumi.Output<string>;
    public readonly managedType!: pulumi.Output<string>;
    public readonly state!: pulumi.Output<string>;

    /**
     * Create a OracleManagedCustomEndpoint resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: OracleManagedCustomEndpointArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: OracleManagedCustomEndpointArgs | OracleManagedCustomEndpointState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as OracleManagedCustomEndpointState | undefined;
            resourceInputs["dnsType"] = state ? state.dnsType : undefined;
            resourceInputs["dnsZoneName"] = state ? state.dnsZoneName : undefined;
            resourceInputs["hostname"] = state ? state.hostname : undefined;
            resourceInputs["integrationInstanceId"] = state ? state.integrationInstanceId : undefined;
            resourceInputs["managedType"] = state ? state.managedType : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
        } else {
            const args = argsOrState as OracleManagedCustomEndpointArgs | undefined;
            if ((!args || args.hostname === undefined) && !opts.urn) {
                throw new Error("Missing required property 'hostname'");
            }
            if ((!args || args.integrationInstanceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'integrationInstanceId'");
            }
            resourceInputs["dnsType"] = args ? args.dnsType : undefined;
            resourceInputs["dnsZoneName"] = args ? args.dnsZoneName : undefined;
            resourceInputs["hostname"] = args ? args.hostname : undefined;
            resourceInputs["integrationInstanceId"] = args ? args.integrationInstanceId : undefined;
            resourceInputs["managedType"] = args ? args.managedType : undefined;
            resourceInputs["state"] = args ? args.state : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(OracleManagedCustomEndpoint.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering OracleManagedCustomEndpoint resources.
 */
export interface OracleManagedCustomEndpointState {
    dnsType?: pulumi.Input<string>;
    dnsZoneName?: pulumi.Input<string>;
    hostname?: pulumi.Input<string>;
    integrationInstanceId?: pulumi.Input<string>;
    managedType?: pulumi.Input<string>;
    state?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a OracleManagedCustomEndpoint resource.
 */
export interface OracleManagedCustomEndpointArgs {
    dnsType?: pulumi.Input<string>;
    dnsZoneName?: pulumi.Input<string>;
    hostname: pulumi.Input<string>;
    integrationInstanceId: pulumi.Input<string>;
    managedType?: pulumi.Input<string>;
    state?: pulumi.Input<string>;
}
