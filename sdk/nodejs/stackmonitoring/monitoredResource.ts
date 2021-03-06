// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Monitored Resource resource in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * Creates a new monitored resource for the given resource type
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitoredResource = new oci.stackmonitoring.MonitoredResource("testMonitoredResource", {
 *     compartmentId: _var.compartment_id,
 *     type: _var.monitored_resource_type,
 *     aliases: {
 *         credential: {
 *             name: _var.monitored_resource_aliases_credential_name,
 *             service: _var.monitored_resource_aliases_credential_service,
 *             source: _var.monitored_resource_aliases_credential_source,
 *         },
 *         name: _var.monitored_resource_aliases_name,
 *         source: _var.monitored_resource_aliases_source,
 *     },
 *     credentials: {
 *         credentialType: _var.monitored_resource_credentials_credential_type,
 *         description: _var.monitored_resource_credentials_description,
 *         keyId: _var.monitored_resource_credentials_key_id,
 *         name: _var.monitored_resource_credentials_name,
 *         properties: [{
 *             name: _var.monitored_resource_credentials_properties_name,
 *             value: _var.monitored_resource_credentials_properties_value,
 *         }],
 *         source: _var.monitored_resource_credentials_source,
 *         type: _var.monitored_resource_credentials_type,
 *     },
 *     databaseConnectionDetails: {
 *         port: _var.monitored_resource_database_connection_details_port,
 *         protocol: _var.monitored_resource_database_connection_details_protocol,
 *         serviceName: _var.monitored_resource_database_service_name,
 *         connectorId: _var.monitored_resource_database_connector_id,
 *         dbId: _var.monitored_resource_database_id,
 *         dbUniqueName: _var.monitored_resource_database_connection_details_db_unique_name,
 *     },
 *     displayName: _var.monitored_resource_display_name,
 *     externalResourceId: _var.monitored_resource_external_resource_id,
 *     hostName: _var.monitored_resource_host_name,
 *     managementAgentId: oci_management_agent_management_agent.test_management_agent.id,
 *     properties: [{
 *         name: _var.monitored_resource_properties_name,
 *         value: _var.monitored_resource_properties_value,
 *     }],
 *     resourceTimeZone: _var.monitored_resource_resource_time_zone,
 * });
 * ```
 *
 * ## Import
 *
 * MonitoredResources can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:StackMonitoring/monitoredResource:MonitoredResource test_monitored_resource "id"
 * ```
 */
export class MonitoredResource extends pulumi.CustomResource {
    /**
     * Get an existing MonitoredResource resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MonitoredResourceState, opts?: pulumi.CustomResourceOptions): MonitoredResource {
        return new MonitoredResource(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:StackMonitoring/monitoredResource:MonitoredResource';

    /**
     * Returns true if the given object is an instance of MonitoredResource.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MonitoredResource {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MonitoredResource.__pulumiType;
    }

    /**
     * (Updatable) Monitored Resource Alias Credential Details
     */
    public readonly aliases!: pulumi.Output<outputs.StackMonitoring.MonitoredResourceAliases | undefined>;
    /**
     * (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Monitored Resource Credential Details
     */
    public readonly credentials!: pulumi.Output<outputs.StackMonitoring.MonitoredResourceCredentials | undefined>;
    /**
     * (Updatable) Connection details to connect to the database. HostName, protocol, and port should be specified.
     */
    public readonly databaseConnectionDetails!: pulumi.Output<outputs.StackMonitoring.MonitoredResourceDatabaseConnectionDetails | undefined>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public /*out*/ readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Monitored resource display name.
     */
    public readonly displayName!: pulumi.Output<string | undefined>;
    /**
     * Generally used by DBaaS to send the Database OCID stored on the DBaaS. The same will be passed to resource service to enable Stack Monitoring Service on DBM. This will be stored in Stack Monitoring Resource Service data store as identifier for monitored resource. If this header is not set as part of the request, then an id will be generated and stored for the resource.
     */
    public readonly externalResourceId!: pulumi.Output<string | undefined>;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public /*out*/ readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Host name of the monitored resource
     */
    public readonly hostName!: pulumi.Output<string | undefined>;
    /**
     * Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    public readonly managementAgentId!: pulumi.Output<string | undefined>;
    /**
     * (Updatable) property name
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * (Updatable) List of monitored resource properties
     */
    public readonly properties!: pulumi.Output<outputs.StackMonitoring.MonitoredResourceProperty[] | undefined>;
    /**
     * (Updatable) Time zone in the form of tz database canonical zone ID.
     */
    public readonly resourceTimeZone!: pulumi.Output<string | undefined>;
    /**
     * Lifecycle state of the monitored resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     */
    public /*out*/ readonly tenantId!: pulumi.Output<string>;
    /**
     * The time the the resource was created. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the the resource was updated. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * Monitored resource type
     */
    public readonly type!: pulumi.Output<string>;

    /**
     * Create a MonitoredResource resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MonitoredResourceArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MonitoredResourceArgs | MonitoredResourceState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MonitoredResourceState | undefined;
            resourceInputs["aliases"] = state ? state.aliases : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["credentials"] = state ? state.credentials : undefined;
            resourceInputs["databaseConnectionDetails"] = state ? state.databaseConnectionDetails : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["externalResourceId"] = state ? state.externalResourceId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["hostName"] = state ? state.hostName : undefined;
            resourceInputs["managementAgentId"] = state ? state.managementAgentId : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["properties"] = state ? state.properties : undefined;
            resourceInputs["resourceTimeZone"] = state ? state.resourceTimeZone : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["tenantId"] = state ? state.tenantId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
        } else {
            const args = argsOrState as MonitoredResourceArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.type === undefined) && !opts.urn) {
                throw new Error("Missing required property 'type'");
            }
            resourceInputs["aliases"] = args ? args.aliases : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["credentials"] = args ? args.credentials : undefined;
            resourceInputs["databaseConnectionDetails"] = args ? args.databaseConnectionDetails : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["externalResourceId"] = args ? args.externalResourceId : undefined;
            resourceInputs["hostName"] = args ? args.hostName : undefined;
            resourceInputs["managementAgentId"] = args ? args.managementAgentId : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["properties"] = args ? args.properties : undefined;
            resourceInputs["resourceTimeZone"] = args ? args.resourceTimeZone : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["definedTags"] = undefined /*out*/;
            resourceInputs["freeformTags"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["tenantId"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MonitoredResource.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MonitoredResource resources.
 */
export interface MonitoredResourceState {
    /**
     * (Updatable) Monitored Resource Alias Credential Details
     */
    aliases?: pulumi.Input<inputs.StackMonitoring.MonitoredResourceAliases>;
    /**
     * (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Monitored Resource Credential Details
     */
    credentials?: pulumi.Input<inputs.StackMonitoring.MonitoredResourceCredentials>;
    /**
     * (Updatable) Connection details to connect to the database. HostName, protocol, and port should be specified.
     */
    databaseConnectionDetails?: pulumi.Input<inputs.StackMonitoring.MonitoredResourceDatabaseConnectionDetails>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Monitored resource display name.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Generally used by DBaaS to send the Database OCID stored on the DBaaS. The same will be passed to resource service to enable Stack Monitoring Service on DBM. This will be stored in Stack Monitoring Resource Service data store as identifier for monitored resource. If this header is not set as part of the request, then an id will be generated and stored for the resource.
     */
    externalResourceId?: pulumi.Input<string>;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Host name of the monitored resource
     */
    hostName?: pulumi.Input<string>;
    /**
     * Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    managementAgentId?: pulumi.Input<string>;
    /**
     * (Updatable) property name
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) List of monitored resource properties
     */
    properties?: pulumi.Input<pulumi.Input<inputs.StackMonitoring.MonitoredResourceProperty>[]>;
    /**
     * (Updatable) Time zone in the form of tz database canonical zone ID.
     */
    resourceTimeZone?: pulumi.Input<string>;
    /**
     * Lifecycle state of the monitored resource.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     */
    tenantId?: pulumi.Input<string>;
    /**
     * The time the the resource was created. An RFC3339 formatted datetime string
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the the resource was updated. An RFC3339 formatted datetime string
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * Monitored resource type
     */
    type?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MonitoredResource resource.
 */
export interface MonitoredResourceArgs {
    /**
     * (Updatable) Monitored Resource Alias Credential Details
     */
    aliases?: pulumi.Input<inputs.StackMonitoring.MonitoredResourceAliases>;
    /**
     * (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Monitored Resource Credential Details
     */
    credentials?: pulumi.Input<inputs.StackMonitoring.MonitoredResourceCredentials>;
    /**
     * (Updatable) Connection details to connect to the database. HostName, protocol, and port should be specified.
     */
    databaseConnectionDetails?: pulumi.Input<inputs.StackMonitoring.MonitoredResourceDatabaseConnectionDetails>;
    /**
     * (Updatable) Monitored resource display name.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Generally used by DBaaS to send the Database OCID stored on the DBaaS. The same will be passed to resource service to enable Stack Monitoring Service on DBM. This will be stored in Stack Monitoring Resource Service data store as identifier for monitored resource. If this header is not set as part of the request, then an id will be generated and stored for the resource.
     */
    externalResourceId?: pulumi.Input<string>;
    /**
     * (Updatable) Host name of the monitored resource
     */
    hostName?: pulumi.Input<string>;
    /**
     * Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    managementAgentId?: pulumi.Input<string>;
    /**
     * (Updatable) property name
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) List of monitored resource properties
     */
    properties?: pulumi.Input<pulumi.Input<inputs.StackMonitoring.MonitoredResourceProperty>[]>;
    /**
     * (Updatable) Time zone in the form of tz database canonical zone ID.
     */
    resourceTimeZone?: pulumi.Input<string>;
    /**
     * Monitored resource type
     */
    type: pulumi.Input<string>;
}
