// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Database Registration resource in Oracle Cloud Infrastructure Golden Gate service.
 *
 * Retrieves a DatabaseRegistration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDatabaseRegistration = oci.GoldenGate.getDatabaseRegistration({
 *     databaseRegistrationId: oci_golden_gate_database_registration.test_database_registration.id,
 * });
 * ```
 */
export function getDatabaseRegistration(args: GetDatabaseRegistrationArgs, opts?: pulumi.InvokeOptions): Promise<GetDatabaseRegistrationResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:GoldenGate/getDatabaseRegistration:getDatabaseRegistration", {
        "databaseRegistrationId": args.databaseRegistrationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDatabaseRegistration.
 */
export interface GetDatabaseRegistrationArgs {
    /**
     * A unique DatabaseRegistration identifier.
     */
    databaseRegistrationId: string;
}

/**
 * A collection of values returned by getDatabaseRegistration.
 */
export interface GetDatabaseRegistrationResult {
    /**
     * Credential store alias.
     */
    readonly aliasName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
     */
    readonly compartmentId: string;
    /**
     * Connect descriptor or Easy Connect Naming method that Oracle GoldenGate uses to connect to a database.
     */
    readonly connectionString: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database being referenced.
     */
    readonly databaseId: string;
    readonly databaseRegistrationId: string;
    /**
     * Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Metadata about this specific object.
     */
    readonly description: string;
    /**
     * An object's Display Name.
     */
    readonly displayName: string;
    /**
     * A three-label Fully Qualified Domain Name (FQDN) for a resource.
     */
    readonly fqdn: string;
    /**
     * A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the databaseRegistration being referenced.
     */
    readonly id: string;
    /**
     * The private IP address in the customer's VCN of the customer's endpoint, typically a database.
     */
    readonly ipAddress: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the customer "Master" key being referenced. If provided, this will reference a key which the customer will be required to ensure the policies are established to permit the GoldenGate Service to utilize this key to manage secrets.
     */
    readonly keyId: string;
    /**
     * Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
     */
    readonly lifecycleDetails: string;
    readonly password: string;
    /**
     * A Private Endpoint IP Address created in the customer's subnet.  A customer database can expect network traffic initiated by GGS from this IP address and send network traffic to this IP address, typically in response to requests from GGS (OGG).  The customer may utilize this IP address in Security Lists or Network Security Groups (NSG) as needed.
     */
    readonly rcePrivateIp: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the the GGS Secret will be created. If provided, this will reference a key which the customer will be required to ensure the policies are established to permit the GoldenGate Service to utilize this Compartment in which to create a Secret.
     */
    readonly secretCompartmentId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the customer GGS Secret being referenced. If provided, this will reference a key which the customer will be required to ensure the policies are established to permit the GoldenGate Service to utilize this Secret
     */
    readonly secretId: string;
    /**
     * The mode of the database connection session to be established by the data client. REDIRECT - for a RAC database, DIRECT - for a non-RAC database. Connection to a RAC database involves a redirection received from the SCAN listeners to the database node to connect to. By default the mode would be DIRECT.
     */
    readonly sessionMode: string;
    /**
     * Possible lifecycle states.
     */
    readonly state: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet being referenced.
     */
    readonly subnetId: string;
    /**
     * The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     */
    readonly timeCreated: string;
    /**
     * The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     */
    readonly timeUpdated: string;
    /**
     * The username Oracle GoldenGate uses to connect the associated RDBMS.  This username must already exist and be available for use by the database.  It must conform to the security requirements implemented by the database including length, case sensitivity, and so on.
     */
    readonly username: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the customer vault being referenced. If provided, this will reference a vault which the customer will be required to ensure the policies are established to permit the GoldenGate Service to manage secrets contained within this vault.
     */
    readonly vaultId: string;
    readonly wallet: string;
}

export function getDatabaseRegistrationOutput(args: GetDatabaseRegistrationOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDatabaseRegistrationResult> {
    return pulumi.output(args).apply(a => getDatabaseRegistration(a, opts))
}

/**
 * A collection of arguments for invoking getDatabaseRegistration.
 */
export interface GetDatabaseRegistrationOutputArgs {
    /**
     * A unique DatabaseRegistration identifier.
     */
    databaseRegistrationId: pulumi.Input<string>;
}
