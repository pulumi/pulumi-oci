// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * **Deprecated. Use oci.Database.AutonomousDatabaseWallet instead.**
 *
 * This data source provides details about a specific Autonomous Database Wallet resource in Oracle Cloud Infrastructure Database service.
 *
 * Creates and downloads a wallet for the specified Autonomous Database.
 */
export function getAutonomousDatabaseWallet(args: GetAutonomousDatabaseWalletArgs, opts?: pulumi.InvokeOptions): Promise<GetAutonomousDatabaseWalletResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getAutonomousDatabaseWallet:getAutonomousDatabaseWallet", {
        "autonomousDatabaseId": args.autonomousDatabaseId,
        "base64EncodeContent": args.base64EncodeContent,
        "generateType": args.generateType,
        "password": args.password,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousDatabaseWallet.
 */
export interface GetAutonomousDatabaseWalletArgs {
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     *
     * @deprecated The 'data.oci_database_autonomous_database_wallet' resource has been deprecated. Please use 'oci_database_autonomous_database_wallet' instead.
     */
    autonomousDatabaseId: string;
    base64EncodeContent?: boolean;
    /**
     * The type of wallet to generate.
     *
     * **Serverless instance usage:**
     * * `SINGLE` - used to generate a wallet for a single database
     * * `ALL` - used to generate wallet for all databases in the region
     *
     * **Dedicated Exadata infrastructure usage:** Value must be `NULL` if attribute is used.
     */
    generateType?: string;
    /**
     * The password to encrypt the keys inside the wallet. The password must be at least 8 characters long and must include at least 1 letter and either 1 numeric character or 1 special character.
     */
    password: string;
}

/**
 * A collection of values returned by getAutonomousDatabaseWallet.
 */
export interface GetAutonomousDatabaseWalletResult {
    /**
     * @deprecated The 'data.oci_database_autonomous_database_wallet' resource has been deprecated. Please use 'oci_database_autonomous_database_wallet' instead.
     */
    readonly autonomousDatabaseId: string;
    readonly base64EncodeContent?: boolean;
    /**
     * content of the downloaded zipped wallet for the Autonomous Database. If `base64EncodeContent` is set to `true`, then this content will be base64 encoded.
     */
    readonly content: string;
    readonly generateType?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly password: string;
}
/**
 * **Deprecated. Use oci.Database.AutonomousDatabaseWallet instead.**
 *
 * This data source provides details about a specific Autonomous Database Wallet resource in Oracle Cloud Infrastructure Database service.
 *
 * Creates and downloads a wallet for the specified Autonomous Database.
 */
export function getAutonomousDatabaseWalletOutput(args: GetAutonomousDatabaseWalletOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAutonomousDatabaseWalletResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getAutonomousDatabaseWallet:getAutonomousDatabaseWallet", {
        "autonomousDatabaseId": args.autonomousDatabaseId,
        "base64EncodeContent": args.base64EncodeContent,
        "generateType": args.generateType,
        "password": args.password,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousDatabaseWallet.
 */
export interface GetAutonomousDatabaseWalletOutputArgs {
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     *
     * @deprecated The 'data.oci_database_autonomous_database_wallet' resource has been deprecated. Please use 'oci_database_autonomous_database_wallet' instead.
     */
    autonomousDatabaseId: pulumi.Input<string>;
    base64EncodeContent?: pulumi.Input<boolean>;
    /**
     * The type of wallet to generate.
     *
     * **Serverless instance usage:**
     * * `SINGLE` - used to generate a wallet for a single database
     * * `ALL` - used to generate wallet for all databases in the region
     *
     * **Dedicated Exadata infrastructure usage:** Value must be `NULL` if attribute is used.
     */
    generateType?: pulumi.Input<string>;
    /**
     * The password to encrypt the keys inside the wallet. The password must be at least 8 characters long and must include at least 1 letter and either 1 numeric character or 1 special character.
     */
    password: pulumi.Input<string>;
}
