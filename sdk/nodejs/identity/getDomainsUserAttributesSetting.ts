// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific User Attributes Setting resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get User Schema Attribute Settings
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUserAttributesSetting = oci.Identity.getDomainsUserAttributesSetting({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     userAttributesSettingId: oci_identity_domains_user_attributes_setting.test_user_attributes_setting.id,
 *     attributeSets: ["all"],
 *     attributes: "",
 *     authorization: _var.user_attributes_setting_authorization,
 *     resourceTypeSchemaVersion: _var.user_attributes_setting_resource_type_schema_version,
 * });
 * ```
 */
export function getDomainsUserAttributesSetting(args: GetDomainsUserAttributesSettingArgs, opts?: pulumi.InvokeOptions): Promise<GetDomainsUserAttributesSettingResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getDomainsUserAttributesSetting:getDomainsUserAttributesSetting", {
        "attributeSets": args.attributeSets,
        "attributes": args.attributes,
        "authorization": args.authorization,
        "idcsEndpoint": args.idcsEndpoint,
        "resourceTypeSchemaVersion": args.resourceTypeSchemaVersion,
        "userAttributesSettingId": args.userAttributesSettingId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainsUserAttributesSetting.
 */
export interface GetDomainsUserAttributesSettingArgs {
    /**
     * A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     */
    attributeSets?: string[];
    /**
     * A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     */
    attributes?: string;
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    authorization?: string;
    /**
     * The basic endpoint for the identity domain
     */
    idcsEndpoint: string;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: string;
    /**
     * ID of the resource
     */
    userAttributesSettingId: string;
}

/**
 * A collection of values returned by getDomainsUserAttributesSetting.
 */
export interface GetDomainsUserAttributesSettingResult {
    readonly attributeSets?: string[];
    /**
     * User Schema Attribute Settings
     */
    readonly attributeSettings: outputs.Identity.GetDomainsUserAttributesSettingAttributeSetting[];
    readonly attributes?: string;
    readonly authorization?: string;
    /**
     * Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     */
    readonly compartmentOcid: string;
    /**
     * A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     */
    readonly deleteInProgress: boolean;
    /**
     * Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     */
    readonly domainOcid: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The User or App who created the Resource
     */
    readonly idcsCreatedBies: outputs.Identity.GetDomainsUserAttributesSettingIdcsCreatedBy[];
    readonly idcsEndpoint: string;
    /**
     * The User or App who modified the Resource
     */
    readonly idcsLastModifiedBies: outputs.Identity.GetDomainsUserAttributesSettingIdcsLastModifiedBy[];
    /**
     * The release number when the resource was upgraded.
     */
    readonly idcsLastUpgradedInRelease: string;
    /**
     * Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     */
    readonly idcsPreventedOperations: string[];
    /**
     * A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     */
    readonly metas: outputs.Identity.GetDomainsUserAttributesSettingMeta[];
    /**
     * Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     */
    readonly ocid: string;
    readonly resourceTypeSchemaVersion?: string;
    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     */
    readonly schemas: string[];
    /**
     * A list of tags on this resource.
     */
    readonly tags: outputs.Identity.GetDomainsUserAttributesSettingTag[];
    /**
     * Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     */
    readonly tenancyOcid: string;
    readonly userAttributesSettingId: string;
}
/**
 * This data source provides details about a specific User Attributes Setting resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get User Schema Attribute Settings
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUserAttributesSetting = oci.Identity.getDomainsUserAttributesSetting({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     userAttributesSettingId: oci_identity_domains_user_attributes_setting.test_user_attributes_setting.id,
 *     attributeSets: ["all"],
 *     attributes: "",
 *     authorization: _var.user_attributes_setting_authorization,
 *     resourceTypeSchemaVersion: _var.user_attributes_setting_resource_type_schema_version,
 * });
 * ```
 */
export function getDomainsUserAttributesSettingOutput(args: GetDomainsUserAttributesSettingOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDomainsUserAttributesSettingResult> {
    return pulumi.output(args).apply((a: any) => getDomainsUserAttributesSetting(a, opts))
}

/**
 * A collection of arguments for invoking getDomainsUserAttributesSetting.
 */
export interface GetDomainsUserAttributesSettingOutputArgs {
    /**
     * A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     */
    attributeSets?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     */
    attributes?: pulumi.Input<string>;
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    authorization?: pulumi.Input<string>;
    /**
     * The basic endpoint for the identity domain
     */
    idcsEndpoint: pulumi.Input<string>;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: pulumi.Input<string>;
    /**
     * ID of the resource
     */
    userAttributesSettingId: pulumi.Input<string>;
}