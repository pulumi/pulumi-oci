// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the My Customer Secret Key resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Add a user's own customer secret key.
 *
 * ## Import
 *
 * MyCustomerSecretKeys can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Identity/domainsMyCustomerSecretKey:DomainsMyCustomerSecretKey test_my_customer_secret_key "idcsEndpoint/{idcsEndpoint}/myCustomerSecretKeys/{myCustomerSecretKeyId}"
 * ```
 */
export class DomainsMyCustomerSecretKey extends pulumi.CustomResource {
    /**
     * Get an existing DomainsMyCustomerSecretKey resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DomainsMyCustomerSecretKeyState, opts?: pulumi.CustomResourceOptions): DomainsMyCustomerSecretKey {
        return new DomainsMyCustomerSecretKey(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Identity/domainsMyCustomerSecretKey:DomainsMyCustomerSecretKey';

    /**
     * Returns true if the given object is an instance of DomainsMyCustomerSecretKey.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DomainsMyCustomerSecretKey {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DomainsMyCustomerSecretKey.__pulumiType;
    }

    /**
     * (Updatable) The access key.
     *
     * **SCIM++ Properties:**
     * * caseExact: true
     * * type: string
     * * mutability: readOnly
     * * required: false
     * * returned: default
     */
    public /*out*/ readonly accessKey!: pulumi.Output<string>;
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    public readonly authorization!: pulumi.Output<string | undefined>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     */
    public /*out*/ readonly compartmentOcid!: pulumi.Output<string>;
    /**
     * (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     */
    public /*out*/ readonly deleteInProgress!: pulumi.Output<boolean>;
    /**
     * Description
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * type: string
     * * mutability: readWrite
     * * required: false
     * * returned: default
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * Display Name
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * type: string
     * * mutability: readWrite
     * * required: false
     * * returned: default
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     */
    public /*out*/ readonly domainOcid!: pulumi.Output<string>;
    /**
     * When the user's credential expire.
     *
     * **Added In:** 2109090424
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: dateTime
     * * uniqueness: none
     */
    public readonly expiresOn!: pulumi.Output<string>;
    /**
     * (Updatable) The User or App who created the Resource
     *
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: complex
     */
    public /*out*/ readonly idcsCreatedBies!: pulumi.Output<outputs.Identity.DomainsMyCustomerSecretKeyIdcsCreatedBy[]>;
    /**
     * The basic endpoint for the identity domain
     */
    public readonly idcsEndpoint!: pulumi.Output<string>;
    /**
     * (Updatable) The User or App who modified the Resource
     *
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: complex
     */
    public /*out*/ readonly idcsLastModifiedBies!: pulumi.Output<outputs.Identity.DomainsMyCustomerSecretKeyIdcsLastModifiedBy[]>;
    /**
     * (Updatable) The release number when the resource was upgraded.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     */
    public /*out*/ readonly idcsLastUpgradedInRelease!: pulumi.Output<string>;
    /**
     * (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     *
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     */
    public /*out*/ readonly idcsPreventedOperations!: pulumi.Output<string[]>;
    /**
     * (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Created Date, mapsTo:meta.created]]
     * * type: complex
     */
    public /*out*/ readonly metas!: pulumi.Output<outputs.Identity.DomainsMyCustomerSecretKeyMeta[]>;
    /**
     * Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     *
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: global
     */
    public readonly ocid!: pulumi.Output<string>;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    public readonly resourceTypeSchemaVersion!: pulumi.Output<string | undefined>;
    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     */
    public readonly schemas!: pulumi.Output<string[]>;
    /**
     * The user's credential status.
     *
     * **Added In:** 2109090424
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: never
     * * type: string
     * * uniqueness: none
     */
    public readonly status!: pulumi.Output<string>;
    /**
     * A list of tags on this resource.
     *
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [key, value]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: complex
     * * uniqueness: none
     */
    public readonly tags!: pulumi.Output<outputs.Identity.DomainsMyCustomerSecretKeyTag[]>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     */
    public /*out*/ readonly tenancyOcid!: pulumi.Output<string>;
    /**
     * User linked to customer secret key
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: complex
     * * uniqueness: none
     */
    public readonly user!: pulumi.Output<outputs.Identity.DomainsMyCustomerSecretKeyUser>;

    /**
     * Create a DomainsMyCustomerSecretKey resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DomainsMyCustomerSecretKeyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DomainsMyCustomerSecretKeyArgs | DomainsMyCustomerSecretKeyState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DomainsMyCustomerSecretKeyState | undefined;
            resourceInputs["accessKey"] = state ? state.accessKey : undefined;
            resourceInputs["authorization"] = state ? state.authorization : undefined;
            resourceInputs["compartmentOcid"] = state ? state.compartmentOcid : undefined;
            resourceInputs["deleteInProgress"] = state ? state.deleteInProgress : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["domainOcid"] = state ? state.domainOcid : undefined;
            resourceInputs["expiresOn"] = state ? state.expiresOn : undefined;
            resourceInputs["idcsCreatedBies"] = state ? state.idcsCreatedBies : undefined;
            resourceInputs["idcsEndpoint"] = state ? state.idcsEndpoint : undefined;
            resourceInputs["idcsLastModifiedBies"] = state ? state.idcsLastModifiedBies : undefined;
            resourceInputs["idcsLastUpgradedInRelease"] = state ? state.idcsLastUpgradedInRelease : undefined;
            resourceInputs["idcsPreventedOperations"] = state ? state.idcsPreventedOperations : undefined;
            resourceInputs["metas"] = state ? state.metas : undefined;
            resourceInputs["ocid"] = state ? state.ocid : undefined;
            resourceInputs["resourceTypeSchemaVersion"] = state ? state.resourceTypeSchemaVersion : undefined;
            resourceInputs["schemas"] = state ? state.schemas : undefined;
            resourceInputs["status"] = state ? state.status : undefined;
            resourceInputs["tags"] = state ? state.tags : undefined;
            resourceInputs["tenancyOcid"] = state ? state.tenancyOcid : undefined;
            resourceInputs["user"] = state ? state.user : undefined;
        } else {
            const args = argsOrState as DomainsMyCustomerSecretKeyArgs | undefined;
            if ((!args || args.idcsEndpoint === undefined) && !opts.urn) {
                throw new Error("Missing required property 'idcsEndpoint'");
            }
            if ((!args || args.schemas === undefined) && !opts.urn) {
                throw new Error("Missing required property 'schemas'");
            }
            resourceInputs["authorization"] = args ? args.authorization : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["expiresOn"] = args ? args.expiresOn : undefined;
            resourceInputs["idcsEndpoint"] = args ? args.idcsEndpoint : undefined;
            resourceInputs["ocid"] = args ? args.ocid : undefined;
            resourceInputs["resourceTypeSchemaVersion"] = args ? args.resourceTypeSchemaVersion : undefined;
            resourceInputs["schemas"] = args ? args.schemas : undefined;
            resourceInputs["status"] = args ? args.status : undefined;
            resourceInputs["tags"] = args ? args.tags : undefined;
            resourceInputs["user"] = args ? args.user : undefined;
            resourceInputs["accessKey"] = undefined /*out*/;
            resourceInputs["compartmentOcid"] = undefined /*out*/;
            resourceInputs["deleteInProgress"] = undefined /*out*/;
            resourceInputs["domainOcid"] = undefined /*out*/;
            resourceInputs["idcsCreatedBies"] = undefined /*out*/;
            resourceInputs["idcsLastModifiedBies"] = undefined /*out*/;
            resourceInputs["idcsLastUpgradedInRelease"] = undefined /*out*/;
            resourceInputs["idcsPreventedOperations"] = undefined /*out*/;
            resourceInputs["metas"] = undefined /*out*/;
            resourceInputs["tenancyOcid"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DomainsMyCustomerSecretKey.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DomainsMyCustomerSecretKey resources.
 */
export interface DomainsMyCustomerSecretKeyState {
    /**
     * (Updatable) The access key.
     *
     * **SCIM++ Properties:**
     * * caseExact: true
     * * type: string
     * * mutability: readOnly
     * * required: false
     * * returned: default
     */
    accessKey?: pulumi.Input<string>;
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    authorization?: pulumi.Input<string>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     */
    compartmentOcid?: pulumi.Input<string>;
    /**
     * (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     */
    deleteInProgress?: pulumi.Input<boolean>;
    /**
     * Description
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * type: string
     * * mutability: readWrite
     * * required: false
     * * returned: default
     */
    description?: pulumi.Input<string>;
    /**
     * Display Name
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * type: string
     * * mutability: readWrite
     * * required: false
     * * returned: default
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     */
    domainOcid?: pulumi.Input<string>;
    /**
     * When the user's credential expire.
     *
     * **Added In:** 2109090424
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: dateTime
     * * uniqueness: none
     */
    expiresOn?: pulumi.Input<string>;
    /**
     * (Updatable) The User or App who created the Resource
     *
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: complex
     */
    idcsCreatedBies?: pulumi.Input<pulumi.Input<inputs.Identity.DomainsMyCustomerSecretKeyIdcsCreatedBy>[]>;
    /**
     * The basic endpoint for the identity domain
     */
    idcsEndpoint?: pulumi.Input<string>;
    /**
     * (Updatable) The User or App who modified the Resource
     *
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: complex
     */
    idcsLastModifiedBies?: pulumi.Input<pulumi.Input<inputs.Identity.DomainsMyCustomerSecretKeyIdcsLastModifiedBy>[]>;
    /**
     * (Updatable) The release number when the resource was upgraded.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     */
    idcsLastUpgradedInRelease?: pulumi.Input<string>;
    /**
     * (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     *
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     */
    idcsPreventedOperations?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Created Date, mapsTo:meta.created]]
     * * type: complex
     */
    metas?: pulumi.Input<pulumi.Input<inputs.Identity.DomainsMyCustomerSecretKeyMeta>[]>;
    /**
     * Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     *
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: global
     */
    ocid?: pulumi.Input<string>;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: pulumi.Input<string>;
    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     */
    schemas?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The user's credential status.
     *
     * **Added In:** 2109090424
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: never
     * * type: string
     * * uniqueness: none
     */
    status?: pulumi.Input<string>;
    /**
     * A list of tags on this resource.
     *
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [key, value]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: complex
     * * uniqueness: none
     */
    tags?: pulumi.Input<pulumi.Input<inputs.Identity.DomainsMyCustomerSecretKeyTag>[]>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     */
    tenancyOcid?: pulumi.Input<string>;
    /**
     * User linked to customer secret key
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: complex
     * * uniqueness: none
     */
    user?: pulumi.Input<inputs.Identity.DomainsMyCustomerSecretKeyUser>;
}

/**
 * The set of arguments for constructing a DomainsMyCustomerSecretKey resource.
 */
export interface DomainsMyCustomerSecretKeyArgs {
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    authorization?: pulumi.Input<string>;
    /**
     * Description
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * type: string
     * * mutability: readWrite
     * * required: false
     * * returned: default
     */
    description?: pulumi.Input<string>;
    /**
     * Display Name
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * type: string
     * * mutability: readWrite
     * * required: false
     * * returned: default
     */
    displayName?: pulumi.Input<string>;
    /**
     * When the user's credential expire.
     *
     * **Added In:** 2109090424
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: dateTime
     * * uniqueness: none
     */
    expiresOn?: pulumi.Input<string>;
    /**
     * The basic endpoint for the identity domain
     */
    idcsEndpoint: pulumi.Input<string>;
    /**
     * Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     *
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: global
     */
    ocid?: pulumi.Input<string>;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: pulumi.Input<string>;
    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     */
    schemas: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The user's credential status.
     *
     * **Added In:** 2109090424
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: never
     * * type: string
     * * uniqueness: none
     */
    status?: pulumi.Input<string>;
    /**
     * A list of tags on this resource.
     *
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [key, value]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: complex
     * * uniqueness: none
     */
    tags?: pulumi.Input<pulumi.Input<inputs.Identity.DomainsMyCustomerSecretKeyTag>[]>;
    /**
     * User linked to customer secret key
     *
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: complex
     * * uniqueness: none
     */
    user?: pulumi.Input<inputs.Identity.DomainsMyCustomerSecretKeyUser>;
}
