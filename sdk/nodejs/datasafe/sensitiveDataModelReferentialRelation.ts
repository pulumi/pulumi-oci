// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Sensitive Data Model Referential Relation resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Creates a new referential relation in the specified sensitive data model.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSensitiveDataModelReferentialRelation = new oci.datasafe.SensitiveDataModelReferentialRelation("test_sensitive_data_model_referential_relation", {
 *     child: {
 *         appName: sensitiveDataModelReferentialRelationChildAppName,
 *         columnGroups: sensitiveDataModelReferentialRelationChildColumnGroup,
 *         object: sensitiveDataModelReferentialRelationChildObject,
 *         objectType: sensitiveDataModelReferentialRelationChildObjectType,
 *         schemaName: sensitiveDataModelReferentialRelationChildSchemaName,
 *         sensitiveTypeIds: sensitiveDataModelReferentialRelationChildSensitiveTypeIds,
 *     },
 *     parent: {
 *         appName: sensitiveDataModelReferentialRelationParentAppName,
 *         columnGroups: sensitiveDataModelReferentialRelationParentColumnGroup,
 *         object: sensitiveDataModelReferentialRelationParentObject,
 *         objectType: sensitiveDataModelReferentialRelationParentObjectType,
 *         schemaName: sensitiveDataModelReferentialRelationParentSchemaName,
 *         sensitiveTypeIds: sensitiveDataModelReferentialRelationParentSensitiveTypeIds,
 *     },
 *     relationType: sensitiveDataModelReferentialRelationRelationType,
 *     sensitiveDataModelId: testSensitiveDataModel.id,
 *     isSensitive: sensitiveDataModelReferentialRelationIsSensitive,
 * });
 * ```
 *
 * ## Import
 *
 * SensitiveDataModelReferentialRelations can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DataSafe/sensitiveDataModelReferentialRelation:SensitiveDataModelReferentialRelation test_sensitive_data_model_referential_relation "sensitiveDataModels/{sensitiveDataModelId}/referentialRelations/{referentialRelationKey}"
 * ```
 */
export class SensitiveDataModelReferentialRelation extends pulumi.CustomResource {
    /**
     * Get an existing SensitiveDataModelReferentialRelation resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: SensitiveDataModelReferentialRelationState, opts?: pulumi.CustomResourceOptions): SensitiveDataModelReferentialRelation {
        return new SensitiveDataModelReferentialRelation(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataSafe/sensitiveDataModelReferentialRelation:SensitiveDataModelReferentialRelation';

    /**
     * Returns true if the given object is an instance of SensitiveDataModelReferentialRelation.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is SensitiveDataModelReferentialRelation {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === SensitiveDataModelReferentialRelation.__pulumiType;
    }

    /**
     * columnsInfo object has details of column group with schema details.
     */
    public readonly child!: pulumi.Output<outputs.DataSafe.SensitiveDataModelReferentialRelationChild>;
    /**
     * Add to sensitive data model if passed true. If false is passed, then the columns will not be added in the sensitive data model as sensitive columns and  if sensitive type OCIDs are assigned to the columns, then the sensitive type OCIDs will not be retained.
     */
    public readonly isSensitive!: pulumi.Output<boolean>;
    /**
     * The unique key that identifies the referential relation. It's numeric and unique within a sensitive data model.
     */
    public /*out*/ readonly key!: pulumi.Output<string>;
    /**
     * columnsInfo object has details of column group with schema details.
     */
    public readonly parent!: pulumi.Output<outputs.DataSafe.SensitiveDataModelReferentialRelationParent>;
    /**
     * The type of referential relationship the sensitive column has with its parent.  DB_DEFINED indicates that the relationship is defined in the database dictionary.  APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
     */
    public readonly relationType!: pulumi.Output<string>;
    /**
     * The OCID of the sensitive data model.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly sensitiveDataModelId!: pulumi.Output<string>;
    /**
     * The current state of the referential relation.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;

    /**
     * Create a SensitiveDataModelReferentialRelation resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: SensitiveDataModelReferentialRelationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: SensitiveDataModelReferentialRelationArgs | SensitiveDataModelReferentialRelationState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as SensitiveDataModelReferentialRelationState | undefined;
            resourceInputs["child"] = state ? state.child : undefined;
            resourceInputs["isSensitive"] = state ? state.isSensitive : undefined;
            resourceInputs["key"] = state ? state.key : undefined;
            resourceInputs["parent"] = state ? state.parent : undefined;
            resourceInputs["relationType"] = state ? state.relationType : undefined;
            resourceInputs["sensitiveDataModelId"] = state ? state.sensitiveDataModelId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
        } else {
            const args = argsOrState as SensitiveDataModelReferentialRelationArgs | undefined;
            if ((!args || args.child === undefined) && !opts.urn) {
                throw new Error("Missing required property 'child'");
            }
            if ((!args || args.parent === undefined) && !opts.urn) {
                throw new Error("Missing required property 'parent'");
            }
            if ((!args || args.relationType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'relationType'");
            }
            if ((!args || args.sensitiveDataModelId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'sensitiveDataModelId'");
            }
            resourceInputs["child"] = args ? args.child : undefined;
            resourceInputs["isSensitive"] = args ? args.isSensitive : undefined;
            resourceInputs["parent"] = args ? args.parent : undefined;
            resourceInputs["relationType"] = args ? args.relationType : undefined;
            resourceInputs["sensitiveDataModelId"] = args ? args.sensitiveDataModelId : undefined;
            resourceInputs["key"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(SensitiveDataModelReferentialRelation.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering SensitiveDataModelReferentialRelation resources.
 */
export interface SensitiveDataModelReferentialRelationState {
    /**
     * columnsInfo object has details of column group with schema details.
     */
    child?: pulumi.Input<inputs.DataSafe.SensitiveDataModelReferentialRelationChild>;
    /**
     * Add to sensitive data model if passed true. If false is passed, then the columns will not be added in the sensitive data model as sensitive columns and  if sensitive type OCIDs are assigned to the columns, then the sensitive type OCIDs will not be retained.
     */
    isSensitive?: pulumi.Input<boolean>;
    /**
     * The unique key that identifies the referential relation. It's numeric and unique within a sensitive data model.
     */
    key?: pulumi.Input<string>;
    /**
     * columnsInfo object has details of column group with schema details.
     */
    parent?: pulumi.Input<inputs.DataSafe.SensitiveDataModelReferentialRelationParent>;
    /**
     * The type of referential relationship the sensitive column has with its parent.  DB_DEFINED indicates that the relationship is defined in the database dictionary.  APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
     */
    relationType?: pulumi.Input<string>;
    /**
     * The OCID of the sensitive data model.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    sensitiveDataModelId?: pulumi.Input<string>;
    /**
     * The current state of the referential relation.
     */
    state?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a SensitiveDataModelReferentialRelation resource.
 */
export interface SensitiveDataModelReferentialRelationArgs {
    /**
     * columnsInfo object has details of column group with schema details.
     */
    child: pulumi.Input<inputs.DataSafe.SensitiveDataModelReferentialRelationChild>;
    /**
     * Add to sensitive data model if passed true. If false is passed, then the columns will not be added in the sensitive data model as sensitive columns and  if sensitive type OCIDs are assigned to the columns, then the sensitive type OCIDs will not be retained.
     */
    isSensitive?: pulumi.Input<boolean>;
    /**
     * columnsInfo object has details of column group with schema details.
     */
    parent: pulumi.Input<inputs.DataSafe.SensitiveDataModelReferentialRelationParent>;
    /**
     * The type of referential relationship the sensitive column has with its parent.  DB_DEFINED indicates that the relationship is defined in the database dictionary.  APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
     */
    relationType: pulumi.Input<string>;
    /**
     * The OCID of the sensitive data model.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    sensitiveDataModelId: pulumi.Input<string>;
}
