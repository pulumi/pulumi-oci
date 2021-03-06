// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Registry Folder resource in Oracle Cloud Infrastructure Data Connectivity service.
 *
 * Creates a folder under a specefied registry.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRegistryFolder = new oci.dataconnectivity.RegistryFolder("testRegistryFolder", {
 *     identifier: _var.registry_folder_identifier,
 *     registryId: oci_data_connectivity_registry.test_registry.id,
 *     dataAssets: [{
 *         identifier: _var.registry_folder_data_assets_identifier,
 *         key: _var.registry_folder_data_assets_key,
 *         name: _var.registry_folder_data_assets_name,
 *         assetProperties: _var.registry_folder_data_assets_asset_properties,
 *         defaultConnection: {
 *             identifier: _var.registry_folder_data_assets_default_connection_identifier,
 *             key: _var.registry_folder_data_assets_default_connection_key,
 *             name: _var.registry_folder_data_assets_default_connection_name,
 *             connectionProperties: [{
 *                 name: _var.registry_folder_data_assets_default_connection_connection_properties_name,
 *                 value: _var.registry_folder_data_assets_default_connection_connection_properties_value,
 *             }],
 *             description: _var.registry_folder_data_assets_default_connection_description,
 *             isDefault: _var.registry_folder_data_assets_default_connection_is_default,
 *             metadata: {
 *                 aggregator: {
 *                     description: _var.registry_folder_data_assets_default_connection_metadata_aggregator_description,
 *                     identifier: _var.registry_folder_data_assets_default_connection_metadata_aggregator_identifier,
 *                     key: _var.registry_folder_data_assets_default_connection_metadata_aggregator_key,
 *                     name: _var.registry_folder_data_assets_default_connection_metadata_aggregator_name,
 *                     type: _var.registry_folder_data_assets_default_connection_metadata_aggregator_type,
 *                 },
 *                 aggregatorKey: _var.registry_folder_data_assets_default_connection_metadata_aggregator_key,
 *                 createdBy: _var.registry_folder_data_assets_default_connection_metadata_created_by,
 *                 createdByName: _var.registry_folder_data_assets_default_connection_metadata_created_by_name,
 *                 identifierPath: _var.registry_folder_data_assets_default_connection_metadata_identifier_path,
 *                 infoFields: _var.registry_folder_data_assets_default_connection_metadata_info_fields,
 *                 isFavorite: _var.registry_folder_data_assets_default_connection_metadata_is_favorite,
 *                 labels: _var.registry_folder_data_assets_default_connection_metadata_labels,
 *                 registryVersion: _var.registry_folder_data_assets_default_connection_metadata_registry_version,
 *                 timeCreated: _var.registry_folder_data_assets_default_connection_metadata_time_created,
 *                 timeUpdated: _var.registry_folder_data_assets_default_connection_metadata_time_updated,
 *                 updatedBy: _var.registry_folder_data_assets_default_connection_metadata_updated_by,
 *                 updatedByName: _var.registry_folder_data_assets_default_connection_metadata_updated_by_name,
 *             },
 *             modelType: _var.registry_folder_data_assets_default_connection_model_type,
 *             modelVersion: _var.registry_folder_data_assets_default_connection_model_version,
 *             objectStatus: _var.registry_folder_data_assets_default_connection_object_status,
 *             objectVersion: _var.registry_folder_data_assets_default_connection_object_version,
 *             primarySchema: {
 *                 identifier: _var.registry_folder_data_assets_default_connection_primary_schema_identifier,
 *                 key: _var.registry_folder_data_assets_default_connection_primary_schema_key,
 *                 modelType: _var.registry_folder_data_assets_default_connection_primary_schema_model_type,
 *                 name: _var.registry_folder_data_assets_default_connection_primary_schema_name,
 *                 defaultConnection: _var.registry_folder_data_assets_default_connection_primary_schema_default_connection,
 *                 description: _var.registry_folder_data_assets_default_connection_primary_schema_description,
 *                 externalKey: _var.registry_folder_data_assets_default_connection_primary_schema_external_key,
 *                 isHasContainers: _var.registry_folder_data_assets_default_connection_primary_schema_is_has_containers,
 *                 metadata: {
 *                     aggregator: {
 *                         description: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_aggregator_description,
 *                         identifier: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_aggregator_identifier,
 *                         key: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_aggregator_key,
 *                         name: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_aggregator_name,
 *                         type: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_aggregator_type,
 *                     },
 *                     aggregatorKey: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_aggregator_key,
 *                     createdBy: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_created_by,
 *                     createdByName: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_created_by_name,
 *                     identifierPath: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_identifier_path,
 *                     infoFields: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_info_fields,
 *                     isFavorite: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_is_favorite,
 *                     labels: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_labels,
 *                     registryVersion: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_registry_version,
 *                     timeCreated: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_time_created,
 *                     timeUpdated: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_time_updated,
 *                     updatedBy: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_updated_by,
 *                     updatedByName: _var.registry_folder_data_assets_default_connection_primary_schema_metadata_updated_by_name,
 *                 },
 *                 modelVersion: _var.registry_folder_data_assets_default_connection_primary_schema_model_version,
 *                 objectStatus: _var.registry_folder_data_assets_default_connection_primary_schema_object_status,
 *                 objectVersion: _var.registry_folder_data_assets_default_connection_primary_schema_object_version,
 *                 parentRef: {
 *                     parent: _var.registry_folder_data_assets_default_connection_primary_schema_parent_ref_parent,
 *                 },
 *                 resourceName: _var.registry_folder_data_assets_default_connection_primary_schema_resource_name,
 *             },
 *             properties: _var.registry_folder_data_assets_default_connection_properties,
 *             registryMetadata: {
 *                 aggregatorKey: _var.registry_folder_data_assets_default_connection_registry_metadata_aggregator_key,
 *                 createdByUserId: oci_identity_user.test_user.id,
 *                 createdByUserName: oci_identity_user.test_user.name,
 *                 isFavorite: _var.registry_folder_data_assets_default_connection_registry_metadata_is_favorite,
 *                 key: _var.registry_folder_data_assets_default_connection_registry_metadata_key,
 *                 labels: _var.registry_folder_data_assets_default_connection_registry_metadata_labels,
 *                 registryVersion: _var.registry_folder_data_assets_default_connection_registry_metadata_registry_version,
 *                 timeCreated: _var.registry_folder_data_assets_default_connection_registry_metadata_time_created,
 *                 timeUpdated: _var.registry_folder_data_assets_default_connection_registry_metadata_time_updated,
 *                 updatedByUserId: oci_identity_user.test_user.id,
 *                 updatedByUserName: oci_identity_user.test_user.name,
 *             },
 *             type: _var.registry_folder_data_assets_default_connection_type,
 *         },
 *         description: _var.registry_folder_data_assets_description,
 *         externalKey: _var.registry_folder_data_assets_external_key,
 *         metadata: {
 *             aggregator: {
 *                 description: _var.registry_folder_data_assets_metadata_aggregator_description,
 *                 identifier: _var.registry_folder_data_assets_metadata_aggregator_identifier,
 *                 key: _var.registry_folder_data_assets_metadata_aggregator_key,
 *                 name: _var.registry_folder_data_assets_metadata_aggregator_name,
 *                 type: _var.registry_folder_data_assets_metadata_aggregator_type,
 *             },
 *             aggregatorKey: _var.registry_folder_data_assets_metadata_aggregator_key,
 *             createdBy: _var.registry_folder_data_assets_metadata_created_by,
 *             createdByName: _var.registry_folder_data_assets_metadata_created_by_name,
 *             identifierPath: _var.registry_folder_data_assets_metadata_identifier_path,
 *             infoFields: _var.registry_folder_data_assets_metadata_info_fields,
 *             isFavorite: _var.registry_folder_data_assets_metadata_is_favorite,
 *             labels: _var.registry_folder_data_assets_metadata_labels,
 *             registryVersion: _var.registry_folder_data_assets_metadata_registry_version,
 *             timeCreated: _var.registry_folder_data_assets_metadata_time_created,
 *             timeUpdated: _var.registry_folder_data_assets_metadata_time_updated,
 *             updatedBy: _var.registry_folder_data_assets_metadata_updated_by,
 *             updatedByName: _var.registry_folder_data_assets_metadata_updated_by_name,
 *         },
 *         modelType: _var.registry_folder_data_assets_model_type,
 *         modelVersion: _var.registry_folder_data_assets_model_version,
 *         nativeTypeSystem: {
 *             description: _var.registry_folder_data_assets_native_type_system_description,
 *             identifier: _var.registry_folder_data_assets_native_type_system_identifier,
 *             key: _var.registry_folder_data_assets_native_type_system_key,
 *             modelType: _var.registry_folder_data_assets_native_type_system_model_type,
 *             modelVersion: _var.registry_folder_data_assets_native_type_system_model_version,
 *             name: _var.registry_folder_data_assets_native_type_system_name,
 *             objectStatus: _var.registry_folder_data_assets_native_type_system_object_status,
 *             objectVersion: _var.registry_folder_data_assets_native_type_system_object_version,
 *             parentRef: {
 *                 parent: _var.registry_folder_data_assets_native_type_system_parent_ref_parent,
 *             },
 *             typeMappingFrom: _var.registry_folder_data_assets_native_type_system_type_mapping_from,
 *             typeMappingTo: _var.registry_folder_data_assets_native_type_system_type_mapping_to,
 *             types: [{
 *                 modelType: _var.registry_folder_data_assets_native_type_system_types_model_type,
 *                 configDefinition: {
 *                     configParameterDefinitions: [{
 *                         classFieldName: _var.registry_folder_data_assets_native_type_system_types_config_definition_config_parameter_definitions_class_field_name,
 *                         defaultValue: _var.registry_folder_data_assets_native_type_system_types_config_definition_config_parameter_definitions_default_value,
 *                         description: _var.registry_folder_data_assets_native_type_system_types_config_definition_config_parameter_definitions_description,
 *                         isClassFieldValue: _var.registry_folder_data_assets_native_type_system_types_config_definition_config_parameter_definitions_is_class_field_value,
 *                         isStatic: _var.registry_folder_data_assets_native_type_system_types_config_definition_config_parameter_definitions_is_static,
 *                         parameterName: _var.registry_folder_data_assets_native_type_system_types_config_definition_config_parameter_definitions_parameter_name,
 *                         parameterType: _var.registry_folder_data_assets_native_type_system_types_config_definition_config_parameter_definitions_parameter_type,
 *                     }],
 *                     isContained: _var.registry_folder_data_assets_native_type_system_types_config_definition_is_contained,
 *                     key: _var.registry_folder_data_assets_native_type_system_types_config_definition_key,
 *                     modelType: _var.registry_folder_data_assets_native_type_system_types_config_definition_model_type,
 *                     modelVersion: _var.registry_folder_data_assets_native_type_system_types_config_definition_model_version,
 *                     name: _var.registry_folder_data_assets_native_type_system_types_config_definition_name,
 *                     objectStatus: _var.registry_folder_data_assets_native_type_system_types_config_definition_object_status,
 *                     parentRef: {
 *                         parent: _var.registry_folder_data_assets_native_type_system_types_config_definition_parent_ref_parent,
 *                     },
 *                 },
 *                 description: _var.registry_folder_data_assets_native_type_system_types_description,
 *                 dtType: _var.registry_folder_data_assets_native_type_system_types_dt_type,
 *                 key: _var.registry_folder_data_assets_native_type_system_types_key,
 *                 modelVersion: _var.registry_folder_data_assets_native_type_system_types_model_version,
 *                 name: _var.registry_folder_data_assets_native_type_system_types_name,
 *                 objectStatus: _var.registry_folder_data_assets_native_type_system_types_object_status,
 *                 parentRef: {
 *                     parent: _var.registry_folder_data_assets_native_type_system_types_parent_ref_parent,
 *                 },
 *                 typeSystemName: _var.registry_folder_data_assets_native_type_system_types_type_system_name,
 *             }],
 *         },
 *         objectStatus: _var.registry_folder_data_assets_object_status,
 *         objectVersion: _var.registry_folder_data_assets_object_version,
 *         properties: _var.registry_folder_data_assets_properties,
 *         registryMetadata: {
 *             aggregatorKey: _var.registry_folder_data_assets_registry_metadata_aggregator_key,
 *             createdByUserId: oci_identity_user.test_user.id,
 *             createdByUserName: oci_identity_user.test_user.name,
 *             isFavorite: _var.registry_folder_data_assets_registry_metadata_is_favorite,
 *             key: _var.registry_folder_data_assets_registry_metadata_key,
 *             labels: _var.registry_folder_data_assets_registry_metadata_labels,
 *             registryVersion: _var.registry_folder_data_assets_registry_metadata_registry_version,
 *             timeCreated: _var.registry_folder_data_assets_registry_metadata_time_created,
 *             timeUpdated: _var.registry_folder_data_assets_registry_metadata_time_updated,
 *             updatedByUserId: oci_identity_user.test_user.id,
 *             updatedByUserName: oci_identity_user.test_user.name,
 *         },
 *         type: _var.registry_folder_data_assets_type,
 *     }],
 *     description: _var.registry_folder_description,
 *     key: _var.registry_folder_key,
 *     modelType: _var.registry_folder_model_type,
 *     modelVersion: _var.registry_folder_model_version,
 *     objectStatus: _var.registry_folder_object_status,
 *     objectVersion: _var.registry_folder_object_version,
 *     parentRef: {
 *         parent: _var.registry_folder_parent_ref_parent,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * RegistryFolders can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DataConnectivity/registryFolder:RegistryFolder test_registry_folder "registries/{registryId}/folders/{folderKey}"
 * ```
 */
export class RegistryFolder extends pulumi.CustomResource {
    /**
     * Get an existing RegistryFolder resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: RegistryFolderState, opts?: pulumi.CustomResourceOptions): RegistryFolder {
        return new RegistryFolder(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataConnectivity/registryFolder:RegistryFolder';

    /**
     * Returns true if the given object is an instance of RegistryFolder.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is RegistryFolder {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === RegistryFolder.__pulumiType;
    }

    /**
     * (Updatable) List of data assets which belongs to this folder
     */
    public readonly dataAssets!: pulumi.Output<outputs.DataConnectivity.RegistryFolderDataAsset[]>;
    /**
     * (Updatable) User-defined description for the folder.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     */
    public readonly identifier!: pulumi.Output<string>;
    /**
     * (Updatable) Generated key that can be used in API calls to identify folder. On scenarios where reference to the folder is needed, a value can be passed in create.
     */
    public readonly key!: pulumi.Output<string>;
    /**
     * (Updatable) The type of the folder.
     */
    public readonly modelType!: pulumi.Output<string>;
    /**
     * (Updatable) The model version of an object.
     */
    public readonly modelVersion!: pulumi.Output<string>;
    /**
     * (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     */
    public readonly objectStatus!: pulumi.Output<number>;
    /**
     * (Updatable) The version of the object that is used to track changes in the object instance.
     */
    public readonly objectVersion!: pulumi.Output<number>;
    /**
     * (Updatable) A reference to the object's parent.
     */
    public readonly parentRef!: pulumi.Output<outputs.DataConnectivity.RegistryFolderParentRef>;
    /**
     * The registry Ocid.
     */
    public readonly registryId!: pulumi.Output<string>;

    /**
     * Create a RegistryFolder resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: RegistryFolderArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: RegistryFolderArgs | RegistryFolderState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as RegistryFolderState | undefined;
            resourceInputs["dataAssets"] = state ? state.dataAssets : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["identifier"] = state ? state.identifier : undefined;
            resourceInputs["key"] = state ? state.key : undefined;
            resourceInputs["modelType"] = state ? state.modelType : undefined;
            resourceInputs["modelVersion"] = state ? state.modelVersion : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["objectStatus"] = state ? state.objectStatus : undefined;
            resourceInputs["objectVersion"] = state ? state.objectVersion : undefined;
            resourceInputs["parentRef"] = state ? state.parentRef : undefined;
            resourceInputs["registryId"] = state ? state.registryId : undefined;
        } else {
            const args = argsOrState as RegistryFolderArgs | undefined;
            if ((!args || args.identifier === undefined) && !opts.urn) {
                throw new Error("Missing required property 'identifier'");
            }
            if ((!args || args.registryId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'registryId'");
            }
            resourceInputs["dataAssets"] = args ? args.dataAssets : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["identifier"] = args ? args.identifier : undefined;
            resourceInputs["key"] = args ? args.key : undefined;
            resourceInputs["modelType"] = args ? args.modelType : undefined;
            resourceInputs["modelVersion"] = args ? args.modelVersion : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["objectStatus"] = args ? args.objectStatus : undefined;
            resourceInputs["objectVersion"] = args ? args.objectVersion : undefined;
            resourceInputs["parentRef"] = args ? args.parentRef : undefined;
            resourceInputs["registryId"] = args ? args.registryId : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(RegistryFolder.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering RegistryFolder resources.
 */
export interface RegistryFolderState {
    /**
     * (Updatable) List of data assets which belongs to this folder
     */
    dataAssets?: pulumi.Input<pulumi.Input<inputs.DataConnectivity.RegistryFolderDataAsset>[]>;
    /**
     * (Updatable) User-defined description for the folder.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     */
    identifier?: pulumi.Input<string>;
    /**
     * (Updatable) Generated key that can be used in API calls to identify folder. On scenarios where reference to the folder is needed, a value can be passed in create.
     */
    key?: pulumi.Input<string>;
    /**
     * (Updatable) The type of the folder.
     */
    modelType?: pulumi.Input<string>;
    /**
     * (Updatable) The model version of an object.
     */
    modelVersion?: pulumi.Input<string>;
    /**
     * (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     */
    objectStatus?: pulumi.Input<number>;
    /**
     * (Updatable) The version of the object that is used to track changes in the object instance.
     */
    objectVersion?: pulumi.Input<number>;
    /**
     * (Updatable) A reference to the object's parent.
     */
    parentRef?: pulumi.Input<inputs.DataConnectivity.RegistryFolderParentRef>;
    /**
     * The registry Ocid.
     */
    registryId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a RegistryFolder resource.
 */
export interface RegistryFolderArgs {
    /**
     * (Updatable) List of data assets which belongs to this folder
     */
    dataAssets?: pulumi.Input<pulumi.Input<inputs.DataConnectivity.RegistryFolderDataAsset>[]>;
    /**
     * (Updatable) User-defined description for the folder.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     */
    identifier: pulumi.Input<string>;
    /**
     * (Updatable) Generated key that can be used in API calls to identify folder. On scenarios where reference to the folder is needed, a value can be passed in create.
     */
    key?: pulumi.Input<string>;
    /**
     * (Updatable) The type of the folder.
     */
    modelType?: pulumi.Input<string>;
    /**
     * (Updatable) The model version of an object.
     */
    modelVersion?: pulumi.Input<string>;
    /**
     * (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     */
    objectStatus?: pulumi.Input<number>;
    /**
     * (Updatable) The version of the object that is used to track changes in the object instance.
     */
    objectVersion?: pulumi.Input<number>;
    /**
     * (Updatable) A reference to the object's parent.
     */
    parentRef?: pulumi.Input<inputs.DataConnectivity.RegistryFolderParentRef>;
    /**
     * The registry Ocid.
     */
    registryId: pulumi.Input<string>;
}
