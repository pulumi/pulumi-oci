// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    /// <summary>
    /// This resource provides the Sensitive Data Model resource in Oracle Cloud Infrastructure Data Safe service.
    /// 
    /// Creates a new sensitive data model. If schemas and sensitive types are provided, it automatically runs data discovery
    /// and adds the discovered columns to the sensitive data model. Otherwise, it creates an empty sensitive data model
    /// that can be updated later.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testSensitiveDataModel = new Oci.DataSafe.SensitiveDataModel("testSensitiveDataModel", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         TargetId = oci_cloud_guard_target.Test_target.Id,
    ///         AppSuiteName = @var.Sensitive_data_model_app_suite_name,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         Description = @var.Sensitive_data_model_description,
    ///         DisplayName = @var.Sensitive_data_model_display_name,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         IsAppDefinedRelationDiscoveryEnabled = @var.Sensitive_data_model_is_app_defined_relation_discovery_enabled,
    ///         IsIncludeAllSchemas = @var.Sensitive_data_model_is_include_all_schemas,
    ///         IsIncludeAllSensitiveTypes = @var.Sensitive_data_model_is_include_all_sensitive_types,
    ///         IsSampleDataCollectionEnabled = @var.Sensitive_data_model_is_sample_data_collection_enabled,
    ///         SchemasForDiscoveries = @var.Sensitive_data_model_schemas_for_discovery,
    ///         SensitiveTypeIdsForDiscoveries = @var.Sensitive_data_model_sensitive_type_ids_for_discovery,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// SensitiveDataModels can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:DataSafe/sensitiveDataModel:SensitiveDataModel test_sensitive_data_model "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DataSafe/sensitiveDataModel:SensitiveDataModel")]
    public partial class SensitiveDataModel : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The application suite name identifying a collection of applications. It's useful only if maintaining a sensitive data model for a suite of applications.
        /// </summary>
        [Output("appSuiteName")]
        public Output<string> AppSuiteName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment where the sensitive data model should be created.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The description of the sensitive data model.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The display name of the sensitive data model. The name does not have to be unique, and it's changeable.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Indicates if data discovery jobs should identify potential application-level (non-dictionary) referential relationships between columns. Note that data discovery automatically identifies and adds database-level (dictionary-defined) relationships. This option helps identify application-level relationships that are not defined in the database dictionary, which in turn, helps identify additional sensitive columns and preserve referential integrity during data masking. It's disabled by default and should be used only if there is a need to identify application-level relationships.
        /// </summary>
        [Output("isAppDefinedRelationDiscoveryEnabled")]
        public Output<bool> IsAppDefinedRelationDiscoveryEnabled { get; private set; } = null!;

        /// <summary>
        /// Indicates if all the schemas in the associated target database should be scanned by data discovery jobs. If it's set to true, the schemasForDiscovery attribute is ignored and all schemas are used for data discovery.
        /// </summary>
        [Output("isIncludeAllSchemas")]
        public Output<bool> IsIncludeAllSchemas { get; private set; } = null!;

        /// <summary>
        /// Indicates if all the existing sensitive types should be used by data discovery jobs. If it's set to true, the sensitiveTypeIdsForDiscovery attribute is ignored and all sensitive types are used for data discovery.
        /// </summary>
        [Output("isIncludeAllSensitiveTypes")]
        public Output<bool> IsIncludeAllSensitiveTypes { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Indicates if data discovery jobs should collect and store sample data values for the discovered columns. Sample data helps review the discovered columns and ensure that they actually contain sensitive data. As it collects original data from the target database, it's disabled by default and should be used only if it's acceptable to store sample data in Data Safe's repository in Oracle Cloud. Note that sample data values are not collected for columns with the following data types: LONG, LOB, RAW, XMLTYPE and BFILE.
        /// </summary>
        [Output("isSampleDataCollectionEnabled")]
        public Output<bool> IsSampleDataCollectionEnabled { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The schemas to be scanned by data discovery jobs.
        /// </summary>
        [Output("schemasForDiscoveries")]
        public Output<ImmutableArray<string>> SchemasForDiscoveries { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCIDs of the sensitive types to be used by data discovery jobs. If OCID of a sensitive category is provided, all its child sensitive types are used for data discovery.
        /// </summary>
        [Output("sensitiveTypeIdsForDiscoveries")]
        public Output<ImmutableArray<string>> SensitiveTypeIdsForDiscoveries { get; private set; } = null!;

        /// <summary>
        /// The current state of the sensitive data model.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the reference target database to be associated with the sensitive data model. All operations such as performing data discovery and adding columns manually are done in the context of the associated target database.
        /// </summary>
        [Output("targetId")]
        public Output<string> TargetId { get; private set; } = null!;

        /// <summary>
        /// The date and time the sensitive data model was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the sensitive data model was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a SensitiveDataModel resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public SensitiveDataModel(string name, SensitiveDataModelArgs args, CustomResourceOptions? options = null)
            : base("oci:DataSafe/sensitiveDataModel:SensitiveDataModel", name, args ?? new SensitiveDataModelArgs(), MakeResourceOptions(options, ""))
        {
        }

        private SensitiveDataModel(string name, Input<string> id, SensitiveDataModelState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataSafe/sensitiveDataModel:SensitiveDataModel", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing SensitiveDataModel resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static SensitiveDataModel Get(string name, Input<string> id, SensitiveDataModelState? state = null, CustomResourceOptions? options = null)
        {
            return new SensitiveDataModel(name, id, state, options);
        }
    }

    public sealed class SensitiveDataModelArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The application suite name identifying a collection of applications. It's useful only if maintaining a sensitive data model for a suite of applications.
        /// </summary>
        [Input("appSuiteName")]
        public Input<string>? AppSuiteName { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment where the sensitive data model should be created.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description of the sensitive data model.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name of the sensitive data model. The name does not have to be unique, and it's changeable.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Indicates if data discovery jobs should identify potential application-level (non-dictionary) referential relationships between columns. Note that data discovery automatically identifies and adds database-level (dictionary-defined) relationships. This option helps identify application-level relationships that are not defined in the database dictionary, which in turn, helps identify additional sensitive columns and preserve referential integrity during data masking. It's disabled by default and should be used only if there is a need to identify application-level relationships.
        /// </summary>
        [Input("isAppDefinedRelationDiscoveryEnabled")]
        public Input<bool>? IsAppDefinedRelationDiscoveryEnabled { get; set; }

        /// <summary>
        /// Indicates if all the schemas in the associated target database should be scanned by data discovery jobs. If it's set to true, the schemasForDiscovery attribute is ignored and all schemas are used for data discovery.
        /// </summary>
        [Input("isIncludeAllSchemas")]
        public Input<bool>? IsIncludeAllSchemas { get; set; }

        /// <summary>
        /// Indicates if all the existing sensitive types should be used by data discovery jobs. If it's set to true, the sensitiveTypeIdsForDiscovery attribute is ignored and all sensitive types are used for data discovery.
        /// </summary>
        [Input("isIncludeAllSensitiveTypes")]
        public Input<bool>? IsIncludeAllSensitiveTypes { get; set; }

        /// <summary>
        /// (Updatable) Indicates if data discovery jobs should collect and store sample data values for the discovered columns. Sample data helps review the discovered columns and ensure that they actually contain sensitive data. As it collects original data from the target database, it's disabled by default and should be used only if it's acceptable to store sample data in Data Safe's repository in Oracle Cloud. Note that sample data values are not collected for columns with the following data types: LONG, LOB, RAW, XMLTYPE and BFILE.
        /// </summary>
        [Input("isSampleDataCollectionEnabled")]
        public Input<bool>? IsSampleDataCollectionEnabled { get; set; }

        [Input("schemasForDiscoveries")]
        private InputList<string>? _schemasForDiscoveries;

        /// <summary>
        /// (Updatable) The schemas to be scanned by data discovery jobs.
        /// </summary>
        public InputList<string> SchemasForDiscoveries
        {
            get => _schemasForDiscoveries ?? (_schemasForDiscoveries = new InputList<string>());
            set => _schemasForDiscoveries = value;
        }

        [Input("sensitiveTypeIdsForDiscoveries")]
        private InputList<string>? _sensitiveTypeIdsForDiscoveries;

        /// <summary>
        /// (Updatable) The OCIDs of the sensitive types to be used by data discovery jobs. If OCID of a sensitive category is provided, all its child sensitive types are used for data discovery.
        /// </summary>
        public InputList<string> SensitiveTypeIdsForDiscoveries
        {
            get => _sensitiveTypeIdsForDiscoveries ?? (_sensitiveTypeIdsForDiscoveries = new InputList<string>());
            set => _sensitiveTypeIdsForDiscoveries = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the reference target database to be associated with the sensitive data model. All operations such as performing data discovery and adding columns manually are done in the context of the associated target database.
        /// </summary>
        [Input("targetId", required: true)]
        public Input<string> TargetId { get; set; } = null!;

        public SensitiveDataModelArgs()
        {
        }
        public static new SensitiveDataModelArgs Empty => new SensitiveDataModelArgs();
    }

    public sealed class SensitiveDataModelState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The application suite name identifying a collection of applications. It's useful only if maintaining a sensitive data model for a suite of applications.
        /// </summary>
        [Input("appSuiteName")]
        public Input<string>? AppSuiteName { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment where the sensitive data model should be created.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description of the sensitive data model.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name of the sensitive data model. The name does not have to be unique, and it's changeable.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Indicates if data discovery jobs should identify potential application-level (non-dictionary) referential relationships between columns. Note that data discovery automatically identifies and adds database-level (dictionary-defined) relationships. This option helps identify application-level relationships that are not defined in the database dictionary, which in turn, helps identify additional sensitive columns and preserve referential integrity during data masking. It's disabled by default and should be used only if there is a need to identify application-level relationships.
        /// </summary>
        [Input("isAppDefinedRelationDiscoveryEnabled")]
        public Input<bool>? IsAppDefinedRelationDiscoveryEnabled { get; set; }

        /// <summary>
        /// Indicates if all the schemas in the associated target database should be scanned by data discovery jobs. If it's set to true, the schemasForDiscovery attribute is ignored and all schemas are used for data discovery.
        /// </summary>
        [Input("isIncludeAllSchemas")]
        public Input<bool>? IsIncludeAllSchemas { get; set; }

        /// <summary>
        /// Indicates if all the existing sensitive types should be used by data discovery jobs. If it's set to true, the sensitiveTypeIdsForDiscovery attribute is ignored and all sensitive types are used for data discovery.
        /// </summary>
        [Input("isIncludeAllSensitiveTypes")]
        public Input<bool>? IsIncludeAllSensitiveTypes { get; set; }

        /// <summary>
        /// (Updatable) Indicates if data discovery jobs should collect and store sample data values for the discovered columns. Sample data helps review the discovered columns and ensure that they actually contain sensitive data. As it collects original data from the target database, it's disabled by default and should be used only if it's acceptable to store sample data in Data Safe's repository in Oracle Cloud. Note that sample data values are not collected for columns with the following data types: LONG, LOB, RAW, XMLTYPE and BFILE.
        /// </summary>
        [Input("isSampleDataCollectionEnabled")]
        public Input<bool>? IsSampleDataCollectionEnabled { get; set; }

        [Input("schemasForDiscoveries")]
        private InputList<string>? _schemasForDiscoveries;

        /// <summary>
        /// (Updatable) The schemas to be scanned by data discovery jobs.
        /// </summary>
        public InputList<string> SchemasForDiscoveries
        {
            get => _schemasForDiscoveries ?? (_schemasForDiscoveries = new InputList<string>());
            set => _schemasForDiscoveries = value;
        }

        [Input("sensitiveTypeIdsForDiscoveries")]
        private InputList<string>? _sensitiveTypeIdsForDiscoveries;

        /// <summary>
        /// (Updatable) The OCIDs of the sensitive types to be used by data discovery jobs. If OCID of a sensitive category is provided, all its child sensitive types are used for data discovery.
        /// </summary>
        public InputList<string> SensitiveTypeIdsForDiscoveries
        {
            get => _sensitiveTypeIdsForDiscoveries ?? (_sensitiveTypeIdsForDiscoveries = new InputList<string>());
            set => _sensitiveTypeIdsForDiscoveries = value;
        }

        /// <summary>
        /// The current state of the sensitive data model.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the reference target database to be associated with the sensitive data model. All operations such as performing data discovery and adding columns manually are done in the context of the associated target database.
        /// </summary>
        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        /// <summary>
        /// The date and time the sensitive data model was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the sensitive data model was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public SensitiveDataModelState()
        {
        }
        public static new SensitiveDataModelState Empty => new SensitiveDataModelState();
    }
}