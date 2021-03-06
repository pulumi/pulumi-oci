// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging
{
    /// <summary>
    /// This resource provides the Unified Agent Configuration resource in Oracle Cloud Infrastructure Logging service.
    /// 
    /// Create unified agent configuration registration.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testUnifiedAgentConfiguration = new Oci.Logging.UnifiedAgentConfiguration("testUnifiedAgentConfiguration", new Oci.Logging.UnifiedAgentConfigurationArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             IsEnabled = @var.Unified_agent_configuration_is_enabled,
    ///             Description = @var.Unified_agent_configuration_description,
    ///             DisplayName = @var.Unified_agent_configuration_display_name,
    ///             ServiceConfiguration = new Oci.Logging.Inputs.UnifiedAgentConfigurationServiceConfigurationArgs
    ///             {
    ///                 ConfigurationType = @var.Unified_agent_configuration_service_configuration_configuration_type,
    ///                 Destination = new Oci.Logging.Inputs.UnifiedAgentConfigurationServiceConfigurationDestinationArgs
    ///                 {
    ///                     LogObjectId = oci_objectstorage_object.Test_object.Id,
    ///                 },
    ///                 Sources = 
    ///                 {
    ///                     new Oci.Logging.Inputs.UnifiedAgentConfigurationServiceConfigurationSourceArgs
    ///                     {
    ///                         SourceType = @var.Unified_agent_configuration_service_configuration_sources_source_type,
    ///                         Channels = @var.Unified_agent_configuration_service_configuration_sources_channels,
    ///                         Name = @var.Unified_agent_configuration_service_configuration_sources_name,
    ///                         Parser = new Oci.Logging.Inputs.UnifiedAgentConfigurationServiceConfigurationSourceParserArgs
    ///                         {
    ///                             ParserType = @var.Unified_agent_configuration_service_configuration_sources_parser_parser_type,
    ///                             Delimiter = @var.Unified_agent_configuration_service_configuration_sources_parser_delimiter,
    ///                             Expression = @var.Unified_agent_configuration_service_configuration_sources_parser_expression,
    ///                             FieldTimeKey = @var.Unified_agent_configuration_service_configuration_sources_parser_field_time_key,
    ///                             Formats = @var.Unified_agent_configuration_service_configuration_sources_parser_format,
    ///                             FormatFirstline = @var.Unified_agent_configuration_service_configuration_sources_parser_format_firstline,
    ///                             GrokFailureKey = @var.Unified_agent_configuration_service_configuration_sources_parser_grok_failure_key,
    ///                             GrokNameKey = @var.Unified_agent_configuration_service_configuration_sources_parser_grok_name_key,
    ///                             IsEstimateCurrentEvent = @var.Unified_agent_configuration_service_configuration_sources_parser_is_estimate_current_event,
    ///                             IsKeepTimeKey = @var.Unified_agent_configuration_service_configuration_sources_parser_is_keep_time_key,
    ///                             IsNullEmptyString = @var.Unified_agent_configuration_service_configuration_sources_parser_is_null_empty_string,
    ///                             IsSupportColonlessIdent = @var.Unified_agent_configuration_service_configuration_sources_parser_is_support_colonless_ident,
    ///                             IsWithPriority = @var.Unified_agent_configuration_service_configuration_sources_parser_is_with_priority,
    ///                             Keys = @var.Unified_agent_configuration_service_configuration_sources_parser_keys,
    ///                             MessageFormat = @var.Unified_agent_configuration_service_configuration_sources_parser_message_format,
    ///                             MessageKey = @var.Unified_agent_configuration_service_configuration_sources_parser_message_key,
    ///                             MultiLineStartRegexp = @var.Unified_agent_configuration_service_configuration_sources_parser_multi_line_start_regexp,
    ///                             NullValuePattern = @var.Unified_agent_configuration_service_configuration_sources_parser_null_value_pattern,
    ///                             Patterns = 
    ///                             {
    ///                                 new Oci.Logging.Inputs.UnifiedAgentConfigurationServiceConfigurationSourceParserPatternArgs
    ///                                 {
    ///                                     FieldTimeFormat = @var.Unified_agent_configuration_service_configuration_sources_parser_patterns_field_time_format,
    ///                                     FieldTimeKey = @var.Unified_agent_configuration_service_configuration_sources_parser_patterns_field_time_key,
    ///                                     FieldTimeZone = @var.Unified_agent_configuration_service_configuration_sources_parser_patterns_field_time_zone,
    ///                                     Name = @var.Unified_agent_configuration_service_configuration_sources_parser_patterns_name,
    ///                                     Pattern = @var.Unified_agent_configuration_service_configuration_sources_parser_patterns_pattern,
    ///                                 },
    ///                             },
    ///                             Rfc5424timeFormat = @var.Unified_agent_configuration_service_configuration_sources_parser_rfc5424time_format,
    ///                             SyslogParserType = @var.Unified_agent_configuration_service_configuration_sources_parser_syslog_parser_type,
    ///                             TimeFormat = @var.Unified_agent_configuration_service_configuration_sources_parser_time_format,
    ///                             TimeType = @var.Unified_agent_configuration_service_configuration_sources_parser_time_type,
    ///                             TimeoutInMilliseconds = @var.Unified_agent_configuration_service_configuration_sources_parser_timeout_in_milliseconds,
    ///                             Types = @var.Unified_agent_configuration_service_configuration_sources_parser_types,
    ///                         },
    ///                         Paths = @var.Unified_agent_configuration_service_configuration_sources_paths,
    ///                     },
    ///                 },
    ///             },
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///             GroupAssociation = new Oci.Logging.Inputs.UnifiedAgentConfigurationGroupAssociationArgs
    ///             {
    ///                 GroupLists = @var.Unified_agent_configuration_group_association_group_list,
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// UnifiedAgentConfigurations can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Logging/unifiedAgentConfiguration:UnifiedAgentConfiguration test_unified_agent_configuration "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Logging/unifiedAgentConfiguration:UnifiedAgentConfiguration")]
    public partial class UnifiedAgentConfiguration : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that the resource belongs to.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// State of unified agent service configuration.
        /// </summary>
        [Output("configurationState")]
        public Output<string> ConfigurationState { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Description for this resource.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Groups using the configuration.
        /// </summary>
        [Output("groupAssociation")]
        public Output<Outputs.UnifiedAgentConfigurationGroupAssociation> GroupAssociation { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether or not this resource is currently enabled.
        /// </summary>
        [Output("isEnabled")]
        public Output<bool> IsEnabled { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Top level Unified Agent service configuration object.
        /// </summary>
        [Output("serviceConfiguration")]
        public Output<Outputs.UnifiedAgentConfigurationServiceConfiguration> ServiceConfiguration { get; private set; } = null!;

        /// <summary>
        /// The pipeline state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Time the resource was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// Time the resource was last modified.
        /// </summary>
        [Output("timeLastModified")]
        public Output<string> TimeLastModified { get; private set; } = null!;


        /// <summary>
        /// Create a UnifiedAgentConfiguration resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public UnifiedAgentConfiguration(string name, UnifiedAgentConfigurationArgs args, CustomResourceOptions? options = null)
            : base("oci:Logging/unifiedAgentConfiguration:UnifiedAgentConfiguration", name, args ?? new UnifiedAgentConfigurationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private UnifiedAgentConfiguration(string name, Input<string> id, UnifiedAgentConfigurationState? state = null, CustomResourceOptions? options = null)
            : base("oci:Logging/unifiedAgentConfiguration:UnifiedAgentConfiguration", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing UnifiedAgentConfiguration resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static UnifiedAgentConfiguration Get(string name, Input<string> id, UnifiedAgentConfigurationState? state = null, CustomResourceOptions? options = null)
        {
            return new UnifiedAgentConfiguration(name, id, state, options);
        }
    }

    public sealed class UnifiedAgentConfigurationArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that the resource belongs to.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description for this resource.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Groups using the configuration.
        /// </summary>
        [Input("groupAssociation")]
        public Input<Inputs.UnifiedAgentConfigurationGroupAssociationArgs>? GroupAssociation { get; set; }

        /// <summary>
        /// (Updatable) Whether or not this resource is currently enabled.
        /// </summary>
        [Input("isEnabled", required: true)]
        public Input<bool> IsEnabled { get; set; } = null!;

        /// <summary>
        /// (Updatable) Top level Unified Agent service configuration object.
        /// </summary>
        [Input("serviceConfiguration", required: true)]
        public Input<Inputs.UnifiedAgentConfigurationServiceConfigurationArgs> ServiceConfiguration { get; set; } = null!;

        public UnifiedAgentConfigurationArgs()
        {
        }
    }

    public sealed class UnifiedAgentConfigurationState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that the resource belongs to.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// State of unified agent service configuration.
        /// </summary>
        [Input("configurationState")]
        public Input<string>? ConfigurationState { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description for this resource.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Groups using the configuration.
        /// </summary>
        [Input("groupAssociation")]
        public Input<Inputs.UnifiedAgentConfigurationGroupAssociationGetArgs>? GroupAssociation { get; set; }

        /// <summary>
        /// (Updatable) Whether or not this resource is currently enabled.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// (Updatable) Top level Unified Agent service configuration object.
        /// </summary>
        [Input("serviceConfiguration")]
        public Input<Inputs.UnifiedAgentConfigurationServiceConfigurationGetArgs>? ServiceConfiguration { get; set; }

        /// <summary>
        /// The pipeline state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Time the resource was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Time the resource was last modified.
        /// </summary>
        [Input("timeLastModified")]
        public Input<string>? TimeLastModified { get; set; }

        public UnifiedAgentConfigurationState()
        {
        }
    }
}
