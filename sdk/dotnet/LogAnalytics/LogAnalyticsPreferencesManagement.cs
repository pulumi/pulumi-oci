// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics
{
    /// <summary>
    /// This resource provides the Log Analytics Preferences Management resource in Oracle Cloud Infrastructure Log Analytics service.
    /// 
    /// Updates the tenant preferences. Currently, only "DEFAULT_HOMEPAGE" is supported.
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
    ///         var testLogAnalyticsPreferencesManagement = new Oci.LogAnalytics.LogAnalyticsPreferencesManagement("testLogAnalyticsPreferencesManagement", new Oci.LogAnalytics.LogAnalyticsPreferencesManagementArgs
    ///         {
    ///             Namespace = @var.Log_analytics_preferences_management_namespace,
    ///             Items = 
    ///             {
    ///                 new Oci.LogAnalytics.Inputs.LogAnalyticsPreferencesManagementItemArgs
    ///                 {
    ///                     Name = @var.Log_analytics_preferences_management_items_name,
    ///                     Value = @var.Log_analytics_preferences_management_items_value,
    ///                 },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for LogAnalyticsPreferencesManagement
    /// </summary>
    [OciResourceType("oci:LogAnalytics/logAnalyticsPreferencesManagement:LogAnalyticsPreferencesManagement")]
    public partial class LogAnalyticsPreferencesManagement : Pulumi.CustomResource
    {
        /// <summary>
        /// An array of tenant preference details.
        /// </summary>
        [Output("items")]
        public Output<ImmutableArray<Outputs.LogAnalyticsPreferencesManagementItem>> Items { get; private set; } = null!;

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Output("namespace")]
        public Output<string> Namespace { get; private set; } = null!;


        /// <summary>
        /// Create a LogAnalyticsPreferencesManagement resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public LogAnalyticsPreferencesManagement(string name, LogAnalyticsPreferencesManagementArgs args, CustomResourceOptions? options = null)
            : base("oci:LogAnalytics/logAnalyticsPreferencesManagement:LogAnalyticsPreferencesManagement", name, args ?? new LogAnalyticsPreferencesManagementArgs(), MakeResourceOptions(options, ""))
        {
        }

        private LogAnalyticsPreferencesManagement(string name, Input<string> id, LogAnalyticsPreferencesManagementState? state = null, CustomResourceOptions? options = null)
            : base("oci:LogAnalytics/logAnalyticsPreferencesManagement:LogAnalyticsPreferencesManagement", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing LogAnalyticsPreferencesManagement resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static LogAnalyticsPreferencesManagement Get(string name, Input<string> id, LogAnalyticsPreferencesManagementState? state = null, CustomResourceOptions? options = null)
        {
            return new LogAnalyticsPreferencesManagement(name, id, state, options);
        }
    }

    public sealed class LogAnalyticsPreferencesManagementArgs : Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.LogAnalyticsPreferencesManagementItemArgs>? _items;

        /// <summary>
        /// An array of tenant preference details.
        /// </summary>
        public InputList<Inputs.LogAnalyticsPreferencesManagementItemArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.LogAnalyticsPreferencesManagementItemArgs>());
            set => _items = value;
        }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        public LogAnalyticsPreferencesManagementArgs()
        {
        }
    }

    public sealed class LogAnalyticsPreferencesManagementState : Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.LogAnalyticsPreferencesManagementItemGetArgs>? _items;

        /// <summary>
        /// An array of tenant preference details.
        /// </summary>
        public InputList<Inputs.LogAnalyticsPreferencesManagementItemGetArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.LogAnalyticsPreferencesManagementItemGetArgs>());
            set => _items = value;
        }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace")]
        public Input<string>? Namespace { get; set; }

        public LogAnalyticsPreferencesManagementState()
        {
        }
    }
}
