// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms
{
    public static class GetPluginErrors
    {
        /// <summary>
        /// This data source provides the list of Plugin Errors in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Returns a list of plugin errors that describe all detected errors.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testPluginErrors = Oci.Jms.GetPluginErrors.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = pluginErrorCompartmentIdInSubtree,
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         TimeFirstSeenGreaterThanOrEqualTo = pluginErrorTimeFirstSeenGreaterThanOrEqualTo,
        ///         TimeFirstSeenLessThanOrEqualTo = pluginErrorTimeFirstSeenLessThanOrEqualTo,
        ///         TimeLastSeenGreaterThanOrEqualTo = pluginErrorTimeLastSeenGreaterThanOrEqualTo,
        ///         TimeLastSeenLessThanOrEqualTo = pluginErrorTimeLastSeenLessThanOrEqualTo,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetPluginErrorsResult> InvokeAsync(GetPluginErrorsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPluginErrorsResult>("oci:Jms/getPluginErrors:getPluginErrors", args ?? new GetPluginErrorsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Plugin Errors in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Returns a list of plugin errors that describe all detected errors.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testPluginErrors = Oci.Jms.GetPluginErrors.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = pluginErrorCompartmentIdInSubtree,
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         TimeFirstSeenGreaterThanOrEqualTo = pluginErrorTimeFirstSeenGreaterThanOrEqualTo,
        ///         TimeFirstSeenLessThanOrEqualTo = pluginErrorTimeFirstSeenLessThanOrEqualTo,
        ///         TimeLastSeenGreaterThanOrEqualTo = pluginErrorTimeLastSeenGreaterThanOrEqualTo,
        ///         TimeLastSeenLessThanOrEqualTo = pluginErrorTimeLastSeenLessThanOrEqualTo,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPluginErrorsResult> Invoke(GetPluginErrorsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPluginErrorsResult>("oci:Jms/getPluginErrors:getPluginErrors", args ?? new GetPluginErrorsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Plugin Errors in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Returns a list of plugin errors that describe all detected errors.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testPluginErrors = Oci.Jms.GetPluginErrors.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = pluginErrorCompartmentIdInSubtree,
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         TimeFirstSeenGreaterThanOrEqualTo = pluginErrorTimeFirstSeenGreaterThanOrEqualTo,
        ///         TimeFirstSeenLessThanOrEqualTo = pluginErrorTimeFirstSeenLessThanOrEqualTo,
        ///         TimeLastSeenGreaterThanOrEqualTo = pluginErrorTimeLastSeenGreaterThanOrEqualTo,
        ///         TimeLastSeenLessThanOrEqualTo = pluginErrorTimeLastSeenLessThanOrEqualTo,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPluginErrorsResult> Invoke(GetPluginErrorsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetPluginErrorsResult>("oci:Jms/getPluginErrors:getPluginErrors", args ?? new GetPluginErrorsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPluginErrorsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// Flag to determine whether the info should be gathered only in the compartment or in the compartment and its subcompartments.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private List<Inputs.GetPluginErrorsFilterArgs>? _filters;
        public List<Inputs.GetPluginErrorsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetPluginErrorsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The Fleet-unique identifier of the managed instance.
        /// </summary>
        [Input("managedInstanceId")]
        public string? ManagedInstanceId { get; set; }

        /// <summary>
        /// If specified, only errors with a first seen time later than this parameter will be included in the search (formatted according to RFC3339).
        /// </summary>
        [Input("timeFirstSeenGreaterThanOrEqualTo")]
        public string? TimeFirstSeenGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// If specified, only errors with a first seen time earlier than this parameter will be included in the search (formatted according to RFC3339).
        /// </summary>
        [Input("timeFirstSeenLessThanOrEqualTo")]
        public string? TimeFirstSeenLessThanOrEqualTo { get; set; }

        /// <summary>
        /// If specified, only errors with a last seen time later than this parameter will be included in the search (formatted according to RFC3339).
        /// </summary>
        [Input("timeLastSeenGreaterThanOrEqualTo")]
        public string? TimeLastSeenGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// If specified, only errors with a last seen time earlier than this parameter will be included in the search (formatted according to RFC3339).
        /// </summary>
        [Input("timeLastSeenLessThanOrEqualTo")]
        public string? TimeLastSeenLessThanOrEqualTo { get; set; }

        public GetPluginErrorsArgs()
        {
        }
        public static new GetPluginErrorsArgs Empty => new GetPluginErrorsArgs();
    }

    public sealed class GetPluginErrorsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// Flag to determine whether the info should be gathered only in the compartment or in the compartment and its subcompartments.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public Input<bool>? CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetPluginErrorsFilterInputArgs>? _filters;
        public InputList<Inputs.GetPluginErrorsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetPluginErrorsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The Fleet-unique identifier of the managed instance.
        /// </summary>
        [Input("managedInstanceId")]
        public Input<string>? ManagedInstanceId { get; set; }

        /// <summary>
        /// If specified, only errors with a first seen time later than this parameter will be included in the search (formatted according to RFC3339).
        /// </summary>
        [Input("timeFirstSeenGreaterThanOrEqualTo")]
        public Input<string>? TimeFirstSeenGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// If specified, only errors with a first seen time earlier than this parameter will be included in the search (formatted according to RFC3339).
        /// </summary>
        [Input("timeFirstSeenLessThanOrEqualTo")]
        public Input<string>? TimeFirstSeenLessThanOrEqualTo { get; set; }

        /// <summary>
        /// If specified, only errors with a last seen time later than this parameter will be included in the search (formatted according to RFC3339).
        /// </summary>
        [Input("timeLastSeenGreaterThanOrEqualTo")]
        public Input<string>? TimeLastSeenGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// If specified, only errors with a last seen time earlier than this parameter will be included in the search (formatted according to RFC3339).
        /// </summary>
        [Input("timeLastSeenLessThanOrEqualTo")]
        public Input<string>? TimeLastSeenLessThanOrEqualTo { get; set; }

        public GetPluginErrorsInvokeArgs()
        {
        }
        public static new GetPluginErrorsInvokeArgs Empty => new GetPluginErrorsInvokeArgs();
    }


    [OutputType]
    public sealed class GetPluginErrorsResult
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        public readonly string? CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        public readonly ImmutableArray<Outputs.GetPluginErrorsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Instance running the plugin.
        /// </summary>
        public readonly string? ManagedInstanceId;
        /// <summary>
        /// The list of plugin_error_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPluginErrorsPluginErrorCollectionResult> PluginErrorCollections;
        public readonly string? TimeFirstSeenGreaterThanOrEqualTo;
        public readonly string? TimeFirstSeenLessThanOrEqualTo;
        public readonly string? TimeLastSeenGreaterThanOrEqualTo;
        public readonly string? TimeLastSeenLessThanOrEqualTo;

        [OutputConstructor]
        private GetPluginErrorsResult(
            string? compartmentId,

            bool? compartmentIdInSubtree,

            ImmutableArray<Outputs.GetPluginErrorsFilterResult> filters,

            string id,

            string? managedInstanceId,

            ImmutableArray<Outputs.GetPluginErrorsPluginErrorCollectionResult> pluginErrorCollections,

            string? timeFirstSeenGreaterThanOrEqualTo,

            string? timeFirstSeenLessThanOrEqualTo,

            string? timeLastSeenGreaterThanOrEqualTo,

            string? timeLastSeenLessThanOrEqualTo)
        {
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            Filters = filters;
            Id = id;
            ManagedInstanceId = managedInstanceId;
            PluginErrorCollections = pluginErrorCollections;
            TimeFirstSeenGreaterThanOrEqualTo = timeFirstSeenGreaterThanOrEqualTo;
            TimeFirstSeenLessThanOrEqualTo = timeFirstSeenLessThanOrEqualTo;
            TimeLastSeenGreaterThanOrEqualTo = timeLastSeenGreaterThanOrEqualTo;
            TimeLastSeenLessThanOrEqualTo = timeLastSeenLessThanOrEqualTo;
        }
    }
}
