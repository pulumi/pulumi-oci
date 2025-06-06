// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring
{
    /// <summary>
    /// This resource provides the Metric Extension Metric Extension On Given Resources Management resource in Oracle Cloud Infrastructure Stack Monitoring service.
    /// 
    /// Submits a request to enable matching metric extension Id for the given Resource IDs
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
    ///     var testMetricExtensionMetricExtensionOnGivenResourcesManagement = new Oci.StackMonitoring.MetricExtensionMetricExtensionOnGivenResourcesManagement("test_metric_extension_metric_extension_on_given_resources_management", new()
    ///     {
    ///         MetricExtensionId = testMetricExtension.Id,
    ///         ResourceIds = metricExtensionMetricExtensionOnGivenResourcesManagementResourceIds[0],
    ///         EnableMetricExtensionOnGivenResources = enableMetricExtensionOnGivenResources,
    ///     });
    /// 
    /// });
    /// ```
    /// </summary>
    [OciResourceType("oci:StackMonitoring/metricExtensionMetricExtensionOnGivenResourcesManagement:MetricExtensionMetricExtensionOnGivenResourcesManagement")]
    public partial class MetricExtensionMetricExtensionOnGivenResourcesManagement : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("enableMetricExtensionOnGivenResources")]
        public Output<bool> EnableMetricExtensionOnGivenResources { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
        /// </summary>
        [Output("metricExtensionId")]
        public Output<string> MetricExtensionId { get; private set; } = null!;

        /// <summary>
        /// List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
        /// </summary>
        [Output("resourceIds")]
        public Output<string> ResourceIds { get; private set; } = null!;


        /// <summary>
        /// Create a MetricExtensionMetricExtensionOnGivenResourcesManagement resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public MetricExtensionMetricExtensionOnGivenResourcesManagement(string name, MetricExtensionMetricExtensionOnGivenResourcesManagementArgs args, CustomResourceOptions? options = null)
            : base("oci:StackMonitoring/metricExtensionMetricExtensionOnGivenResourcesManagement:MetricExtensionMetricExtensionOnGivenResourcesManagement", name, args ?? new MetricExtensionMetricExtensionOnGivenResourcesManagementArgs(), MakeResourceOptions(options, ""))
        {
        }

        private MetricExtensionMetricExtensionOnGivenResourcesManagement(string name, Input<string> id, MetricExtensionMetricExtensionOnGivenResourcesManagementState? state = null, CustomResourceOptions? options = null)
            : base("oci:StackMonitoring/metricExtensionMetricExtensionOnGivenResourcesManagement:MetricExtensionMetricExtensionOnGivenResourcesManagement", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing MetricExtensionMetricExtensionOnGivenResourcesManagement resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static MetricExtensionMetricExtensionOnGivenResourcesManagement Get(string name, Input<string> id, MetricExtensionMetricExtensionOnGivenResourcesManagementState? state = null, CustomResourceOptions? options = null)
        {
            return new MetricExtensionMetricExtensionOnGivenResourcesManagement(name, id, state, options);
        }
    }

    public sealed class MetricExtensionMetricExtensionOnGivenResourcesManagementArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("enableMetricExtensionOnGivenResources", required: true)]
        public Input<bool> EnableMetricExtensionOnGivenResources { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
        /// </summary>
        [Input("metricExtensionId", required: true)]
        public Input<string> MetricExtensionId { get; set; } = null!;

        /// <summary>
        /// List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
        /// </summary>
        [Input("resourceIds", required: true)]
        public Input<string> ResourceIds { get; set; } = null!;

        public MetricExtensionMetricExtensionOnGivenResourcesManagementArgs()
        {
        }
        public static new MetricExtensionMetricExtensionOnGivenResourcesManagementArgs Empty => new MetricExtensionMetricExtensionOnGivenResourcesManagementArgs();
    }

    public sealed class MetricExtensionMetricExtensionOnGivenResourcesManagementState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("enableMetricExtensionOnGivenResources")]
        public Input<bool>? EnableMetricExtensionOnGivenResources { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
        /// </summary>
        [Input("metricExtensionId")]
        public Input<string>? MetricExtensionId { get; set; }

        /// <summary>
        /// List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
        /// </summary>
        [Input("resourceIds")]
        public Input<string>? ResourceIds { get; set; }

        public MetricExtensionMetricExtensionOnGivenResourcesManagementState()
        {
        }
        public static new MetricExtensionMetricExtensionOnGivenResourcesManagementState Empty => new MetricExtensionMetricExtensionOnGivenResourcesManagementState();
    }
}
