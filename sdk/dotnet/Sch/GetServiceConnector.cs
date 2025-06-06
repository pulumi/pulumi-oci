// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Sch
{
    public static class GetServiceConnector
    {
        /// <summary>
        /// This data source provides details about a specific Service Connector resource in Oracle Cloud Infrastructure Service Connector Hub service.
        /// 
        /// Gets the specified connector's configuration information.
        /// For more information, see
        /// [Getting a Connector](https://docs.cloud.oracle.com/iaas/Content/connector-hub/get-service-connector.htm).
        /// 
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
        ///     var testServiceConnector = Oci.Sch.GetServiceConnector.Invoke(new()
        ///     {
        ///         ServiceConnectorId = testServiceConnectorOciSchServiceConnector.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetServiceConnectorResult> InvokeAsync(GetServiceConnectorArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetServiceConnectorResult>("oci:Sch/getServiceConnector:getServiceConnector", args ?? new GetServiceConnectorArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Service Connector resource in Oracle Cloud Infrastructure Service Connector Hub service.
        /// 
        /// Gets the specified connector's configuration information.
        /// For more information, see
        /// [Getting a Connector](https://docs.cloud.oracle.com/iaas/Content/connector-hub/get-service-connector.htm).
        /// 
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
        ///     var testServiceConnector = Oci.Sch.GetServiceConnector.Invoke(new()
        ///     {
        ///         ServiceConnectorId = testServiceConnectorOciSchServiceConnector.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetServiceConnectorResult> Invoke(GetServiceConnectorInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetServiceConnectorResult>("oci:Sch/getServiceConnector:getServiceConnector", args ?? new GetServiceConnectorInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Service Connector resource in Oracle Cloud Infrastructure Service Connector Hub service.
        /// 
        /// Gets the specified connector's configuration information.
        /// For more information, see
        /// [Getting a Connector](https://docs.cloud.oracle.com/iaas/Content/connector-hub/get-service-connector.htm).
        /// 
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
        ///     var testServiceConnector = Oci.Sch.GetServiceConnector.Invoke(new()
        ///     {
        ///         ServiceConnectorId = testServiceConnectorOciSchServiceConnector.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetServiceConnectorResult> Invoke(GetServiceConnectorInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetServiceConnectorResult>("oci:Sch/getServiceConnector:getServiceConnector", args ?? new GetServiceConnectorInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetServiceConnectorArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connector.
        /// </summary>
        [Input("serviceConnectorId", required: true)]
        public string ServiceConnectorId { get; set; } = null!;

        public GetServiceConnectorArgs()
        {
        }
        public static new GetServiceConnectorArgs Empty => new GetServiceConnectorArgs();
    }

    public sealed class GetServiceConnectorInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connector.
        /// </summary>
        [Input("serviceConnectorId", required: true)]
        public Input<string> ServiceConnectorId { get; set; } = null!;

        public GetServiceConnectorInvokeArgs()
        {
        }
        public static new GetServiceConnectorInvokeArgs Empty => new GetServiceConnectorInvokeArgs();
    }


    [OutputType]
    public sealed class GetServiceConnectorResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The description of the resource. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connector.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// *Please note this property is deprecated and will be removed on January 27, 2026. Use `lifecycleDetails` instead.* A message describing the current state in more detail. For example, the message might provide actionable information for a resource in a `FAILED` state.
        /// </summary>
        public readonly string LifecyleDetails;
        public readonly string ServiceConnectorId;
        public readonly ImmutableArray<Outputs.GetServiceConnectorSourceResult> Sources;
        /// <summary>
        /// The current state of the connector.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        public readonly ImmutableArray<Outputs.GetServiceConnectorTargetResult> Targets;
        /// <summary>
        /// The list of tasks.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetServiceConnectorTaskResult> Tasks;
        /// <summary>
        /// The date and time when the connector was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time when the connector was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetServiceConnectorResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string lifecyleDetails,

            string serviceConnectorId,

            ImmutableArray<Outputs.GetServiceConnectorSourceResult> sources,

            string state,

            ImmutableDictionary<string, string> systemTags,

            ImmutableArray<Outputs.GetServiceConnectorTargetResult> targets,

            ImmutableArray<Outputs.GetServiceConnectorTaskResult> tasks,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            LifecyleDetails = lifecyleDetails;
            ServiceConnectorId = serviceConnectorId;
            Sources = sources;
            State = state;
            SystemTags = systemTags;
            Targets = targets;
            Tasks = tasks;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
