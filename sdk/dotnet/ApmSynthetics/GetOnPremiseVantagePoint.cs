// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics
{
    public static class GetOnPremiseVantagePoint
    {
        /// <summary>
        /// This data source provides details about a specific On Premise Vantage Point resource in Oracle Cloud Infrastructure APM Availability Monitoring service (aka APM Synthetics Service).
        /// 
        /// Gets the details of the On-premise vantage point identified by the OCID.
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
        ///     var testOnPremiseVantagePoint = Oci.ApmSynthetics.GetOnPremiseVantagePoint.Invoke(new()
        ///     {
        ///         ApmDomainId = testApmDomain.Id,
        ///         OnPremiseVantagePointId = testOnPremiseVantagePointOciApmSyntheticsOnPremiseVantagePoint.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetOnPremiseVantagePointResult> InvokeAsync(GetOnPremiseVantagePointArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetOnPremiseVantagePointResult>("oci:ApmSynthetics/getOnPremiseVantagePoint:getOnPremiseVantagePoint", args ?? new GetOnPremiseVantagePointArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific On Premise Vantage Point resource in Oracle Cloud Infrastructure APM Availability Monitoring service (aka APM Synthetics Service).
        /// 
        /// Gets the details of the On-premise vantage point identified by the OCID.
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
        ///     var testOnPremiseVantagePoint = Oci.ApmSynthetics.GetOnPremiseVantagePoint.Invoke(new()
        ///     {
        ///         ApmDomainId = testApmDomain.Id,
        ///         OnPremiseVantagePointId = testOnPremiseVantagePointOciApmSyntheticsOnPremiseVantagePoint.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOnPremiseVantagePointResult> Invoke(GetOnPremiseVantagePointInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetOnPremiseVantagePointResult>("oci:ApmSynthetics/getOnPremiseVantagePoint:getOnPremiseVantagePoint", args ?? new GetOnPremiseVantagePointInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific On Premise Vantage Point resource in Oracle Cloud Infrastructure APM Availability Monitoring service (aka APM Synthetics Service).
        /// 
        /// Gets the details of the On-premise vantage point identified by the OCID.
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
        ///     var testOnPremiseVantagePoint = Oci.ApmSynthetics.GetOnPremiseVantagePoint.Invoke(new()
        ///     {
        ///         ApmDomainId = testApmDomain.Id,
        ///         OnPremiseVantagePointId = testOnPremiseVantagePointOciApmSyntheticsOnPremiseVantagePoint.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOnPremiseVantagePointResult> Invoke(GetOnPremiseVantagePointInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetOnPremiseVantagePointResult>("oci:ApmSynthetics/getOnPremiseVantagePoint:getOnPremiseVantagePoint", args ?? new GetOnPremiseVantagePointInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOnPremiseVantagePointArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The APM domain ID the request is intended for.
        /// </summary>
        [Input("apmDomainId", required: true)]
        public string ApmDomainId { get; set; } = null!;

        /// <summary>
        /// The OCID of the On-premise vantage point.
        /// </summary>
        [Input("onPremiseVantagePointId", required: true)]
        public string OnPremiseVantagePointId { get; set; } = null!;

        public GetOnPremiseVantagePointArgs()
        {
        }
        public static new GetOnPremiseVantagePointArgs Empty => new GetOnPremiseVantagePointArgs();
    }

    public sealed class GetOnPremiseVantagePointInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The APM domain ID the request is intended for.
        /// </summary>
        [Input("apmDomainId", required: true)]
        public Input<string> ApmDomainId { get; set; } = null!;

        /// <summary>
        /// The OCID of the On-premise vantage point.
        /// </summary>
        [Input("onPremiseVantagePointId", required: true)]
        public Input<string> OnPremiseVantagePointId { get; set; } = null!;

        public GetOnPremiseVantagePointInvokeArgs()
        {
        }
        public static new GetOnPremiseVantagePointInvokeArgs Empty => new GetOnPremiseVantagePointInvokeArgs();
    }


    [OutputType]
    public sealed class GetOnPremiseVantagePointResult
    {
        public readonly string ApmDomainId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A short description about the On-premise vantage point.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Unique permanent name of the On-premise vantage point.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the On-premise vantage point.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Unique On-premise vantage point name that cannot be edited. The name should not contain any confidential information.
        /// </summary>
        public readonly string Name;
        public readonly string OnPremiseVantagePointId;
        /// <summary>
        /// The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Type of On-premise vantage point.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// Details of the workers in a specific On-premise vantage point.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOnPremiseVantagePointWorkersSummaryResult> WorkersSummaries;

        [OutputConstructor]
        private GetOnPremiseVantagePointResult(
            string apmDomainId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string name,

            string onPremiseVantagePointId,

            string timeCreated,

            string timeUpdated,

            string type,

            ImmutableArray<Outputs.GetOnPremiseVantagePointWorkersSummaryResult> workersSummaries)
        {
            ApmDomainId = apmDomainId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            Name = name;
            OnPremiseVantagePointId = onPremiseVantagePointId;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Type = type;
            WorkersSummaries = workersSummaries;
        }
    }
}
