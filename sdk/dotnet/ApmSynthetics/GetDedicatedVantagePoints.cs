// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics
{
    public static class GetDedicatedVantagePoints
    {
        /// <summary>
        /// This data source provides the list of Dedicated Vantage Points in Oracle Cloud Infrastructure Apm Synthetics service.
        /// 
        /// Returns a list of dedicated vantage points.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testDedicatedVantagePoints = Oci.ApmSynthetics.GetDedicatedVantagePoints.Invoke(new()
        ///     {
        ///         ApmDomainId = oci_apm_apm_domain.Test_apm_domain.Id,
        ///         DisplayName = @var.Dedicated_vantage_point_display_name,
        ///         Name = @var.Dedicated_vantage_point_name,
        ///         Status = @var.Dedicated_vantage_point_status,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDedicatedVantagePointsResult> InvokeAsync(GetDedicatedVantagePointsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDedicatedVantagePointsResult>("oci:ApmSynthetics/getDedicatedVantagePoints:getDedicatedVantagePoints", args ?? new GetDedicatedVantagePointsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Dedicated Vantage Points in Oracle Cloud Infrastructure Apm Synthetics service.
        /// 
        /// Returns a list of dedicated vantage points.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testDedicatedVantagePoints = Oci.ApmSynthetics.GetDedicatedVantagePoints.Invoke(new()
        ///     {
        ///         ApmDomainId = oci_apm_apm_domain.Test_apm_domain.Id,
        ///         DisplayName = @var.Dedicated_vantage_point_display_name,
        ///         Name = @var.Dedicated_vantage_point_name,
        ///         Status = @var.Dedicated_vantage_point_status,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDedicatedVantagePointsResult> Invoke(GetDedicatedVantagePointsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDedicatedVantagePointsResult>("oci:ApmSynthetics/getDedicatedVantagePoints:getDedicatedVantagePoints", args ?? new GetDedicatedVantagePointsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDedicatedVantagePointsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The APM domain ID the request is intended for.
        /// </summary>
        [Input("apmDomainId", required: true)]
        public string ApmDomainId { get; set; } = null!;

        /// <summary>
        /// A filter to return only the resources that match the entire display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDedicatedVantagePointsFilterArgs>? _filters;
        public List<Inputs.GetDedicatedVantagePointsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDedicatedVantagePointsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the resources that match the entire name.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// A filter to return only the dedicated vantage points that match a given status.
        /// </summary>
        [Input("status")]
        public string? Status { get; set; }

        public GetDedicatedVantagePointsArgs()
        {
        }
        public static new GetDedicatedVantagePointsArgs Empty => new GetDedicatedVantagePointsArgs();
    }

    public sealed class GetDedicatedVantagePointsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The APM domain ID the request is intended for.
        /// </summary>
        [Input("apmDomainId", required: true)]
        public Input<string> ApmDomainId { get; set; } = null!;

        /// <summary>
        /// A filter to return only the resources that match the entire display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDedicatedVantagePointsFilterInputArgs>? _filters;
        public InputList<Inputs.GetDedicatedVantagePointsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDedicatedVantagePointsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the resources that match the entire name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A filter to return only the dedicated vantage points that match a given status.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        public GetDedicatedVantagePointsInvokeArgs()
        {
        }
        public static new GetDedicatedVantagePointsInvokeArgs Empty => new GetDedicatedVantagePointsInvokeArgs();
    }


    [OutputType]
    public sealed class GetDedicatedVantagePointsResult
    {
        public readonly string ApmDomainId;
        /// <summary>
        /// The list of dedicated_vantage_point_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDedicatedVantagePointsDedicatedVantagePointCollectionResult> DedicatedVantagePointCollections;
        /// <summary>
        /// Unique dedicated vantage point name that cannot be edited. The name should not contain any confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDedicatedVantagePointsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Unique permanent name of the dedicated vantage point. This is the same as the displayName.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// Status of the dedicated vantage point.
        /// </summary>
        public readonly string? Status;

        [OutputConstructor]
        private GetDedicatedVantagePointsResult(
            string apmDomainId,

            ImmutableArray<Outputs.GetDedicatedVantagePointsDedicatedVantagePointCollectionResult> dedicatedVantagePointCollections,

            string? displayName,

            ImmutableArray<Outputs.GetDedicatedVantagePointsFilterResult> filters,

            string id,

            string? name,

            string? status)
        {
            ApmDomainId = apmDomainId;
            DedicatedVantagePointCollections = dedicatedVantagePointCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            Name = name;
            Status = status;
        }
    }
}