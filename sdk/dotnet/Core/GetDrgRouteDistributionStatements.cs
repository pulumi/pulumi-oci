// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetDrgRouteDistributionStatements
    {
        /// <summary>
        /// This data source provides the list of Drg Route Distribution Statements in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the statements for the specified route distribution.
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
        ///     var testDrgRouteDistributionStatements = Oci.Core.GetDrgRouteDistributionStatements.Invoke(new()
        ///     {
        ///         DrgRouteDistributionId = testDrgRouteDistribution.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDrgRouteDistributionStatementsResult> InvokeAsync(GetDrgRouteDistributionStatementsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDrgRouteDistributionStatementsResult>("oci:Core/getDrgRouteDistributionStatements:getDrgRouteDistributionStatements", args ?? new GetDrgRouteDistributionStatementsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Drg Route Distribution Statements in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the statements for the specified route distribution.
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
        ///     var testDrgRouteDistributionStatements = Oci.Core.GetDrgRouteDistributionStatements.Invoke(new()
        ///     {
        ///         DrgRouteDistributionId = testDrgRouteDistribution.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDrgRouteDistributionStatementsResult> Invoke(GetDrgRouteDistributionStatementsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDrgRouteDistributionStatementsResult>("oci:Core/getDrgRouteDistributionStatements:getDrgRouteDistributionStatements", args ?? new GetDrgRouteDistributionStatementsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Drg Route Distribution Statements in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the statements for the specified route distribution.
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
        ///     var testDrgRouteDistributionStatements = Oci.Core.GetDrgRouteDistributionStatements.Invoke(new()
        ///     {
        ///         DrgRouteDistributionId = testDrgRouteDistribution.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDrgRouteDistributionStatementsResult> Invoke(GetDrgRouteDistributionStatementsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDrgRouteDistributionStatementsResult>("oci:Core/getDrgRouteDistributionStatements:getDrgRouteDistributionStatements", args ?? new GetDrgRouteDistributionStatementsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDrgRouteDistributionStatementsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route distribution.
        /// </summary>
        [Input("drgRouteDistributionId", required: true)]
        public string DrgRouteDistributionId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetDrgRouteDistributionStatementsFilterArgs>? _filters;
        public List<Inputs.GetDrgRouteDistributionStatementsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDrgRouteDistributionStatementsFilterArgs>());
            set => _filters = value;
        }

        public GetDrgRouteDistributionStatementsArgs()
        {
        }
        public static new GetDrgRouteDistributionStatementsArgs Empty => new GetDrgRouteDistributionStatementsArgs();
    }

    public sealed class GetDrgRouteDistributionStatementsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route distribution.
        /// </summary>
        [Input("drgRouteDistributionId", required: true)]
        public Input<string> DrgRouteDistributionId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetDrgRouteDistributionStatementsFilterInputArgs>? _filters;
        public InputList<Inputs.GetDrgRouteDistributionStatementsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDrgRouteDistributionStatementsFilterInputArgs>());
            set => _filters = value;
        }

        public GetDrgRouteDistributionStatementsInvokeArgs()
        {
        }
        public static new GetDrgRouteDistributionStatementsInvokeArgs Empty => new GetDrgRouteDistributionStatementsInvokeArgs();
    }


    [OutputType]
    public sealed class GetDrgRouteDistributionStatementsResult
    {
        public readonly string DrgRouteDistributionId;
        /// <summary>
        /// The list of drg_route_distribution_statements.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrgRouteDistributionStatementsDrgRouteDistributionStatementResult> DrgRouteDistributionStatements;
        public readonly ImmutableArray<Outputs.GetDrgRouteDistributionStatementsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetDrgRouteDistributionStatementsResult(
            string drgRouteDistributionId,

            ImmutableArray<Outputs.GetDrgRouteDistributionStatementsDrgRouteDistributionStatementResult> drgRouteDistributionStatements,

            ImmutableArray<Outputs.GetDrgRouteDistributionStatementsFilterResult> filters,

            string id)
        {
            DrgRouteDistributionId = drgRouteDistributionId;
            DrgRouteDistributionStatements = drgRouteDistributionStatements;
            Filters = filters;
            Id = id;
        }
    }
}
