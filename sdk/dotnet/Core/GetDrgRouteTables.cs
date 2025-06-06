// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetDrgRouteTables
    {
        /// <summary>
        /// This data source provides the list of Drg Route Tables in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the DRG route tables for the specified DRG.
        /// 
        /// Use the `ListDrgRouteRules` operation to retrieve the route rules in a table.
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
        ///     var testDrgRouteTables = Oci.Core.GetDrgRouteTables.Invoke(new()
        ///     {
        ///         DrgId = testDrg.Id,
        ///         DisplayName = drgRouteTableDisplayName,
        ///         ImportDrgRouteDistributionId = testDrgRouteDistribution.Id,
        ///         State = drgRouteTableState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDrgRouteTablesResult> InvokeAsync(GetDrgRouteTablesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDrgRouteTablesResult>("oci:Core/getDrgRouteTables:getDrgRouteTables", args ?? new GetDrgRouteTablesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Drg Route Tables in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the DRG route tables for the specified DRG.
        /// 
        /// Use the `ListDrgRouteRules` operation to retrieve the route rules in a table.
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
        ///     var testDrgRouteTables = Oci.Core.GetDrgRouteTables.Invoke(new()
        ///     {
        ///         DrgId = testDrg.Id,
        ///         DisplayName = drgRouteTableDisplayName,
        ///         ImportDrgRouteDistributionId = testDrgRouteDistribution.Id,
        ///         State = drgRouteTableState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDrgRouteTablesResult> Invoke(GetDrgRouteTablesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDrgRouteTablesResult>("oci:Core/getDrgRouteTables:getDrgRouteTables", args ?? new GetDrgRouteTablesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Drg Route Tables in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the DRG route tables for the specified DRG.
        /// 
        /// Use the `ListDrgRouteRules` operation to retrieve the route rules in a table.
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
        ///     var testDrgRouteTables = Oci.Core.GetDrgRouteTables.Invoke(new()
        ///     {
        ///         DrgId = testDrg.Id,
        ///         DisplayName = drgRouteTableDisplayName,
        ///         ImportDrgRouteDistributionId = testDrgRouteDistribution.Id,
        ///         State = drgRouteTableState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDrgRouteTablesResult> Invoke(GetDrgRouteTablesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDrgRouteTablesResult>("oci:Core/getDrgRouteTables:getDrgRouteTables", args ?? new GetDrgRouteTablesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDrgRouteTablesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
        /// </summary>
        [Input("drgId", required: true)]
        public string DrgId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetDrgRouteTablesFilterArgs>? _filters;
        public List<Inputs.GetDrgRouteTablesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDrgRouteTablesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the import route distribution.
        /// </summary>
        [Input("importDrgRouteDistributionId")]
        public string? ImportDrgRouteDistributionId { get; set; }

        /// <summary>
        /// A filter that only returns matches for the specified lifecycle state. The value is case insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDrgRouteTablesArgs()
        {
        }
        public static new GetDrgRouteTablesArgs Empty => new GetDrgRouteTablesArgs();
    }

    public sealed class GetDrgRouteTablesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
        /// </summary>
        [Input("drgId", required: true)]
        public Input<string> DrgId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetDrgRouteTablesFilterInputArgs>? _filters;
        public InputList<Inputs.GetDrgRouteTablesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDrgRouteTablesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the import route distribution.
        /// </summary>
        [Input("importDrgRouteDistributionId")]
        public Input<string>? ImportDrgRouteDistributionId { get; set; }

        /// <summary>
        /// A filter that only returns matches for the specified lifecycle state. The value is case insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetDrgRouteTablesInvokeArgs()
        {
        }
        public static new GetDrgRouteTablesInvokeArgs Empty => new GetDrgRouteTablesInvokeArgs();
    }


    [OutputType]
    public sealed class GetDrgRouteTablesResult
    {
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the DRG that contains this route table.
        /// </summary>
        public readonly string DrgId;
        /// <summary>
        /// The list of drg_route_tables.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrgRouteTablesDrgRouteTableResult> DrgRouteTables;
        public readonly ImmutableArray<Outputs.GetDrgRouteTablesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the import route distribution used to specify how incoming route advertisements from referenced attachments are inserted into the DRG route table.
        /// </summary>
        public readonly string? ImportDrgRouteDistributionId;
        /// <summary>
        /// The DRG route table's current state.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDrgRouteTablesResult(
            string? displayName,

            string drgId,

            ImmutableArray<Outputs.GetDrgRouteTablesDrgRouteTableResult> drgRouteTables,

            ImmutableArray<Outputs.GetDrgRouteTablesFilterResult> filters,

            string id,

            string? importDrgRouteDistributionId,

            string? state)
        {
            DisplayName = displayName;
            DrgId = drgId;
            DrgRouteTables = drgRouteTables;
            Filters = filters;
            Id = id;
            ImportDrgRouteDistributionId = importDrgRouteDistributionId;
            State = state;
        }
    }
}
