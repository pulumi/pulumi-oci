// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.EmWarehouse
{
    public static class GetEtlRun
    {
        /// <summary>
        /// This data source provides details about a specific Em Warehouse Etl Run resource in Oracle Cloud Infrastructure Em Warehouse service.
        /// 
        /// Gets a list of runs of an EmWarehouseResource by identifier
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
        ///     var testEmWarehouseEtlRun = Oci.EmWarehouse.GetEtlRun.Invoke(new()
        ///     {
        ///         EmWarehouseId = oci_em_warehouse_em_warehouse.Test_em_warehouse.Id,
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Em_warehouse_etl_run_display_name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetEtlRunResult> InvokeAsync(GetEtlRunArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetEtlRunResult>("oci:EmWarehouse/getEtlRun:getEtlRun", args ?? new GetEtlRunArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Em Warehouse Etl Run resource in Oracle Cloud Infrastructure Em Warehouse service.
        /// 
        /// Gets a list of runs of an EmWarehouseResource by identifier
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
        ///     var testEmWarehouseEtlRun = Oci.EmWarehouse.GetEtlRun.Invoke(new()
        ///     {
        ///         EmWarehouseId = oci_em_warehouse_em_warehouse.Test_em_warehouse.Id,
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Em_warehouse_etl_run_display_name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetEtlRunResult> Invoke(GetEtlRunInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetEtlRunResult>("oci:EmWarehouse/getEtlRun:getEtlRun", args ?? new GetEtlRunInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetEtlRunArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// unique EmWarehouse identifier
        /// </summary>
        [Input("emWarehouseId", required: true)]
        public string EmWarehouseId { get; set; } = null!;

        public GetEtlRunArgs()
        {
        }
        public static new GetEtlRunArgs Empty => new GetEtlRunArgs();
    }

    public sealed class GetEtlRunInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// unique EmWarehouse identifier
        /// </summary>
        [Input("emWarehouseId", required: true)]
        public Input<string> EmWarehouseId { get; set; } = null!;

        public GetEtlRunInvokeArgs()
        {
        }
        public static new GetEtlRunInvokeArgs Empty => new GetEtlRunInvokeArgs();
    }


    [OutputType]
    public sealed class GetEtlRunResult
    {
        /// <summary>
        /// Compartment Identifier
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// The name of the ETLRun.
        /// </summary>
        public readonly string? DisplayName;
        public readonly string EmWarehouseId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// List of runs
        /// </summary>
        public readonly ImmutableArray<Outputs.GetEtlRunItemResult> Items;

        [OutputConstructor]
        private GetEtlRunResult(
            string? compartmentId,

            string? displayName,

            string emWarehouseId,

            string id,

            ImmutableArray<Outputs.GetEtlRunItemResult> items)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            EmWarehouseId = emWarehouseId;
            Id = id;
            Items = items;
        }
    }
}