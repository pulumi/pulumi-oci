// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation
{
    public static class GetQuery
    {
        /// <summary>
        /// This data source provides details about a specific Query resource in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the saved query.
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
        ///     var testQuery = Oci.MeteringComputation.GetQuery.Invoke(new()
        ///     {
        ///         QueryId = oci_metering_computation_query.Test_query.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetQueryResult> InvokeAsync(GetQueryArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetQueryResult>("oci:MeteringComputation/getQuery:getQuery", args ?? new GetQueryArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Query resource in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the saved query.
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
        ///     var testQuery = Oci.MeteringComputation.GetQuery.Invoke(new()
        ///     {
        ///         QueryId = oci_metering_computation_query.Test_query.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetQueryResult> Invoke(GetQueryInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetQueryResult>("oci:MeteringComputation/getQuery:getQuery", args ?? new GetQueryInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetQueryArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The query unique OCID.
        /// </summary>
        [Input("queryId", required: true)]
        public string QueryId { get; set; } = null!;

        public GetQueryArgs()
        {
        }
        public static new GetQueryArgs Empty => new GetQueryArgs();
    }

    public sealed class GetQueryInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The query unique OCID.
        /// </summary>
        [Input("queryId", required: true)]
        public Input<string> QueryId { get; set; } = null!;

        public GetQueryInvokeArgs()
        {
        }
        public static new GetQueryInvokeArgs Empty => new GetQueryInvokeArgs();
    }


    [OutputType]
    public sealed class GetQueryResult
    {
        /// <summary>
        /// The compartment OCID.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The query OCID.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The common fields for queries.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetQueryQueryDefinitionResult> QueryDefinitions;
        public readonly string QueryId;

        [OutputConstructor]
        private GetQueryResult(
            string compartmentId,

            string id,

            ImmutableArray<Outputs.GetQueryQueryDefinitionResult> queryDefinitions,

            string queryId)
        {
            CompartmentId = compartmentId;
            Id = id;
            QueryDefinitions = queryDefinitions;
            QueryId = queryId;
        }
    }
}