// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataFlow
{
    public static class GetPools
    {
        /// <summary>
        /// This data source provides the list of Pools in Oracle Cloud Infrastructure Data Flow service.
        /// 
        /// Lists all pools in the specified compartment. The query must include compartmentId. The query may also include one other parameter. If the query does not include compartmentId, or includes compartmentId, but with two or more other parameters, an error is returned.
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
        ///     var testPools = Oci.DataFlow.GetPools.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = poolDisplayName,
        ///         DisplayNameStartsWith = poolDisplayNameStartsWith,
        ///         OwnerPrincipalId = testOwnerPrincipal.Id,
        ///         State = poolState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetPoolsResult> InvokeAsync(GetPoolsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPoolsResult>("oci:DataFlow/getPools:getPools", args ?? new GetPoolsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Pools in Oracle Cloud Infrastructure Data Flow service.
        /// 
        /// Lists all pools in the specified compartment. The query must include compartmentId. The query may also include one other parameter. If the query does not include compartmentId, or includes compartmentId, but with two or more other parameters, an error is returned.
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
        ///     var testPools = Oci.DataFlow.GetPools.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = poolDisplayName,
        ///         DisplayNameStartsWith = poolDisplayNameStartsWith,
        ///         OwnerPrincipalId = testOwnerPrincipal.Id,
        ///         State = poolState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPoolsResult> Invoke(GetPoolsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPoolsResult>("oci:DataFlow/getPools:getPools", args ?? new GetPoolsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Pools in Oracle Cloud Infrastructure Data Flow service.
        /// 
        /// Lists all pools in the specified compartment. The query must include compartmentId. The query may also include one other parameter. If the query does not include compartmentId, or includes compartmentId, but with two or more other parameters, an error is returned.
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
        ///     var testPools = Oci.DataFlow.GetPools.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = poolDisplayName,
        ///         DisplayNameStartsWith = poolDisplayNameStartsWith,
        ///         OwnerPrincipalId = testOwnerPrincipal.Id,
        ///         State = poolState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPoolsResult> Invoke(GetPoolsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetPoolsResult>("oci:DataFlow/getPools:getPools", args ?? new GetPoolsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPoolsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The query parameter for the Spark application name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// The displayName prefix.
        /// </summary>
        [Input("displayNameStartsWith")]
        public string? DisplayNameStartsWith { get; set; }

        [Input("filters")]
        private List<Inputs.GetPoolsFilterArgs>? _filters;
        public List<Inputs.GetPoolsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetPoolsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the user who created the resource.
        /// </summary>
        [Input("ownerPrincipalId")]
        public string? OwnerPrincipalId { get; set; }

        /// <summary>
        /// The LifecycleState of the pool.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetPoolsArgs()
        {
        }
        public static new GetPoolsArgs Empty => new GetPoolsArgs();
    }

    public sealed class GetPoolsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The query parameter for the Spark application name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The displayName prefix.
        /// </summary>
        [Input("displayNameStartsWith")]
        public Input<string>? DisplayNameStartsWith { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetPoolsFilterInputArgs>? _filters;
        public InputList<Inputs.GetPoolsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetPoolsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the user who created the resource.
        /// </summary>
        [Input("ownerPrincipalId")]
        public Input<string>? OwnerPrincipalId { get; set; }

        /// <summary>
        /// The LifecycleState of the pool.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetPoolsInvokeArgs()
        {
        }
        public static new GetPoolsInvokeArgs Empty => new GetPoolsInvokeArgs();
    }


    [OutputType]
    public sealed class GetPoolsResult
    {
        /// <summary>
        /// The OCID of a compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. It does not have to be unique. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly string? DisplayNameStartsWith;
        public readonly ImmutableArray<Outputs.GetPoolsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the user who created the resource.
        /// </summary>
        public readonly string? OwnerPrincipalId;
        /// <summary>
        /// The list of pool_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPoolsPoolCollectionResult> PoolCollections;
        /// <summary>
        /// The current state of this pool.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetPoolsResult(
            string compartmentId,

            string? displayName,

            string? displayNameStartsWith,

            ImmutableArray<Outputs.GetPoolsFilterResult> filters,

            string id,

            string? ownerPrincipalId,

            ImmutableArray<Outputs.GetPoolsPoolCollectionResult> poolCollections,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            DisplayNameStartsWith = displayNameStartsWith;
            Filters = filters;
            Id = id;
            OwnerPrincipalId = ownerPrincipalId;
            PoolCollections = poolCollections;
            State = state;
        }
    }
}
