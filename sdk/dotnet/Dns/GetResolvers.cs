// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns
{
    public static class GetResolvers
    {
        /// <summary>
        /// This data source provides the list of Resolvers in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets a list of all resolvers within a compartment.
        /// 
        /// The collection can be filtered by display name, id, or lifecycle state. It can be sorted
        /// on creation time or displayName both in ASC or DESC order. Note that when no lifecycleState
        /// query parameter is provided, the collection does not include resolvers in the DELETED
        /// lifecycleState to be consistent with other operations of the API.
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
        ///     var testResolvers = Oci.Dns.GetResolvers.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Scope = "PRIVATE",
        ///         DisplayName = resolverDisplayName,
        ///         Id = resolverId,
        ///         State = resolverState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetResolversResult> InvokeAsync(GetResolversArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetResolversResult>("oci:Dns/getResolvers:getResolvers", args ?? new GetResolversArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Resolvers in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets a list of all resolvers within a compartment.
        /// 
        /// The collection can be filtered by display name, id, or lifecycle state. It can be sorted
        /// on creation time or displayName both in ASC or DESC order. Note that when no lifecycleState
        /// query parameter is provided, the collection does not include resolvers in the DELETED
        /// lifecycleState to be consistent with other operations of the API.
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
        ///     var testResolvers = Oci.Dns.GetResolvers.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Scope = "PRIVATE",
        ///         DisplayName = resolverDisplayName,
        ///         Id = resolverId,
        ///         State = resolverState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetResolversResult> Invoke(GetResolversInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetResolversResult>("oci:Dns/getResolvers:getResolvers", args ?? new GetResolversInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Resolvers in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets a list of all resolvers within a compartment.
        /// 
        /// The collection can be filtered by display name, id, or lifecycle state. It can be sorted
        /// on creation time or displayName both in ASC or DESC order. Note that when no lifecycleState
        /// query parameter is provided, the collection does not include resolvers in the DELETED
        /// lifecycleState to be consistent with other operations of the API.
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
        ///     var testResolvers = Oci.Dns.GetResolvers.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Scope = "PRIVATE",
        ///         DisplayName = resolverDisplayName,
        ///         Id = resolverId,
        ///         State = resolverState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetResolversResult> Invoke(GetResolversInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetResolversResult>("oci:Dns/getResolvers:getResolvers", args ?? new GetResolversInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetResolversArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The displayName of a resource.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetResolversFilterArgs>? _filters;
        public List<Inputs.GetResolversFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetResolversFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of a resource.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// Value must be `PRIVATE` when listing private name resolvers.
        /// </summary>
        [Input("scope", required: true)]
        public string Scope { get; set; } = null!;

        /// <summary>
        /// The state of a resource.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetResolversArgs()
        {
        }
        public static new GetResolversArgs Empty => new GetResolversArgs();
    }

    public sealed class GetResolversInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The displayName of a resource.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetResolversFilterInputArgs>? _filters;
        public InputList<Inputs.GetResolversFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetResolversFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of a resource.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// Value must be `PRIVATE` when listing private name resolvers.
        /// </summary>
        [Input("scope", required: true)]
        public Input<string> Scope { get; set; } = null!;

        /// <summary>
        /// The state of a resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetResolversInvokeArgs()
        {
        }
        public static new GetResolversInvokeArgs Empty => new GetResolversInvokeArgs();
    }


    [OutputType]
    public sealed class GetResolversResult
    {
        /// <summary>
        /// The OCID of the owning compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The display name of the resolver.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetResolversFilterResult> Filters;
        /// <summary>
        /// The OCID of the resolver.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of resolvers.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetResolversResolverResult> Resolvers;
        public readonly string Scope;
        /// <summary>
        /// The current state of the resource.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetResolversResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetResolversFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetResolversResolverResult> resolvers,

            string scope,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            Resolvers = resolvers;
            Scope = scope;
            State = state;
        }
    }
}
