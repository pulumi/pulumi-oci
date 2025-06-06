// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Desktops
{
    public static class GetDesktopPools
    {
        /// <summary>
        /// This data source provides the list of Desktop Pools in Oracle Cloud Infrastructure Desktops service.
        /// 
        /// Returns a list of desktop pools within the given compartment. You can limit the results to an availability domain, pool name, or pool state. You can limit the number of results returned, sort the results by time or name, and sort in ascending or descending order.
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
        ///     var testDesktopPools = Oci.Desktops.GetDesktopPools.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = desktopPoolAvailabilityDomain,
        ///         DisplayName = desktopPoolDisplayName,
        ///         Id = desktopPoolId,
        ///         State = desktopPoolState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDesktopPoolsResult> InvokeAsync(GetDesktopPoolsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDesktopPoolsResult>("oci:Desktops/getDesktopPools:getDesktopPools", args ?? new GetDesktopPoolsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Desktop Pools in Oracle Cloud Infrastructure Desktops service.
        /// 
        /// Returns a list of desktop pools within the given compartment. You can limit the results to an availability domain, pool name, or pool state. You can limit the number of results returned, sort the results by time or name, and sort in ascending or descending order.
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
        ///     var testDesktopPools = Oci.Desktops.GetDesktopPools.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = desktopPoolAvailabilityDomain,
        ///         DisplayName = desktopPoolDisplayName,
        ///         Id = desktopPoolId,
        ///         State = desktopPoolState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDesktopPoolsResult> Invoke(GetDesktopPoolsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDesktopPoolsResult>("oci:Desktops/getDesktopPools:getDesktopPools", args ?? new GetDesktopPoolsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Desktop Pools in Oracle Cloud Infrastructure Desktops service.
        /// 
        /// Returns a list of desktop pools within the given compartment. You can limit the results to an availability domain, pool name, or pool state. You can limit the number of results returned, sort the results by time or name, and sort in ascending or descending order.
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
        ///     var testDesktopPools = Oci.Desktops.GetDesktopPools.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = desktopPoolAvailabilityDomain,
        ///         DisplayName = desktopPoolDisplayName,
        ///         Id = desktopPoolId,
        ///         State = desktopPoolState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDesktopPoolsResult> Invoke(GetDesktopPoolsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDesktopPoolsResult>("oci:Desktops/getDesktopPools:getDesktopPools", args ?? new GetDesktopPoolsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDesktopPoolsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The OCID of the compartment of the desktop pool.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only results with the given displayName.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDesktopPoolsFilterArgs>? _filters;
        public List<Inputs.GetDesktopPoolsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDesktopPoolsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only results with the given OCID.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return only results with the given lifecycleState.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDesktopPoolsArgs()
        {
        }
        public static new GetDesktopPoolsArgs Empty => new GetDesktopPoolsArgs();
    }

    public sealed class GetDesktopPoolsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The OCID of the compartment of the desktop pool.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only results with the given displayName.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDesktopPoolsFilterInputArgs>? _filters;
        public InputList<Inputs.GetDesktopPoolsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDesktopPoolsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only results with the given OCID.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// A filter to return only results with the given lifecycleState.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetDesktopPoolsInvokeArgs()
        {
        }
        public static new GetDesktopPoolsInvokeArgs Empty => new GetDesktopPoolsInvokeArgs();
    }


    [OutputType]
    public sealed class GetDesktopPoolsResult
    {
        /// <summary>
        /// The availability domain of the desktop pool.
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// The OCID of the compartment of the desktop pool.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of desktop_pool_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopPoolsDesktopPoolCollectionResult> DesktopPoolCollections;
        /// <summary>
        /// A user friendly display name. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDesktopPoolsFilterResult> Filters;
        /// <summary>
        /// The OCID of the desktop pool.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The current state of the desktop pool.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDesktopPoolsResult(
            string? availabilityDomain,

            string compartmentId,

            ImmutableArray<Outputs.GetDesktopPoolsDesktopPoolCollectionResult> desktopPoolCollections,

            string? displayName,

            ImmutableArray<Outputs.GetDesktopPoolsFilterResult> filters,

            string? id,

            string? state)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DesktopPoolCollections = desktopPoolCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
