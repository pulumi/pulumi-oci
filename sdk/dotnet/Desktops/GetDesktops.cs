// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Desktops
{
    public static class GetDesktops
    {
        /// <summary>
        /// This data source provides the list of Desktops in Oracle Cloud Infrastructure Desktops service.
        /// 
        /// Returns a list of desktops filtered by the specified parameters. You can limit the results to an availability domain, desktop name, desktop OCID, desktop state, pool OCID, or compartment OCID. You can limit the number of results returned, sort the results by time or name, and sort in ascending or descending order.
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
        ///     var testDesktops = Oci.Desktops.GetDesktops.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = desktopAvailabilityDomain,
        ///         DesktopPoolId = testDesktopPool.Id,
        ///         DisplayName = desktopDisplayName,
        ///         Id = desktopId,
        ///         State = desktopState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDesktopsResult> InvokeAsync(GetDesktopsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDesktopsResult>("oci:Desktops/getDesktops:getDesktops", args ?? new GetDesktopsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Desktops in Oracle Cloud Infrastructure Desktops service.
        /// 
        /// Returns a list of desktops filtered by the specified parameters. You can limit the results to an availability domain, desktop name, desktop OCID, desktop state, pool OCID, or compartment OCID. You can limit the number of results returned, sort the results by time or name, and sort in ascending or descending order.
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
        ///     var testDesktops = Oci.Desktops.GetDesktops.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = desktopAvailabilityDomain,
        ///         DesktopPoolId = testDesktopPool.Id,
        ///         DisplayName = desktopDisplayName,
        ///         Id = desktopId,
        ///         State = desktopState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDesktopsResult> Invoke(GetDesktopsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDesktopsResult>("oci:Desktops/getDesktops:getDesktops", args ?? new GetDesktopsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Desktops in Oracle Cloud Infrastructure Desktops service.
        /// 
        /// Returns a list of desktops filtered by the specified parameters. You can limit the results to an availability domain, desktop name, desktop OCID, desktop state, pool OCID, or compartment OCID. You can limit the number of results returned, sort the results by time or name, and sort in ascending or descending order.
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
        ///     var testDesktops = Oci.Desktops.GetDesktops.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = desktopAvailabilityDomain,
        ///         DesktopPoolId = testDesktopPool.Id,
        ///         DisplayName = desktopDisplayName,
        ///         Id = desktopId,
        ///         State = desktopState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDesktopsResult> Invoke(GetDesktopsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDesktopsResult>("oci:Desktops/getDesktops:getDesktops", args ?? new GetDesktopsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDesktopsArgs : global::Pulumi.InvokeArgs
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
        /// The OCID of the desktop pool.
        /// </summary>
        [Input("desktopPoolId")]
        public string? DesktopPoolId { get; set; }

        /// <summary>
        /// A filter to return only results with the given displayName.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDesktopsFilterArgs>? _filters;
        public List<Inputs.GetDesktopsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDesktopsFilterArgs>());
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

        public GetDesktopsArgs()
        {
        }
        public static new GetDesktopsArgs Empty => new GetDesktopsArgs();
    }

    public sealed class GetDesktopsInvokeArgs : global::Pulumi.InvokeArgs
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
        /// The OCID of the desktop pool.
        /// </summary>
        [Input("desktopPoolId")]
        public Input<string>? DesktopPoolId { get; set; }

        /// <summary>
        /// A filter to return only results with the given displayName.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDesktopsFilterInputArgs>? _filters;
        public InputList<Inputs.GetDesktopsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDesktopsFilterInputArgs>());
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

        public GetDesktopsInvokeArgs()
        {
        }
        public static new GetDesktopsInvokeArgs Empty => new GetDesktopsInvokeArgs();
    }


    [OutputType]
    public sealed class GetDesktopsResult
    {
        public readonly string? AvailabilityDomain;
        public readonly string CompartmentId;
        /// <summary>
        /// The list of desktop_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopsDesktopCollectionResult> DesktopCollections;
        public readonly string? DesktopPoolId;
        /// <summary>
        /// A user friendly display name. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDesktopsFilterResult> Filters;
        /// <summary>
        /// The OCID of the desktop.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The state of the desktop.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDesktopsResult(
            string? availabilityDomain,

            string compartmentId,

            ImmutableArray<Outputs.GetDesktopsDesktopCollectionResult> desktopCollections,

            string? desktopPoolId,

            string? displayName,

            ImmutableArray<Outputs.GetDesktopsFilterResult> filters,

            string? id,

            string? state)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DesktopCollections = desktopCollections;
            DesktopPoolId = desktopPoolId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
