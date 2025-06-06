// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetSoftwareUpdate
{
    public static class GetFsuCollections
    {
        /// <summary>
        /// This data source provides the list of Fsu Collections in Oracle Cloud Infrastructure Fleet Software Update service.
        /// 
        /// Gets a list of all Exadata Fleet Update Collections in a compartment.
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
        ///     var testFsuCollections = Oci.FleetSoftwareUpdate.GetFsuCollections.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = fsuCollectionDisplayName,
        ///         State = fsuCollectionState,
        ///         Type = fsuCollectionType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetFsuCollectionsResult> InvokeAsync(GetFsuCollectionsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFsuCollectionsResult>("oci:FleetSoftwareUpdate/getFsuCollections:getFsuCollections", args ?? new GetFsuCollectionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Fsu Collections in Oracle Cloud Infrastructure Fleet Software Update service.
        /// 
        /// Gets a list of all Exadata Fleet Update Collections in a compartment.
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
        ///     var testFsuCollections = Oci.FleetSoftwareUpdate.GetFsuCollections.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = fsuCollectionDisplayName,
        ///         State = fsuCollectionState,
        ///         Type = fsuCollectionType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFsuCollectionsResult> Invoke(GetFsuCollectionsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFsuCollectionsResult>("oci:FleetSoftwareUpdate/getFsuCollections:getFsuCollections", args ?? new GetFsuCollectionsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Fsu Collections in Oracle Cloud Infrastructure Fleet Software Update service.
        /// 
        /// Gets a list of all Exadata Fleet Update Collections in a compartment.
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
        ///     var testFsuCollections = Oci.FleetSoftwareUpdate.GetFsuCollections.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = fsuCollectionDisplayName,
        ///         State = fsuCollectionState,
        ///         Type = fsuCollectionType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFsuCollectionsResult> Invoke(GetFsuCollectionsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetFsuCollectionsResult>("oci:FleetSoftwareUpdate/getFsuCollections:getFsuCollections", args ?? new GetFsuCollectionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFsuCollectionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetFsuCollectionsFilterArgs>? _filters;
        public List<Inputs.GetFsuCollectionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetFsuCollectionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources whose lifecycleState matches the given lifecycleState.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// A filter to return only resources whose type matches the given type.
        /// </summary>
        [Input("type")]
        public string? Type { get; set; }

        public GetFsuCollectionsArgs()
        {
        }
        public static new GetFsuCollectionsArgs Empty => new GetFsuCollectionsArgs();
    }

    public sealed class GetFsuCollectionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetFsuCollectionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetFsuCollectionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetFsuCollectionsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources whose lifecycleState matches the given lifecycleState.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// A filter to return only resources whose type matches the given type.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public GetFsuCollectionsInvokeArgs()
        {
        }
        public static new GetFsuCollectionsInvokeArgs Empty => new GetFsuCollectionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetFsuCollectionsResult
    {
        /// <summary>
        /// Compartment Identifier
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Exadata Fleet Update Collection resource display name.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetFsuCollectionsFilterResult> Filters;
        /// <summary>
        /// The list of fsu_collection_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFsuCollectionsFsuCollectionSummaryCollectionResult> FsuCollectionSummaryCollections;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the Exadata Fleet Update Collection.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// Exadata Fleet Update Collection type.
        /// </summary>
        public readonly string? Type;

        [OutputConstructor]
        private GetFsuCollectionsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetFsuCollectionsFilterResult> filters,

            ImmutableArray<Outputs.GetFsuCollectionsFsuCollectionSummaryCollectionResult> fsuCollectionSummaryCollections,

            string id,

            string? state,

            string? type)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            FsuCollectionSummaryCollections = fsuCollectionSummaryCollections;
            Id = id;
            State = state;
            Type = type;
        }
    }
}
