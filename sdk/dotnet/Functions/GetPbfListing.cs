// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions
{
    public static class GetPbfListing
    {
        /// <summary>
        /// This data source provides details about a specific Pbf Listing resource in Oracle Cloud Infrastructure Functions service.
        /// 
        /// Fetches a Pre-built Function(PBF) Listing. Returns a PbfListing response model.
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
        ///     var testPbfListing = Oci.Functions.GetPbfListing.Invoke(new()
        ///     {
        ///         PbfListingId = oci_functions_pbf_listing.Test_pbf_listing.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetPbfListingResult> InvokeAsync(GetPbfListingArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPbfListingResult>("oci:Functions/getPbfListing:getPbfListing", args ?? new GetPbfListingArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Pbf Listing resource in Oracle Cloud Infrastructure Functions service.
        /// 
        /// Fetches a Pre-built Function(PBF) Listing. Returns a PbfListing response model.
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
        ///     var testPbfListing = Oci.Functions.GetPbfListing.Invoke(new()
        ///     {
        ///         PbfListingId = oci_functions_pbf_listing.Test_pbf_listing.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetPbfListingResult> Invoke(GetPbfListingInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPbfListingResult>("oci:Functions/getPbfListing:getPbfListing", args ?? new GetPbfListingInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPbfListingArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique PbfListing identifier
        /// </summary>
        [Input("pbfListingId", required: true)]
        public string PbfListingId { get; set; } = null!;

        public GetPbfListingArgs()
        {
        }
        public static new GetPbfListingArgs Empty => new GetPbfListingArgs();
    }

    public sealed class GetPbfListingInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique PbfListing identifier
        /// </summary>
        [Input("pbfListingId", required: true)]
        public Input<string> PbfListingId { get; set; } = null!;

        public GetPbfListingInvokeArgs()
        {
        }
        public static new GetPbfListingInvokeArgs Empty => new GetPbfListingInvokeArgs();
    }


    [OutputType]
    public sealed class GetPbfListingResult
    {
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A short overview of the PBF Listing: the purpose of the PBF and and associated information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A brief descriptive name for the PBF trigger.
        /// </summary>
        public readonly string Name;
        public readonly string PbfListingId;
        /// <summary>
        /// Contains details about the publisher of this PBF Listing.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPbfListingPublisherDetailResult> PublisherDetails;
        /// <summary>
        /// The current state of the PBF resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time the PbfListing was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The last time the PbfListing was updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// An array of Trigger. A list of triggers that may activate the PBF.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPbfListingTriggerResult> Triggers;

        [OutputConstructor]
        private GetPbfListingResult(
            ImmutableDictionary<string, object> definedTags,

            string description,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string name,

            string pbfListingId,

            ImmutableArray<Outputs.GetPbfListingPublisherDetailResult> publisherDetails,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated,

            ImmutableArray<Outputs.GetPbfListingTriggerResult> triggers)
        {
            DefinedTags = definedTags;
            Description = description;
            FreeformTags = freeformTags;
            Id = id;
            Name = name;
            PbfListingId = pbfListingId;
            PublisherDetails = publisherDetails;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Triggers = triggers;
        }
    }
}