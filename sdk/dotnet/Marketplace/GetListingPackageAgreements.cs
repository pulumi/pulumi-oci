// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Marketplace
{
    public static class GetListingPackageAgreements
    {
        /// <summary>
        /// This data source provides the list of Listing Package Agreements in Oracle Cloud Infrastructure Marketplace service.
        /// 
        /// Returns the terms of use agreements that must be accepted before you can deploy the specified version of a package.
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
        ///     var testListingPackageAgreements = Oci.Marketplace.GetListingPackageAgreements.Invoke(new()
        ///     {
        ///         ListingId = testListing.Id,
        ///         PackageVersion = listingPackageAgreementPackageVersion,
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetListingPackageAgreementsResult> InvokeAsync(GetListingPackageAgreementsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetListingPackageAgreementsResult>("oci:Marketplace/getListingPackageAgreements:getListingPackageAgreements", args ?? new GetListingPackageAgreementsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Listing Package Agreements in Oracle Cloud Infrastructure Marketplace service.
        /// 
        /// Returns the terms of use agreements that must be accepted before you can deploy the specified version of a package.
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
        ///     var testListingPackageAgreements = Oci.Marketplace.GetListingPackageAgreements.Invoke(new()
        ///     {
        ///         ListingId = testListing.Id,
        ///         PackageVersion = listingPackageAgreementPackageVersion,
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetListingPackageAgreementsResult> Invoke(GetListingPackageAgreementsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetListingPackageAgreementsResult>("oci:Marketplace/getListingPackageAgreements:getListingPackageAgreements", args ?? new GetListingPackageAgreementsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Listing Package Agreements in Oracle Cloud Infrastructure Marketplace service.
        /// 
        /// Returns the terms of use agreements that must be accepted before you can deploy the specified version of a package.
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
        ///     var testListingPackageAgreements = Oci.Marketplace.GetListingPackageAgreements.Invoke(new()
        ///     {
        ///         ListingId = testListing.Id,
        ///         PackageVersion = listingPackageAgreementPackageVersion,
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetListingPackageAgreementsResult> Invoke(GetListingPackageAgreementsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetListingPackageAgreementsResult>("oci:Marketplace/getListingPackageAgreements:getListingPackageAgreements", args ?? new GetListingPackageAgreementsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetListingPackageAgreementsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier for the compartment.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        [Input("filters")]
        private List<Inputs.GetListingPackageAgreementsFilterArgs>? _filters;
        public List<Inputs.GetListingPackageAgreementsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetListingPackageAgreementsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The unique identifier for the listing.
        /// </summary>
        [Input("listingId", required: true)]
        public string ListingId { get; set; } = null!;

        /// <summary>
        /// The version of the package. Package versions are unique within a listing.
        /// </summary>
        [Input("packageVersion", required: true)]
        public string PackageVersion { get; set; } = null!;

        public GetListingPackageAgreementsArgs()
        {
        }
        public static new GetListingPackageAgreementsArgs Empty => new GetListingPackageAgreementsArgs();
    }

    public sealed class GetListingPackageAgreementsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier for the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetListingPackageAgreementsFilterInputArgs>? _filters;
        public InputList<Inputs.GetListingPackageAgreementsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetListingPackageAgreementsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The unique identifier for the listing.
        /// </summary>
        [Input("listingId", required: true)]
        public Input<string> ListingId { get; set; } = null!;

        /// <summary>
        /// The version of the package. Package versions are unique within a listing.
        /// </summary>
        [Input("packageVersion", required: true)]
        public Input<string> PackageVersion { get; set; } = null!;

        public GetListingPackageAgreementsInvokeArgs()
        {
        }
        public static new GetListingPackageAgreementsInvokeArgs Empty => new GetListingPackageAgreementsInvokeArgs();
    }


    [OutputType]
    public sealed class GetListingPackageAgreementsResult
    {
        /// <summary>
        /// The list of agreements.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingPackageAgreementsAgreementResult> Agreements;
        /// <summary>
        /// The unique identifier for the compartment.
        /// </summary>
        public readonly string? CompartmentId;
        public readonly ImmutableArray<Outputs.GetListingPackageAgreementsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string ListingId;
        public readonly string PackageVersion;

        [OutputConstructor]
        private GetListingPackageAgreementsResult(
            ImmutableArray<Outputs.GetListingPackageAgreementsAgreementResult> agreements,

            string? compartmentId,

            ImmutableArray<Outputs.GetListingPackageAgreementsFilterResult> filters,

            string id,

            string listingId,

            string packageVersion)
        {
            Agreements = agreements;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            ListingId = listingId;
            PackageVersion = packageVersion;
        }
    }
}
