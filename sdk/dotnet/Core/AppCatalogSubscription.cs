// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    /// <summary>
    /// This resource provides the App Catalog Subscription resource in Oracle Cloud Infrastructure Core service.
    /// 
    /// Create a subscription for listing resource version for a compartment. It will take some time to propagate to all regions.
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
    ///     var testAppCatalogSubscription = new Oci.Core.AppCatalogSubscription("test_app_catalog_subscription", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         ListingId = testListing.Id,
    ///         ListingResourceVersion = appCatalogSubscriptionListingResourceVersion,
    ///         OracleTermsOfUseLink = appCatalogSubscriptionOracleTermsOfUseLink,
    ///         Signature = appCatalogSubscriptionSignature,
    ///         TimeRetrieved = appCatalogSubscriptionTimeRetrieved,
    ///         EulaLink = appCatalogSubscriptionEulaLink,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// AppCatalogSubscriptions can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Core/appCatalogSubscription:AppCatalogSubscription test_app_catalog_subscription "compartmentId/{compartmentId}/listingId/{listingId}/listingResourceVersion/{listingResourceVersion}"
    /// ```
    /// </summary>
    [OciResourceType("oci:Core/appCatalogSubscription:AppCatalogSubscription")]
    public partial class AppCatalogSubscription : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The compartmentID for the subscription.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// EULA link
        /// </summary>
        [Output("eulaLink")]
        public Output<string?> EulaLink { get; private set; } = null!;

        /// <summary>
        /// The OCID of the listing.
        /// </summary>
        [Output("listingId")]
        public Output<string> ListingId { get; private set; } = null!;

        /// <summary>
        /// Listing resource id.
        /// </summary>
        [Output("listingResourceId")]
        public Output<string> ListingResourceId { get; private set; } = null!;

        /// <summary>
        /// Listing resource version.
        /// </summary>
        [Output("listingResourceVersion")]
        public Output<string> ListingResourceVersion { get; private set; } = null!;

        /// <summary>
        /// Oracle TOU link
        /// </summary>
        [Output("oracleTermsOfUseLink")]
        public Output<string> OracleTermsOfUseLink { get; private set; } = null!;

        /// <summary>
        /// Name of the publisher who published this listing.
        /// </summary>
        [Output("publisherName")]
        public Output<string> PublisherName { get; private set; } = null!;

        /// <summary>
        /// A generated signature for this listing resource version retrieved the agreements API.
        /// </summary>
        [Output("signature")]
        public Output<string> Signature { get; private set; } = null!;

        /// <summary>
        /// The short summary to the listing.
        /// </summary>
        [Output("summary")]
        public Output<string> Summary { get; private set; } = null!;

        /// <summary>
        /// Date and time at which the subscription was created, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("timeRetrieved")]
        public Output<string> TimeRetrieved { get; private set; } = null!;


        /// <summary>
        /// Create a AppCatalogSubscription resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public AppCatalogSubscription(string name, AppCatalogSubscriptionArgs args, CustomResourceOptions? options = null)
            : base("oci:Core/appCatalogSubscription:AppCatalogSubscription", name, args ?? new AppCatalogSubscriptionArgs(), MakeResourceOptions(options, ""))
        {
        }

        private AppCatalogSubscription(string name, Input<string> id, AppCatalogSubscriptionState? state = null, CustomResourceOptions? options = null)
            : base("oci:Core/appCatalogSubscription:AppCatalogSubscription", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing AppCatalogSubscription resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static AppCatalogSubscription Get(string name, Input<string> id, AppCatalogSubscriptionState? state = null, CustomResourceOptions? options = null)
        {
            return new AppCatalogSubscription(name, id, state, options);
        }
    }

    public sealed class AppCatalogSubscriptionArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The compartmentID for the subscription.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// EULA link
        /// </summary>
        [Input("eulaLink")]
        public Input<string>? EulaLink { get; set; }

        /// <summary>
        /// The OCID of the listing.
        /// </summary>
        [Input("listingId", required: true)]
        public Input<string> ListingId { get; set; } = null!;

        /// <summary>
        /// Listing resource version.
        /// </summary>
        [Input("listingResourceVersion", required: true)]
        public Input<string> ListingResourceVersion { get; set; } = null!;

        /// <summary>
        /// Oracle TOU link
        /// </summary>
        [Input("oracleTermsOfUseLink", required: true)]
        public Input<string> OracleTermsOfUseLink { get; set; } = null!;

        /// <summary>
        /// A generated signature for this listing resource version retrieved the agreements API.
        /// </summary>
        [Input("signature", required: true)]
        public Input<string> Signature { get; set; } = null!;

        /// <summary>
        /// Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("timeRetrieved", required: true)]
        public Input<string> TimeRetrieved { get; set; } = null!;

        public AppCatalogSubscriptionArgs()
        {
        }
        public static new AppCatalogSubscriptionArgs Empty => new AppCatalogSubscriptionArgs();
    }

    public sealed class AppCatalogSubscriptionState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The compartmentID for the subscription.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// EULA link
        /// </summary>
        [Input("eulaLink")]
        public Input<string>? EulaLink { get; set; }

        /// <summary>
        /// The OCID of the listing.
        /// </summary>
        [Input("listingId")]
        public Input<string>? ListingId { get; set; }

        /// <summary>
        /// Listing resource id.
        /// </summary>
        [Input("listingResourceId")]
        public Input<string>? ListingResourceId { get; set; }

        /// <summary>
        /// Listing resource version.
        /// </summary>
        [Input("listingResourceVersion")]
        public Input<string>? ListingResourceVersion { get; set; }

        /// <summary>
        /// Oracle TOU link
        /// </summary>
        [Input("oracleTermsOfUseLink")]
        public Input<string>? OracleTermsOfUseLink { get; set; }

        /// <summary>
        /// Name of the publisher who published this listing.
        /// </summary>
        [Input("publisherName")]
        public Input<string>? PublisherName { get; set; }

        /// <summary>
        /// A generated signature for this listing resource version retrieved the agreements API.
        /// </summary>
        [Input("signature")]
        public Input<string>? Signature { get; set; }

        /// <summary>
        /// The short summary to the listing.
        /// </summary>
        [Input("summary")]
        public Input<string>? Summary { get; set; }

        /// <summary>
        /// Date and time at which the subscription was created, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("timeRetrieved")]
        public Input<string>? TimeRetrieved { get; set; }

        public AppCatalogSubscriptionState()
        {
        }
        public static new AppCatalogSubscriptionState Empty => new AppCatalogSubscriptionState();
    }
}
