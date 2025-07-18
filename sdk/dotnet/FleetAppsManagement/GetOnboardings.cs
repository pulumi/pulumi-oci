// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement
{
    public static class GetOnboardings
    {
        /// <summary>
        /// This data source provides the list of Onboardings in Oracle Cloud Infrastructure Fleet Apps Management service.
        /// 
        /// Returns a list of all the onboardings in the specified root compartment (tenancy).
        /// The query parameter `compartmentId` is required unless the query parameter `id` is specified.
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
        ///     var testOnboardings = Oci.FleetAppsManagement.GetOnboardings.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Id = onboardingId,
        ///         State = onboardingState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetOnboardingsResult> InvokeAsync(GetOnboardingsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetOnboardingsResult>("oci:FleetAppsManagement/getOnboardings:getOnboardings", args ?? new GetOnboardingsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Onboardings in Oracle Cloud Infrastructure Fleet Apps Management service.
        /// 
        /// Returns a list of all the onboardings in the specified root compartment (tenancy).
        /// The query parameter `compartmentId` is required unless the query parameter `id` is specified.
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
        ///     var testOnboardings = Oci.FleetAppsManagement.GetOnboardings.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Id = onboardingId,
        ///         State = onboardingState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOnboardingsResult> Invoke(GetOnboardingsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetOnboardingsResult>("oci:FleetAppsManagement/getOnboardings:getOnboardings", args ?? new GetOnboardingsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Onboardings in Oracle Cloud Infrastructure Fleet Apps Management service.
        /// 
        /// Returns a list of all the onboardings in the specified root compartment (tenancy).
        /// The query parameter `compartmentId` is required unless the query parameter `id` is specified.
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
        ///     var testOnboardings = Oci.FleetAppsManagement.GetOnboardings.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Id = onboardingId,
        ///         State = onboardingState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOnboardingsResult> Invoke(GetOnboardingsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetOnboardingsResult>("oci:FleetAppsManagement/getOnboardings:getOnboardings", args ?? new GetOnboardingsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOnboardingsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        [Input("filters")]
        private List<Inputs.GetOnboardingsFilterArgs>? _filters;
        public List<Inputs.GetOnboardingsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetOnboardingsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single onboarding by id. Either compartmentId or id must be provided.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return only resources whose lifecycleState matches the given lifecycleState.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetOnboardingsArgs()
        {
        }
        public static new GetOnboardingsArgs Empty => new GetOnboardingsArgs();
    }

    public sealed class GetOnboardingsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetOnboardingsFilterInputArgs>? _filters;
        public InputList<Inputs.GetOnboardingsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetOnboardingsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single onboarding by id. Either compartmentId or id must be provided.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// A filter to return only resources whose lifecycleState matches the given lifecycleState.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetOnboardingsInvokeArgs()
        {
        }
        public static new GetOnboardingsInvokeArgs Empty => new GetOnboardingsInvokeArgs();
    }


    [OutputType]
    public sealed class GetOnboardingsResult
    {
        /// <summary>
        /// Tenancy OCID
        /// </summary>
        public readonly string? CompartmentId;
        public readonly ImmutableArray<Outputs.GetOnboardingsFilterResult> Filters;
        /// <summary>
        /// The unique id of the resource.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of onboarding_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOnboardingsOnboardingCollectionResult> OnboardingCollections;
        /// <summary>
        /// The current state of the Onboarding.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetOnboardingsResult(
            string? compartmentId,

            ImmutableArray<Outputs.GetOnboardingsFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetOnboardingsOnboardingCollectionResult> onboardingCollections,

            string? state)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            OnboardingCollections = onboardingCollections;
            State = state;
        }
    }
}
