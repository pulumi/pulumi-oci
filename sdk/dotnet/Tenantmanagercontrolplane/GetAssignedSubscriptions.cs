// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Tenantmanagercontrolplane
{
    public static class GetAssignedSubscriptions
    {
        /// <summary>
        /// This data source provides the list of Assigned Subscriptions in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
        /// 
        /// Lists subscriptions that are consumed by the compartment. Only the root compartment is allowed.
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
        ///     var testAssignedSubscriptions = Oci.Tenantmanagercontrolplane.GetAssignedSubscriptions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         EntityVersion = assignedSubscriptionEntityVersion,
        ///         SubscriptionId = testSubscription.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAssignedSubscriptionsResult> InvokeAsync(GetAssignedSubscriptionsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAssignedSubscriptionsResult>("oci:Tenantmanagercontrolplane/getAssignedSubscriptions:getAssignedSubscriptions", args ?? new GetAssignedSubscriptionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Assigned Subscriptions in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
        /// 
        /// Lists subscriptions that are consumed by the compartment. Only the root compartment is allowed.
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
        ///     var testAssignedSubscriptions = Oci.Tenantmanagercontrolplane.GetAssignedSubscriptions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         EntityVersion = assignedSubscriptionEntityVersion,
        ///         SubscriptionId = testSubscription.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAssignedSubscriptionsResult> Invoke(GetAssignedSubscriptionsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAssignedSubscriptionsResult>("oci:Tenantmanagercontrolplane/getAssignedSubscriptions:getAssignedSubscriptions", args ?? new GetAssignedSubscriptionsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Assigned Subscriptions in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
        /// 
        /// Lists subscriptions that are consumed by the compartment. Only the root compartment is allowed.
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
        ///     var testAssignedSubscriptions = Oci.Tenantmanagercontrolplane.GetAssignedSubscriptions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         EntityVersion = assignedSubscriptionEntityVersion,
        ///         SubscriptionId = testSubscription.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAssignedSubscriptionsResult> Invoke(GetAssignedSubscriptionsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAssignedSubscriptionsResult>("oci:Tenantmanagercontrolplane/getAssignedSubscriptions:getAssignedSubscriptions", args ?? new GetAssignedSubscriptionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAssignedSubscriptionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The version of the subscription entity.
        /// </summary>
        [Input("entityVersion")]
        public string? EntityVersion { get; set; }

        [Input("filters")]
        private List<Inputs.GetAssignedSubscriptionsFilterArgs>? _filters;
        public List<Inputs.GetAssignedSubscriptionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAssignedSubscriptionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The ID of the subscription to which the tenancy is associated.
        /// </summary>
        [Input("subscriptionId")]
        public string? SubscriptionId { get; set; }

        public GetAssignedSubscriptionsArgs()
        {
        }
        public static new GetAssignedSubscriptionsArgs Empty => new GetAssignedSubscriptionsArgs();
    }

    public sealed class GetAssignedSubscriptionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The version of the subscription entity.
        /// </summary>
        [Input("entityVersion")]
        public Input<string>? EntityVersion { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetAssignedSubscriptionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetAssignedSubscriptionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAssignedSubscriptionsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The ID of the subscription to which the tenancy is associated.
        /// </summary>
        [Input("subscriptionId")]
        public Input<string>? SubscriptionId { get; set; }

        public GetAssignedSubscriptionsInvokeArgs()
        {
        }
        public static new GetAssignedSubscriptionsInvokeArgs Empty => new GetAssignedSubscriptionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetAssignedSubscriptionsResult
    {
        /// <summary>
        /// The list of assigned_subscription_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAssignedSubscriptionsAssignedSubscriptionCollectionResult> AssignedSubscriptionCollections;
        /// <summary>
        /// The Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the owning compartment. Always a tenancy OCID.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The entity version of the subscription, whether V1 (the legacy schema version), or V2 (the latest 20230401 API version).
        /// </summary>
        public readonly string? EntityVersion;
        public readonly ImmutableArray<Outputs.GetAssignedSubscriptionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? SubscriptionId;

        [OutputConstructor]
        private GetAssignedSubscriptionsResult(
            ImmutableArray<Outputs.GetAssignedSubscriptionsAssignedSubscriptionCollectionResult> assignedSubscriptionCollections,

            string compartmentId,

            string? entityVersion,

            ImmutableArray<Outputs.GetAssignedSubscriptionsFilterResult> filters,

            string id,

            string? subscriptionId)
        {
            AssignedSubscriptionCollections = assignedSubscriptionCollections;
            CompartmentId = compartmentId;
            EntityVersion = entityVersion;
            Filters = filters;
            Id = id;
            SubscriptionId = subscriptionId;
        }
    }
}
