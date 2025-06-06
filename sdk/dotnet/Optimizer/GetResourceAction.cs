// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer
{
    public static class GetResourceAction
    {
        /// <summary>
        /// This data source provides details about a specific Resource Action resource in Oracle Cloud Infrastructure Optimizer service.
        /// 
        /// Gets the resource action that corresponds to the specified OCID.
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
        ///     var testResourceAction = Oci.Optimizer.GetResourceAction.Invoke(new()
        ///     {
        ///         ResourceActionId = testResourceActionOciOptimizerResourceAction.Id,
        ///         IncludeResourceMetadata = resourceActionIncludeResourceMetadata,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetResourceActionResult> InvokeAsync(GetResourceActionArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetResourceActionResult>("oci:Optimizer/getResourceAction:getResourceAction", args ?? new GetResourceActionArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Resource Action resource in Oracle Cloud Infrastructure Optimizer service.
        /// 
        /// Gets the resource action that corresponds to the specified OCID.
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
        ///     var testResourceAction = Oci.Optimizer.GetResourceAction.Invoke(new()
        ///     {
        ///         ResourceActionId = testResourceActionOciOptimizerResourceAction.Id,
        ///         IncludeResourceMetadata = resourceActionIncludeResourceMetadata,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetResourceActionResult> Invoke(GetResourceActionInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetResourceActionResult>("oci:Optimizer/getResourceAction:getResourceAction", args ?? new GetResourceActionInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Resource Action resource in Oracle Cloud Infrastructure Optimizer service.
        /// 
        /// Gets the resource action that corresponds to the specified OCID.
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
        ///     var testResourceAction = Oci.Optimizer.GetResourceAction.Invoke(new()
        ///     {
        ///         ResourceActionId = testResourceActionOciOptimizerResourceAction.Id,
        ///         IncludeResourceMetadata = resourceActionIncludeResourceMetadata,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetResourceActionResult> Invoke(GetResourceActionInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetResourceActionResult>("oci:Optimizer/getResourceAction:getResourceAction", args ?? new GetResourceActionInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetResourceActionArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Supplement additional resource information in extended metadata response.
        /// </summary>
        [Input("includeResourceMetadata")]
        public bool? IncludeResourceMetadata { get; set; }

        /// <summary>
        /// The unique OCID associated with the resource action.
        /// </summary>
        [Input("resourceActionId", required: true)]
        public string ResourceActionId { get; set; } = null!;

        public GetResourceActionArgs()
        {
        }
        public static new GetResourceActionArgs Empty => new GetResourceActionArgs();
    }

    public sealed class GetResourceActionInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Supplement additional resource information in extended metadata response.
        /// </summary>
        [Input("includeResourceMetadata")]
        public Input<bool>? IncludeResourceMetadata { get; set; }

        /// <summary>
        /// The unique OCID associated with the resource action.
        /// </summary>
        [Input("resourceActionId", required: true)]
        public Input<string> ResourceActionId { get; set; } = null!;

        public GetResourceActionInvokeArgs()
        {
        }
        public static new GetResourceActionInvokeArgs Empty => new GetResourceActionInvokeArgs();
    }


    [OutputType]
    public sealed class GetResourceActionResult
    {
        /// <summary>
        /// Details about the recommended action.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetResourceActionActionResult> Actions;
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        public readonly string CategoryId;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The name associated with the compartment.
        /// </summary>
        public readonly string CompartmentName;
        /// <summary>
        /// The estimated cost savings, in dollars, for the resource action.
        /// </summary>
        public readonly double EstimatedCostSaving;
        /// <summary>
        /// Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
        /// </summary>
        public readonly ImmutableDictionary<string, string> ExtendedMetadata;
        /// <summary>
        /// The unique OCID associated with the resource action.
        /// </summary>
        public readonly string Id;
        public readonly bool? IncludeResourceMetadata;
        /// <summary>
        /// Custom metadata key/value pairs for the resource action.
        /// </summary>
        public readonly ImmutableDictionary<string, string> Metadata;
        /// <summary>
        /// The name assigned to the resource.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The unique OCID associated with the recommendation.
        /// </summary>
        public readonly string RecommendationId;
        public readonly string ResourceActionId;
        /// <summary>
        /// The unique OCID associated with the resource.
        /// </summary>
        public readonly string ResourceId;
        /// <summary>
        /// The kind of resource.
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// The resource action's current state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The current status of the resource action.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The date and time the resource action details were created, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time that the resource action entered its current status. The format is defined by RFC3339.
        /// </summary>
        public readonly string TimeStatusBegin;
        /// <summary>
        /// The date and time the current status will change. The format is defined by RFC3339.
        /// </summary>
        public readonly string TimeStatusEnd;
        /// <summary>
        /// The date and time the resource action details were last updated, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetResourceActionResult(
            ImmutableArray<Outputs.GetResourceActionActionResult> actions,

            string categoryId,

            string compartmentId,

            string compartmentName,

            double estimatedCostSaving,

            ImmutableDictionary<string, string> extendedMetadata,

            string id,

            bool? includeResourceMetadata,

            ImmutableDictionary<string, string> metadata,

            string name,

            string recommendationId,

            string resourceActionId,

            string resourceId,

            string resourceType,

            string state,

            string status,

            string timeCreated,

            string timeStatusBegin,

            string timeStatusEnd,

            string timeUpdated)
        {
            Actions = actions;
            CategoryId = categoryId;
            CompartmentId = compartmentId;
            CompartmentName = compartmentName;
            EstimatedCostSaving = estimatedCostSaving;
            ExtendedMetadata = extendedMetadata;
            Id = id;
            IncludeResourceMetadata = includeResourceMetadata;
            Metadata = metadata;
            Name = name;
            RecommendationId = recommendationId;
            ResourceActionId = resourceActionId;
            ResourceId = resourceId;
            ResourceType = resourceType;
            State = state;
            Status = status;
            TimeCreated = timeCreated;
            TimeStatusBegin = timeStatusBegin;
            TimeStatusEnd = timeStatusEnd;
            TimeUpdated = timeUpdated;
        }
    }
}
