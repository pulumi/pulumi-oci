// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer
{
    public static class GetRecommendations
    {
        /// <summary>
        /// This data source provides the list of Recommendations in Oracle Cloud Infrastructure Optimizer service.
        /// 
        /// Lists the Cloud Advisor recommendations that are currently supported in the specified category.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testRecommendations = Output.Create(Oci.Optimizer.GetRecommendations.InvokeAsync(new Oci.Optimizer.GetRecommendationsArgs
        ///         {
        ///             CategoryId = oci_optimizer_category.Test_category.Id,
        ///             CompartmentId = @var.Compartment_id,
        ///             CompartmentIdInSubtree = @var.Recommendation_compartment_id_in_subtree,
        ///             Name = @var.Recommendation_name,
        ///             State = @var.Recommendation_state,
        ///             Status = @var.Recommendation_status,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRecommendationsResult> InvokeAsync(GetRecommendationsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetRecommendationsResult>("oci:Optimizer/getRecommendations:getRecommendations", args ?? new GetRecommendationsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Recommendations in Oracle Cloud Infrastructure Optimizer service.
        /// 
        /// Lists the Cloud Advisor recommendations that are currently supported in the specified category.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testRecommendations = Output.Create(Oci.Optimizer.GetRecommendations.InvokeAsync(new Oci.Optimizer.GetRecommendationsArgs
        ///         {
        ///             CategoryId = oci_optimizer_category.Test_category.Id,
        ///             CompartmentId = @var.Compartment_id,
        ///             CompartmentIdInSubtree = @var.Recommendation_compartment_id_in_subtree,
        ///             Name = @var.Recommendation_name,
        ///             State = @var.Recommendation_state,
        ///             Status = @var.Recommendation_status,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetRecommendationsResult> Invoke(GetRecommendationsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetRecommendationsResult>("oci:Optimizer/getRecommendations:getRecommendations", args ?? new GetRecommendationsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRecommendationsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        [Input("categoryId", required: true)]
        public string CategoryId { get; set; } = null!;

        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
        /// </summary>
        [Input("compartmentIdInSubtree", required: true)]
        public bool CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private List<Inputs.GetRecommendationsFilterArgs>? _filters;
        public List<Inputs.GetRecommendationsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetRecommendationsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Optional. A filter that returns results that match the name specified.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// A filter that returns results that match the lifecycle state specified.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// A filter that returns recommendations that match the status specified.
        /// </summary>
        [Input("status")]
        public string? Status { get; set; }

        public GetRecommendationsArgs()
        {
        }
    }

    public sealed class GetRecommendationsInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        [Input("categoryId", required: true)]
        public Input<string> CategoryId { get; set; } = null!;

        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
        /// </summary>
        [Input("compartmentIdInSubtree", required: true)]
        public Input<bool> CompartmentIdInSubtree { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetRecommendationsFilterInputArgs>? _filters;
        public InputList<Inputs.GetRecommendationsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetRecommendationsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Optional. A filter that returns results that match the name specified.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A filter that returns results that match the lifecycle state specified.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// A filter that returns recommendations that match the status specified.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        public GetRecommendationsInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetRecommendationsResult
    {
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        public readonly string CategoryId;
        /// <summary>
        /// The OCID of the tenancy. The tenancy is the root compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool CompartmentIdInSubtree;
        public readonly ImmutableArray<Outputs.GetRecommendationsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the profile level.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The list of recommendation_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRecommendationsRecommendationCollectionResult> RecommendationCollections;
        /// <summary>
        /// The recommendation's current state.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The current status of the recommendation.
        /// </summary>
        public readonly string? Status;

        [OutputConstructor]
        private GetRecommendationsResult(
            string categoryId,

            string compartmentId,

            bool compartmentIdInSubtree,

            ImmutableArray<Outputs.GetRecommendationsFilterResult> filters,

            string id,

            string? name,

            ImmutableArray<Outputs.GetRecommendationsRecommendationCollectionResult> recommendationCollections,

            string? state,

            string? status)
        {
            CategoryId = categoryId;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            Filters = filters;
            Id = id;
            Name = name;
            RecommendationCollections = recommendationCollections;
            State = state;
            Status = status;
        }
    }
}
