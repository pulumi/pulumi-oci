// *** WARNING: this file was generated by pulumi-language-dotnet. ***
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
        /// Lists the Cloud Advisor recommendations that are currently supported.
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
        ///     var testRecommendations = Oci.Optimizer.GetRecommendations.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = recommendationCompartmentIdInSubtree,
        ///         CategoryId = testCategory.Id,
        ///         CategoryName = testCategory.Name,
        ///         ChildTenancyIds = recommendationChildTenancyIds,
        ///         IncludeOrganization = recommendationIncludeOrganization,
        ///         Name = recommendationName,
        ///         State = recommendationState,
        ///         Status = recommendationStatus,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetRecommendationsResult> InvokeAsync(GetRecommendationsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetRecommendationsResult>("oci:Optimizer/getRecommendations:getRecommendations", args ?? new GetRecommendationsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Recommendations in Oracle Cloud Infrastructure Optimizer service.
        /// 
        /// Lists the Cloud Advisor recommendations that are currently supported.
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
        ///     var testRecommendations = Oci.Optimizer.GetRecommendations.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = recommendationCompartmentIdInSubtree,
        ///         CategoryId = testCategory.Id,
        ///         CategoryName = testCategory.Name,
        ///         ChildTenancyIds = recommendationChildTenancyIds,
        ///         IncludeOrganization = recommendationIncludeOrganization,
        ///         Name = recommendationName,
        ///         State = recommendationState,
        ///         Status = recommendationStatus,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRecommendationsResult> Invoke(GetRecommendationsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetRecommendationsResult>("oci:Optimizer/getRecommendations:getRecommendations", args ?? new GetRecommendationsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Recommendations in Oracle Cloud Infrastructure Optimizer service.
        /// 
        /// Lists the Cloud Advisor recommendations that are currently supported.
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
        ///     var testRecommendations = Oci.Optimizer.GetRecommendations.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = recommendationCompartmentIdInSubtree,
        ///         CategoryId = testCategory.Id,
        ///         CategoryName = testCategory.Name,
        ///         ChildTenancyIds = recommendationChildTenancyIds,
        ///         IncludeOrganization = recommendationIncludeOrganization,
        ///         Name = recommendationName,
        ///         State = recommendationState,
        ///         Status = recommendationStatus,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRecommendationsResult> Invoke(GetRecommendationsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetRecommendationsResult>("oci:Optimizer/getRecommendations:getRecommendations", args ?? new GetRecommendationsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRecommendationsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        [Input("categoryId")]
        public string? CategoryId { get; set; }

        /// <summary>
        /// Optional. A filter that returns results that match the category name specified.
        /// </summary>
        [Input("categoryName")]
        public string? CategoryName { get; set; }

        [Input("childTenancyIds")]
        private List<string>? _childTenancyIds;

        /// <summary>
        /// A list of child tenancies for which the respective data will be returned. Please note that  the parent tenancy id can also be included in this list. For example, if there is a parent P with two children A and B, to return results of only parent P and child A, this list should be populated with  tenancy id of parent P and child A. 
        /// 
        /// If this list contains a tenancy id that isn't part of the organization of parent P, the request will  fail. That is, let's say there is an organization with parent P with children A and B, and also one  other tenant T that isn't part of the organization. If T is included in the list of  childTenancyIds, the request will fail.
        /// 
        /// It is important to note that if you are setting the includeOrganization parameter value as true and  also populating the childTenancyIds parameter with a list of child tenancies, the request will fail. The childTenancyIds and includeOrganization should be used exclusively.
        /// 
        /// When using this parameter, please make sure to set the compartmentId with the parent tenancy ID.
        /// </summary>
        public List<string> ChildTenancyIds
        {
            get => _childTenancyIds ?? (_childTenancyIds = new List<string>());
            set => _childTenancyIds = value;
        }

        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
        /// 
        /// Can only be set to true when performing ListCompartments on the tenancy (root compartment).
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
        /// When set to true, the data for all child tenancies including the parent is returned. That is, if  there is an organization with parent P and children A and B, to return the data for the parent P, child  A and child B, this parameter value should be set to true.
        /// 
        /// Please note that this parameter shouldn't be used along with childTenancyIds parameter. If you would like  to get results specifically for parent P and only child A, use the childTenancyIds parameter and populate the list with tenancy id of P and A.
        /// 
        /// When using this parameter, please make sure to set the compartmentId with the parent tenancy ID.
        /// </summary>
        [Input("includeOrganization")]
        public bool? IncludeOrganization { get; set; }

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
        public static new GetRecommendationsArgs Empty => new GetRecommendationsArgs();
    }

    public sealed class GetRecommendationsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        [Input("categoryId")]
        public Input<string>? CategoryId { get; set; }

        /// <summary>
        /// Optional. A filter that returns results that match the category name specified.
        /// </summary>
        [Input("categoryName")]
        public Input<string>? CategoryName { get; set; }

        [Input("childTenancyIds")]
        private InputList<string>? _childTenancyIds;

        /// <summary>
        /// A list of child tenancies for which the respective data will be returned. Please note that  the parent tenancy id can also be included in this list. For example, if there is a parent P with two children A and B, to return results of only parent P and child A, this list should be populated with  tenancy id of parent P and child A. 
        /// 
        /// If this list contains a tenancy id that isn't part of the organization of parent P, the request will  fail. That is, let's say there is an organization with parent P with children A and B, and also one  other tenant T that isn't part of the organization. If T is included in the list of  childTenancyIds, the request will fail.
        /// 
        /// It is important to note that if you are setting the includeOrganization parameter value as true and  also populating the childTenancyIds parameter with a list of child tenancies, the request will fail. The childTenancyIds and includeOrganization should be used exclusively.
        /// 
        /// When using this parameter, please make sure to set the compartmentId with the parent tenancy ID.
        /// </summary>
        public InputList<string> ChildTenancyIds
        {
            get => _childTenancyIds ?? (_childTenancyIds = new InputList<string>());
            set => _childTenancyIds = value;
        }

        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
        /// 
        /// Can only be set to true when performing ListCompartments on the tenancy (root compartment).
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
        /// When set to true, the data for all child tenancies including the parent is returned. That is, if  there is an organization with parent P and children A and B, to return the data for the parent P, child  A and child B, this parameter value should be set to true.
        /// 
        /// Please note that this parameter shouldn't be used along with childTenancyIds parameter. If you would like  to get results specifically for parent P and only child A, use the childTenancyIds parameter and populate the list with tenancy id of P and A.
        /// 
        /// When using this parameter, please make sure to set the compartmentId with the parent tenancy ID.
        /// </summary>
        [Input("includeOrganization")]
        public Input<bool>? IncludeOrganization { get; set; }

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
        public static new GetRecommendationsInvokeArgs Empty => new GetRecommendationsInvokeArgs();
    }


    [OutputType]
    public sealed class GetRecommendationsResult
    {
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        public readonly string? CategoryId;
        public readonly string? CategoryName;
        public readonly ImmutableArray<string> ChildTenancyIds;
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
        public readonly bool? IncludeOrganization;
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
            string? categoryId,

            string? categoryName,

            ImmutableArray<string> childTenancyIds,

            string compartmentId,

            bool compartmentIdInSubtree,

            ImmutableArray<Outputs.GetRecommendationsFilterResult> filters,

            string id,

            bool? includeOrganization,

            string? name,

            ImmutableArray<Outputs.GetRecommendationsRecommendationCollectionResult> recommendationCollections,

            string? state,

            string? status)
        {
            CategoryId = categoryId;
            CategoryName = categoryName;
            ChildTenancyIds = childTenancyIds;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            Filters = filters;
            Id = id;
            IncludeOrganization = includeOrganization;
            Name = name;
            RecommendationCollections = recommendationCollections;
            State = state;
            Status = status;
        }
    }
}
