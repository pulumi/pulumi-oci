// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetUserAssessmentProfileAnalytics
    {
        /// <summary>
        /// This data source provides the list of User Assessment Profile Analytics in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of aggregated user profile details in the specified compartment. This provides information about the
        /// overall profiles available. For example, the user profile details include how many users have the profile assigned
        /// and do how many use password verification function. This data is especially useful content for dashboards or to support analytics.
        /// 
        /// When you perform the ListProfileAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
        /// parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has INSPECT
        /// permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
        /// root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
        /// compartmentId, then "Not Authorized" is returned.
        /// 
        /// The parameter compartmentIdInSubtree applies when you perform ListProfileAnalytics on the compartmentId passed and when it is
        /// set to true, the entire hierarchy of compartments can be returned.
        /// 
        /// To use ListProfileAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
        /// set the parameter compartmentIdInSubtree to true and accessLevel to ACCESSIBLE.
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
        ///     var testUserAssessmentProfileAnalytics = Oci.DataSafe.GetUserAssessmentProfileAnalytics.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         UserAssessmentId = testUserAssessment.Id,
        ///         AccessLevel = userAssessmentProfileAnalyticAccessLevel,
        ///         CompartmentIdInSubtree = userAssessmentProfileAnalyticCompartmentIdInSubtree,
        ///         ProfileName = testProfile.Name,
        ///         TargetId = testTarget.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetUserAssessmentProfileAnalyticsResult> InvokeAsync(GetUserAssessmentProfileAnalyticsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetUserAssessmentProfileAnalyticsResult>("oci:DataSafe/getUserAssessmentProfileAnalytics:getUserAssessmentProfileAnalytics", args ?? new GetUserAssessmentProfileAnalyticsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of User Assessment Profile Analytics in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of aggregated user profile details in the specified compartment. This provides information about the
        /// overall profiles available. For example, the user profile details include how many users have the profile assigned
        /// and do how many use password verification function. This data is especially useful content for dashboards or to support analytics.
        /// 
        /// When you perform the ListProfileAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
        /// parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has INSPECT
        /// permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
        /// root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
        /// compartmentId, then "Not Authorized" is returned.
        /// 
        /// The parameter compartmentIdInSubtree applies when you perform ListProfileAnalytics on the compartmentId passed and when it is
        /// set to true, the entire hierarchy of compartments can be returned.
        /// 
        /// To use ListProfileAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
        /// set the parameter compartmentIdInSubtree to true and accessLevel to ACCESSIBLE.
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
        ///     var testUserAssessmentProfileAnalytics = Oci.DataSafe.GetUserAssessmentProfileAnalytics.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         UserAssessmentId = testUserAssessment.Id,
        ///         AccessLevel = userAssessmentProfileAnalyticAccessLevel,
        ///         CompartmentIdInSubtree = userAssessmentProfileAnalyticCompartmentIdInSubtree,
        ///         ProfileName = testProfile.Name,
        ///         TargetId = testTarget.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetUserAssessmentProfileAnalyticsResult> Invoke(GetUserAssessmentProfileAnalyticsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetUserAssessmentProfileAnalyticsResult>("oci:DataSafe/getUserAssessmentProfileAnalytics:getUserAssessmentProfileAnalytics", args ?? new GetUserAssessmentProfileAnalyticsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of User Assessment Profile Analytics in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of aggregated user profile details in the specified compartment. This provides information about the
        /// overall profiles available. For example, the user profile details include how many users have the profile assigned
        /// and do how many use password verification function. This data is especially useful content for dashboards or to support analytics.
        /// 
        /// When you perform the ListProfileAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
        /// parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has INSPECT
        /// permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
        /// root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
        /// compartmentId, then "Not Authorized" is returned.
        /// 
        /// The parameter compartmentIdInSubtree applies when you perform ListProfileAnalytics on the compartmentId passed and when it is
        /// set to true, the entire hierarchy of compartments can be returned.
        /// 
        /// To use ListProfileAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
        /// set the parameter compartmentIdInSubtree to true and accessLevel to ACCESSIBLE.
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
        ///     var testUserAssessmentProfileAnalytics = Oci.DataSafe.GetUserAssessmentProfileAnalytics.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         UserAssessmentId = testUserAssessment.Id,
        ///         AccessLevel = userAssessmentProfileAnalyticAccessLevel,
        ///         CompartmentIdInSubtree = userAssessmentProfileAnalyticCompartmentIdInSubtree,
        ///         ProfileName = testProfile.Name,
        ///         TargetId = testTarget.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetUserAssessmentProfileAnalyticsResult> Invoke(GetUserAssessmentProfileAnalyticsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetUserAssessmentProfileAnalyticsResult>("oci:DataSafe/getUserAssessmentProfileAnalytics:getUserAssessmentProfileAnalytics", args ?? new GetUserAssessmentProfileAnalyticsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetUserAssessmentProfileAnalyticsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private List<Inputs.GetUserAssessmentProfileAnalyticsFilterArgs>? _filters;
        public List<Inputs.GetUserAssessmentProfileAnalyticsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetUserAssessmentProfileAnalyticsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only items that match the specified profile name.
        /// </summary>
        [Input("profileName")]
        public string? ProfileName { get; set; }

        /// <summary>
        /// A filter to return only items related to a specific target OCID.
        /// </summary>
        [Input("targetId")]
        public string? TargetId { get; set; }

        /// <summary>
        /// The OCID of the user assessment.
        /// </summary>
        [Input("userAssessmentId", required: true)]
        public string UserAssessmentId { get; set; } = null!;

        public GetUserAssessmentProfileAnalyticsArgs()
        {
        }
        public static new GetUserAssessmentProfileAnalyticsArgs Empty => new GetUserAssessmentProfileAnalyticsArgs();
    }

    public sealed class GetUserAssessmentProfileAnalyticsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public Input<string>? AccessLevel { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public Input<bool>? CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetUserAssessmentProfileAnalyticsFilterInputArgs>? _filters;
        public InputList<Inputs.GetUserAssessmentProfileAnalyticsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetUserAssessmentProfileAnalyticsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only items that match the specified profile name.
        /// </summary>
        [Input("profileName")]
        public Input<string>? ProfileName { get; set; }

        /// <summary>
        /// A filter to return only items related to a specific target OCID.
        /// </summary>
        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        /// <summary>
        /// The OCID of the user assessment.
        /// </summary>
        [Input("userAssessmentId", required: true)]
        public Input<string> UserAssessmentId { get; set; } = null!;

        public GetUserAssessmentProfileAnalyticsInvokeArgs()
        {
        }
        public static new GetUserAssessmentProfileAnalyticsInvokeArgs Empty => new GetUserAssessmentProfileAnalyticsInvokeArgs();
    }


    [OutputType]
    public sealed class GetUserAssessmentProfileAnalyticsResult
    {
        public readonly string? AccessLevel;
        public readonly string CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        public readonly ImmutableArray<Outputs.GetUserAssessmentProfileAnalyticsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of profile_aggregations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetUserAssessmentProfileAnalyticsProfileAggregationResult> ProfileAggregations;
        public readonly string? ProfileName;
        public readonly string? TargetId;
        public readonly string UserAssessmentId;

        [OutputConstructor]
        private GetUserAssessmentProfileAnalyticsResult(
            string? accessLevel,

            string compartmentId,

            bool? compartmentIdInSubtree,

            ImmutableArray<Outputs.GetUserAssessmentProfileAnalyticsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetUserAssessmentProfileAnalyticsProfileAggregationResult> profileAggregations,

            string? profileName,

            string? targetId,

            string userAssessmentId)
        {
            AccessLevel = accessLevel;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            Filters = filters;
            Id = id;
            ProfileAggregations = profileAggregations;
            ProfileName = profileName;
            TargetId = targetId;
            UserAssessmentId = userAssessmentId;
        }
    }
}
