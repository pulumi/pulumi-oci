// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetUserAssessmentUserAnalytics
    {
        /// <summary>
        /// This data source provides the list of User Assessment User Analytics in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of aggregated user details from the specified user assessment. This provides information about the overall state.
        /// of database user security.  For example, the user details include how many users have the DBA role and how many users are in
        /// the critical category. This data is especially useful content for dashboards or to support analytics.
        /// 
        /// When you perform the ListUserAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
        /// parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has READ
        /// permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
        /// root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
        /// compartmentId, then "Not Authorized" is returned.
        /// 
        /// The parameter compartmentIdInSubtree applies when you perform ListUserAnalytics on the compartmentId passed and when it is
        /// set to true, the entire hierarchy of compartments can be returned.
        /// 
        /// To use ListUserAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
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
        ///     var testUserAssessmentUserAnalytics = Oci.DataSafe.GetUserAssessmentUserAnalytics.Invoke(new()
        ///     {
        ///         UserAssessmentId = testUserAssessment.Id,
        ///         AccessLevel = userAssessmentUserAnalyticAccessLevel,
        ///         AccountStatus = userAssessmentUserAnalyticAccountStatus,
        ///         AuthenticationType = userAssessmentUserAnalyticAuthenticationType,
        ///         CompartmentIdInSubtree = userAssessmentUserAnalyticCompartmentIdInSubtree,
        ///         TargetId = testTarget.Id,
        ///         TimeLastLoginGreaterThanOrEqualTo = userAssessmentUserAnalyticTimeLastLoginGreaterThanOrEqualTo,
        ///         TimeLastLoginLessThan = userAssessmentUserAnalyticTimeLastLoginLessThan,
        ///         TimePasswordExpiryGreaterThanOrEqualTo = userAssessmentUserAnalyticTimePasswordExpiryGreaterThanOrEqualTo,
        ///         TimePasswordExpiryLessThan = userAssessmentUserAnalyticTimePasswordExpiryLessThan,
        ///         TimePasswordLastChangedGreaterThanOrEqualTo = userAssessmentUserAnalyticTimePasswordLastChangedGreaterThanOrEqualTo,
        ///         TimePasswordLastChangedLessThan = userAssessmentUserAnalyticTimePasswordLastChangedLessThan,
        ///         TimeUserCreatedGreaterThanOrEqualTo = userAssessmentUserAnalyticTimeUserCreatedGreaterThanOrEqualTo,
        ///         TimeUserCreatedLessThan = userAssessmentUserAnalyticTimeUserCreatedLessThan,
        ///         UserCategory = userAssessmentUserAnalyticUserCategory,
        ///         UserKey = userAssessmentUserAnalyticUserKey,
        ///         UserName = testUser.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetUserAssessmentUserAnalyticsResult> InvokeAsync(GetUserAssessmentUserAnalyticsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetUserAssessmentUserAnalyticsResult>("oci:DataSafe/getUserAssessmentUserAnalytics:getUserAssessmentUserAnalytics", args ?? new GetUserAssessmentUserAnalyticsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of User Assessment User Analytics in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of aggregated user details from the specified user assessment. This provides information about the overall state.
        /// of database user security.  For example, the user details include how many users have the DBA role and how many users are in
        /// the critical category. This data is especially useful content for dashboards or to support analytics.
        /// 
        /// When you perform the ListUserAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
        /// parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has READ
        /// permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
        /// root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
        /// compartmentId, then "Not Authorized" is returned.
        /// 
        /// The parameter compartmentIdInSubtree applies when you perform ListUserAnalytics on the compartmentId passed and when it is
        /// set to true, the entire hierarchy of compartments can be returned.
        /// 
        /// To use ListUserAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
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
        ///     var testUserAssessmentUserAnalytics = Oci.DataSafe.GetUserAssessmentUserAnalytics.Invoke(new()
        ///     {
        ///         UserAssessmentId = testUserAssessment.Id,
        ///         AccessLevel = userAssessmentUserAnalyticAccessLevel,
        ///         AccountStatus = userAssessmentUserAnalyticAccountStatus,
        ///         AuthenticationType = userAssessmentUserAnalyticAuthenticationType,
        ///         CompartmentIdInSubtree = userAssessmentUserAnalyticCompartmentIdInSubtree,
        ///         TargetId = testTarget.Id,
        ///         TimeLastLoginGreaterThanOrEqualTo = userAssessmentUserAnalyticTimeLastLoginGreaterThanOrEqualTo,
        ///         TimeLastLoginLessThan = userAssessmentUserAnalyticTimeLastLoginLessThan,
        ///         TimePasswordExpiryGreaterThanOrEqualTo = userAssessmentUserAnalyticTimePasswordExpiryGreaterThanOrEqualTo,
        ///         TimePasswordExpiryLessThan = userAssessmentUserAnalyticTimePasswordExpiryLessThan,
        ///         TimePasswordLastChangedGreaterThanOrEqualTo = userAssessmentUserAnalyticTimePasswordLastChangedGreaterThanOrEqualTo,
        ///         TimePasswordLastChangedLessThan = userAssessmentUserAnalyticTimePasswordLastChangedLessThan,
        ///         TimeUserCreatedGreaterThanOrEqualTo = userAssessmentUserAnalyticTimeUserCreatedGreaterThanOrEqualTo,
        ///         TimeUserCreatedLessThan = userAssessmentUserAnalyticTimeUserCreatedLessThan,
        ///         UserCategory = userAssessmentUserAnalyticUserCategory,
        ///         UserKey = userAssessmentUserAnalyticUserKey,
        ///         UserName = testUser.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetUserAssessmentUserAnalyticsResult> Invoke(GetUserAssessmentUserAnalyticsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetUserAssessmentUserAnalyticsResult>("oci:DataSafe/getUserAssessmentUserAnalytics:getUserAssessmentUserAnalytics", args ?? new GetUserAssessmentUserAnalyticsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of User Assessment User Analytics in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of aggregated user details from the specified user assessment. This provides information about the overall state.
        /// of database user security.  For example, the user details include how many users have the DBA role and how many users are in
        /// the critical category. This data is especially useful content for dashboards or to support analytics.
        /// 
        /// When you perform the ListUserAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
        /// parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has READ
        /// permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
        /// root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
        /// compartmentId, then "Not Authorized" is returned.
        /// 
        /// The parameter compartmentIdInSubtree applies when you perform ListUserAnalytics on the compartmentId passed and when it is
        /// set to true, the entire hierarchy of compartments can be returned.
        /// 
        /// To use ListUserAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
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
        ///     var testUserAssessmentUserAnalytics = Oci.DataSafe.GetUserAssessmentUserAnalytics.Invoke(new()
        ///     {
        ///         UserAssessmentId = testUserAssessment.Id,
        ///         AccessLevel = userAssessmentUserAnalyticAccessLevel,
        ///         AccountStatus = userAssessmentUserAnalyticAccountStatus,
        ///         AuthenticationType = userAssessmentUserAnalyticAuthenticationType,
        ///         CompartmentIdInSubtree = userAssessmentUserAnalyticCompartmentIdInSubtree,
        ///         TargetId = testTarget.Id,
        ///         TimeLastLoginGreaterThanOrEqualTo = userAssessmentUserAnalyticTimeLastLoginGreaterThanOrEqualTo,
        ///         TimeLastLoginLessThan = userAssessmentUserAnalyticTimeLastLoginLessThan,
        ///         TimePasswordExpiryGreaterThanOrEqualTo = userAssessmentUserAnalyticTimePasswordExpiryGreaterThanOrEqualTo,
        ///         TimePasswordExpiryLessThan = userAssessmentUserAnalyticTimePasswordExpiryLessThan,
        ///         TimePasswordLastChangedGreaterThanOrEqualTo = userAssessmentUserAnalyticTimePasswordLastChangedGreaterThanOrEqualTo,
        ///         TimePasswordLastChangedLessThan = userAssessmentUserAnalyticTimePasswordLastChangedLessThan,
        ///         TimeUserCreatedGreaterThanOrEqualTo = userAssessmentUserAnalyticTimeUserCreatedGreaterThanOrEqualTo,
        ///         TimeUserCreatedLessThan = userAssessmentUserAnalyticTimeUserCreatedLessThan,
        ///         UserCategory = userAssessmentUserAnalyticUserCategory,
        ///         UserKey = userAssessmentUserAnalyticUserKey,
        ///         UserName = testUser.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetUserAssessmentUserAnalyticsResult> Invoke(GetUserAssessmentUserAnalyticsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetUserAssessmentUserAnalyticsResult>("oci:DataSafe/getUserAssessmentUserAnalytics:getUserAssessmentUserAnalytics", args ?? new GetUserAssessmentUserAnalyticsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetUserAssessmentUserAnalyticsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        /// <summary>
        /// A filter to return only items that match the specified account status.
        /// </summary>
        [Input("accountStatus")]
        public string? AccountStatus { get; set; }

        /// <summary>
        /// A filter to return only items that match the specified authentication type.
        /// </summary>
        [Input("authenticationType")]
        public string? AuthenticationType { get; set; }

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private List<Inputs.GetUserAssessmentUserAnalyticsFilterArgs>? _filters;
        public List<Inputs.GetUserAssessmentUserAnalyticsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetUserAssessmentUserAnalyticsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only items related to a specific target OCID.
        /// </summary>
        [Input("targetId")]
        public string? TargetId { get; set; }

        /// <summary>
        /// A filter to return users whose last login time in the database is greater than or equal to the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// 
        /// **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timeLastLoginGreaterThanOrEqualTo")]
        public string? TimeLastLoginGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// A filter to return users whose last login time in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timeLastLoginLessThan")]
        public string? TimeLastLoginLessThan { get; set; }

        /// <summary>
        /// A filter to return users whose password expiry date in the database is greater than or equal to the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timePasswordExpiryGreaterThanOrEqualTo")]
        public string? TimePasswordExpiryGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// A filter to return users whose password expiry date in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timePasswordExpiryLessThan")]
        public string? TimePasswordExpiryLessThan { get; set; }

        /// <summary>
        /// A filter to return users whose last password change in the database is greater than or equal to the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// 
        /// **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timePasswordLastChangedGreaterThanOrEqualTo")]
        public string? TimePasswordLastChangedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// A filter to return users whose last password change in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// 
        /// **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timePasswordLastChangedLessThan")]
        public string? TimePasswordLastChangedLessThan { get; set; }

        /// <summary>
        /// A filter to return users whose creation time in the database is greater than or equal to the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timeUserCreatedGreaterThanOrEqualTo")]
        public string? TimeUserCreatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// A filter to return users whose creation time in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timeUserCreatedLessThan")]
        public string? TimeUserCreatedLessThan { get; set; }

        /// <summary>
        /// The OCID of the user assessment.
        /// </summary>
        [Input("userAssessmentId", required: true)]
        public string UserAssessmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only items that match the specified user category.
        /// </summary>
        [Input("userCategory")]
        public string? UserCategory { get; set; }

        /// <summary>
        /// A filter to return only items that match the specified user key.
        /// </summary>
        [Input("userKey")]
        public string? UserKey { get; set; }

        /// <summary>
        /// A filter to return only items that match the specified user name.
        /// </summary>
        [Input("userName")]
        public string? UserName { get; set; }

        public GetUserAssessmentUserAnalyticsArgs()
        {
        }
        public static new GetUserAssessmentUserAnalyticsArgs Empty => new GetUserAssessmentUserAnalyticsArgs();
    }

    public sealed class GetUserAssessmentUserAnalyticsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public Input<string>? AccessLevel { get; set; }

        /// <summary>
        /// A filter to return only items that match the specified account status.
        /// </summary>
        [Input("accountStatus")]
        public Input<string>? AccountStatus { get; set; }

        /// <summary>
        /// A filter to return only items that match the specified authentication type.
        /// </summary>
        [Input("authenticationType")]
        public Input<string>? AuthenticationType { get; set; }

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public Input<bool>? CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetUserAssessmentUserAnalyticsFilterInputArgs>? _filters;
        public InputList<Inputs.GetUserAssessmentUserAnalyticsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetUserAssessmentUserAnalyticsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only items related to a specific target OCID.
        /// </summary>
        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        /// <summary>
        /// A filter to return users whose last login time in the database is greater than or equal to the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// 
        /// **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timeLastLoginGreaterThanOrEqualTo")]
        public Input<string>? TimeLastLoginGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// A filter to return users whose last login time in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timeLastLoginLessThan")]
        public Input<string>? TimeLastLoginLessThan { get; set; }

        /// <summary>
        /// A filter to return users whose password expiry date in the database is greater than or equal to the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timePasswordExpiryGreaterThanOrEqualTo")]
        public Input<string>? TimePasswordExpiryGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// A filter to return users whose password expiry date in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timePasswordExpiryLessThan")]
        public Input<string>? TimePasswordExpiryLessThan { get; set; }

        /// <summary>
        /// A filter to return users whose last password change in the database is greater than or equal to the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// 
        /// **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timePasswordLastChangedGreaterThanOrEqualTo")]
        public Input<string>? TimePasswordLastChangedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// A filter to return users whose last password change in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// 
        /// **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timePasswordLastChangedLessThan")]
        public Input<string>? TimePasswordLastChangedLessThan { get; set; }

        /// <summary>
        /// A filter to return users whose creation time in the database is greater than or equal to the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timeUserCreatedGreaterThanOrEqualTo")]
        public Input<string>? TimeUserCreatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// A filter to return users whose creation time in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
        /// </summary>
        [Input("timeUserCreatedLessThan")]
        public Input<string>? TimeUserCreatedLessThan { get; set; }

        /// <summary>
        /// The OCID of the user assessment.
        /// </summary>
        [Input("userAssessmentId", required: true)]
        public Input<string> UserAssessmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only items that match the specified user category.
        /// </summary>
        [Input("userCategory")]
        public Input<string>? UserCategory { get; set; }

        /// <summary>
        /// A filter to return only items that match the specified user key.
        /// </summary>
        [Input("userKey")]
        public Input<string>? UserKey { get; set; }

        /// <summary>
        /// A filter to return only items that match the specified user name.
        /// </summary>
        [Input("userName")]
        public Input<string>? UserName { get; set; }

        public GetUserAssessmentUserAnalyticsInvokeArgs()
        {
        }
        public static new GetUserAssessmentUserAnalyticsInvokeArgs Empty => new GetUserAssessmentUserAnalyticsInvokeArgs();
    }


    [OutputType]
    public sealed class GetUserAssessmentUserAnalyticsResult
    {
        public readonly string? AccessLevel;
        public readonly string? AccountStatus;
        public readonly string? AuthenticationType;
        public readonly bool? CompartmentIdInSubtree;
        public readonly ImmutableArray<Outputs.GetUserAssessmentUserAnalyticsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? TargetId;
        public readonly string? TimeLastLoginGreaterThanOrEqualTo;
        public readonly string? TimeLastLoginLessThan;
        public readonly string? TimePasswordExpiryGreaterThanOrEqualTo;
        public readonly string? TimePasswordExpiryLessThan;
        public readonly string? TimePasswordLastChangedGreaterThanOrEqualTo;
        public readonly string? TimePasswordLastChangedLessThan;
        public readonly string? TimeUserCreatedGreaterThanOrEqualTo;
        public readonly string? TimeUserCreatedLessThan;
        /// <summary>
        /// The list of user_aggregations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetUserAssessmentUserAnalyticsUserAggregationResult> UserAggregations;
        public readonly string UserAssessmentId;
        public readonly string? UserCategory;
        public readonly string? UserKey;
        public readonly string? UserName;

        [OutputConstructor]
        private GetUserAssessmentUserAnalyticsResult(
            string? accessLevel,

            string? accountStatus,

            string? authenticationType,

            bool? compartmentIdInSubtree,

            ImmutableArray<Outputs.GetUserAssessmentUserAnalyticsFilterResult> filters,

            string id,

            string? targetId,

            string? timeLastLoginGreaterThanOrEqualTo,

            string? timeLastLoginLessThan,

            string? timePasswordExpiryGreaterThanOrEqualTo,

            string? timePasswordExpiryLessThan,

            string? timePasswordLastChangedGreaterThanOrEqualTo,

            string? timePasswordLastChangedLessThan,

            string? timeUserCreatedGreaterThanOrEqualTo,

            string? timeUserCreatedLessThan,

            ImmutableArray<Outputs.GetUserAssessmentUserAnalyticsUserAggregationResult> userAggregations,

            string userAssessmentId,

            string? userCategory,

            string? userKey,

            string? userName)
        {
            AccessLevel = accessLevel;
            AccountStatus = accountStatus;
            AuthenticationType = authenticationType;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            Filters = filters;
            Id = id;
            TargetId = targetId;
            TimeLastLoginGreaterThanOrEqualTo = timeLastLoginGreaterThanOrEqualTo;
            TimeLastLoginLessThan = timeLastLoginLessThan;
            TimePasswordExpiryGreaterThanOrEqualTo = timePasswordExpiryGreaterThanOrEqualTo;
            TimePasswordExpiryLessThan = timePasswordExpiryLessThan;
            TimePasswordLastChangedGreaterThanOrEqualTo = timePasswordLastChangedGreaterThanOrEqualTo;
            TimePasswordLastChangedLessThan = timePasswordLastChangedLessThan;
            TimeUserCreatedGreaterThanOrEqualTo = timeUserCreatedGreaterThanOrEqualTo;
            TimeUserCreatedLessThan = timeUserCreatedLessThan;
            UserAggregations = userAggregations;
            UserAssessmentId = userAssessmentId;
            UserCategory = userCategory;
            UserKey = userKey;
            UserName = userName;
        }
    }
}
