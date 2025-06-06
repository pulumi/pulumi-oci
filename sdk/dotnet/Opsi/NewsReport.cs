// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi
{
    /// <summary>
    /// This resource provides the News Report resource in Oracle Cloud Infrastructure Opsi service.
    /// 
    /// Create a news report in Ops Insights. The report will be enabled in Ops Insights. Insights will be emailed as per selected frequency.
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
    ///     var testNewsReport = new Oci.Opsi.NewsReport("test_news_report", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         ContentTypes = new Oci.Opsi.Inputs.NewsReportContentTypesArgs
    ///         {
    ///             ActionableInsightsResources = newsReportContentTypesActionableInsightsResources,
    ///             CapacityPlanningResources = newsReportContentTypesCapacityPlanningResources,
    ///             SqlInsightsFleetAnalysisResources = newsReportContentTypesSqlInsightsFleetAnalysisResources,
    ///             SqlInsightsPerformanceDegradationResources = newsReportContentTypesSqlInsightsPerformanceDegradationResources,
    ///             SqlInsightsPlanChangesResources = newsReportContentTypesSqlInsightsPlanChangesResources,
    ///             SqlInsightsTopDatabasesResources = newsReportContentTypesSqlInsightsTopDatabasesResources,
    ///             SqlInsightsTopSqlByInsightsResources = newsReportContentTypesSqlInsightsTopSqlByInsightsResources,
    ///             SqlInsightsTopSqlResources = newsReportContentTypesSqlInsightsTopSqlResources,
    ///         },
    ///         Description = newsReportDescription,
    ///         Locale = newsReportLocale,
    ///         Name = newsReportName,
    ///         NewsFrequency = newsReportNewsFrequency,
    ///         OnsTopicId = testOnsTopic.Id,
    ///         AreChildCompartmentsIncluded = newsReportAreChildCompartmentsIncluded,
    ///         DayOfWeek = newsReportDayOfWeek,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         MatchRule = newsReportMatchRule,
    ///         Status = newsReportStatus,
    ///         TagFilters = newsReportTagFilters,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// NewsReports can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Opsi/newsReport:NewsReport test_news_report "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Opsi/newsReport:NewsReport")]
    public partial class NewsReport : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) A flag to consider the resources within a given compartment and all sub-compartments.
        /// </summary>
        [Output("areChildCompartmentsIncluded")]
        public Output<bool> AreChildCompartmentsIncluded { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Compartment Identifier where the news report will be created.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Content types that the news report can handle.
        /// </summary>
        [Output("contentTypes")]
        public Output<Outputs.NewsReportContentTypes> ContentTypes { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Day of the week in which the news report will be sent if the frequency is set to WEEKLY.
        /// </summary>
        [Output("dayOfWeek")]
        public Output<string> DayOfWeek { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The description of the news report.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Language of the news report.
        /// </summary>
        [Output("locale")]
        public Output<string> Locale { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Match rule used for tag filters.
        /// </summary>
        [Output("matchRule")]
        public Output<string> MatchRule { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The news report name.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// (Updatable) News report frequency.
        /// </summary>
        [Output("newsFrequency")]
        public Output<string> NewsFrequency { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ONS topic.
        /// </summary>
        [Output("onsTopicId")]
        public Output<string> OnsTopicId { get; private set; } = null!;

        /// <summary>
        /// The current state of the news report.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defines if the news report will be enabled or disabled.
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of tag filters; each filter composed by a namespace, key, and value. Example for defined tags - '&lt;TagNamespace&gt;.&lt;TagKey&gt;=&lt;TagValue&gt;'. Example for freeform tags - '&lt;TagKey&gt;=&lt;TagValue&gt;' 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("tagFilters")]
        public Output<ImmutableArray<string>> TagFilters { get; private set; } = null!;

        /// <summary>
        /// The time the the news report was first enabled. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the news report was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a NewsReport resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public NewsReport(string name, NewsReportArgs args, CustomResourceOptions? options = null)
            : base("oci:Opsi/newsReport:NewsReport", name, args ?? new NewsReportArgs(), MakeResourceOptions(options, ""))
        {
        }

        private NewsReport(string name, Input<string> id, NewsReportState? state = null, CustomResourceOptions? options = null)
            : base("oci:Opsi/newsReport:NewsReport", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing NewsReport resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static NewsReport Get(string name, Input<string> id, NewsReportState? state = null, CustomResourceOptions? options = null)
        {
            return new NewsReport(name, id, state, options);
        }
    }

    public sealed class NewsReportArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A flag to consider the resources within a given compartment and all sub-compartments.
        /// </summary>
        [Input("areChildCompartmentsIncluded")]
        public Input<bool>? AreChildCompartmentsIncluded { get; set; }

        /// <summary>
        /// (Updatable) Compartment Identifier where the news report will be created.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Content types that the news report can handle.
        /// </summary>
        [Input("contentTypes", required: true)]
        public Input<Inputs.NewsReportContentTypesArgs> ContentTypes { get; set; } = null!;

        /// <summary>
        /// (Updatable) Day of the week in which the news report will be sent if the frequency is set to WEEKLY.
        /// </summary>
        [Input("dayOfWeek")]
        public Input<string>? DayOfWeek { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description of the news report.
        /// </summary>
        [Input("description", required: true)]
        public Input<string> Description { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Language of the news report.
        /// </summary>
        [Input("locale", required: true)]
        public Input<string> Locale { get; set; } = null!;

        /// <summary>
        /// (Updatable) Match rule used for tag filters.
        /// </summary>
        [Input("matchRule")]
        public Input<string>? MatchRule { get; set; }

        /// <summary>
        /// (Updatable) The news report name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) News report frequency.
        /// </summary>
        [Input("newsFrequency", required: true)]
        public Input<string> NewsFrequency { get; set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ONS topic.
        /// </summary>
        [Input("onsTopicId", required: true)]
        public Input<string> OnsTopicId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Defines if the news report will be enabled or disabled.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        [Input("tagFilters")]
        private InputList<string>? _tagFilters;

        /// <summary>
        /// (Updatable) List of tag filters; each filter composed by a namespace, key, and value. Example for defined tags - '&lt;TagNamespace&gt;.&lt;TagKey&gt;=&lt;TagValue&gt;'. Example for freeform tags - '&lt;TagKey&gt;=&lt;TagValue&gt;' 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public InputList<string> TagFilters
        {
            get => _tagFilters ?? (_tagFilters = new InputList<string>());
            set => _tagFilters = value;
        }

        public NewsReportArgs()
        {
        }
        public static new NewsReportArgs Empty => new NewsReportArgs();
    }

    public sealed class NewsReportState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A flag to consider the resources within a given compartment and all sub-compartments.
        /// </summary>
        [Input("areChildCompartmentsIncluded")]
        public Input<bool>? AreChildCompartmentsIncluded { get; set; }

        /// <summary>
        /// (Updatable) Compartment Identifier where the news report will be created.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) Content types that the news report can handle.
        /// </summary>
        [Input("contentTypes")]
        public Input<Inputs.NewsReportContentTypesGetArgs>? ContentTypes { get; set; }

        /// <summary>
        /// (Updatable) Day of the week in which the news report will be sent if the frequency is set to WEEKLY.
        /// </summary>
        [Input("dayOfWeek")]
        public Input<string>? DayOfWeek { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description of the news report.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) Language of the news report.
        /// </summary>
        [Input("locale")]
        public Input<string>? Locale { get; set; }

        /// <summary>
        /// (Updatable) Match rule used for tag filters.
        /// </summary>
        [Input("matchRule")]
        public Input<string>? MatchRule { get; set; }

        /// <summary>
        /// (Updatable) The news report name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) News report frequency.
        /// </summary>
        [Input("newsFrequency")]
        public Input<string>? NewsFrequency { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ONS topic.
        /// </summary>
        [Input("onsTopicId")]
        public Input<string>? OnsTopicId { get; set; }

        /// <summary>
        /// The current state of the news report.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// (Updatable) Defines if the news report will be enabled or disabled.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        [Input("tagFilters")]
        private InputList<string>? _tagFilters;

        /// <summary>
        /// (Updatable) List of tag filters; each filter composed by a namespace, key, and value. Example for defined tags - '&lt;TagNamespace&gt;.&lt;TagKey&gt;=&lt;TagValue&gt;'. Example for freeform tags - '&lt;TagKey&gt;=&lt;TagValue&gt;' 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public InputList<string> TagFilters
        {
            get => _tagFilters ?? (_tagFilters = new InputList<string>());
            set => _tagFilters = value;
        }

        /// <summary>
        /// The time the the news report was first enabled. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the news report was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public NewsReportState()
        {
        }
        public static new NewsReportState Empty => new NewsReportState();
    }
}
