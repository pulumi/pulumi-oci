// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics
{
    public static class GetLogAnalyticsCategoriesList
    {
        /// <summary>
        /// This data source provides details about Categories in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Returns a list of categories, containing detailed information about them. You may limit the number of results, provide sorting order, and filter by information such as category name or description.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testLogAnalyticsCategoriesList = Oci.LogAnalytics.GetLogAnalyticsCategoriesList.Invoke(new()
        ///     {
        ///         Namespace = @var.Log_analytics_categories_list_namespace,
        ///         CategoryDisplayText = @var.Log_analytics_categories_list_category_display_text,
        ///         CategoryType = @var.Log_analytics_categories_list_category_type,
        ///         Name = @var.Log_analytics_categories_list_name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetLogAnalyticsCategoriesListResult> InvokeAsync(GetLogAnalyticsCategoriesListArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLogAnalyticsCategoriesListResult>("oci:LogAnalytics/getLogAnalyticsCategoriesList:getLogAnalyticsCategoriesList", args ?? new GetLogAnalyticsCategoriesListArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about Categories in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Returns a list of categories, containing detailed information about them. You may limit the number of results, provide sorting order, and filter by information such as category name or description.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testLogAnalyticsCategoriesList = Oci.LogAnalytics.GetLogAnalyticsCategoriesList.Invoke(new()
        ///     {
        ///         Namespace = @var.Log_analytics_categories_list_namespace,
        ///         CategoryDisplayText = @var.Log_analytics_categories_list_category_display_text,
        ///         CategoryType = @var.Log_analytics_categories_list_category_type,
        ///         Name = @var.Log_analytics_categories_list_name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetLogAnalyticsCategoriesListResult> Invoke(GetLogAnalyticsCategoriesListInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetLogAnalyticsCategoriesListResult>("oci:LogAnalytics/getLogAnalyticsCategoriesList:getLogAnalyticsCategoriesList", args ?? new GetLogAnalyticsCategoriesListInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetLogAnalyticsCategoriesListArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The category display text used for filtering. Only categories matching the specified display name or description will be returned.
        /// </summary>
        [Input("categoryDisplayText")]
        public string? CategoryDisplayText { get; set; }

        /// <summary>
        /// A comma-separated list of category types used for filtering. Only categories of the specified types will be returned.
        /// </summary>
        [Input("categoryType")]
        public string? CategoryType { get; set; }

        /// <summary>
        /// A filter to return only log analytics category whose name matches the entire name given. The match is case-insensitive.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        public GetLogAnalyticsCategoriesListArgs()
        {
        }
        public static new GetLogAnalyticsCategoriesListArgs Empty => new GetLogAnalyticsCategoriesListArgs();
    }

    public sealed class GetLogAnalyticsCategoriesListInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The category display text used for filtering. Only categories matching the specified display name or description will be returned.
        /// </summary>
        [Input("categoryDisplayText")]
        public Input<string>? CategoryDisplayText { get; set; }

        /// <summary>
        /// A comma-separated list of category types used for filtering. Only categories of the specified types will be returned.
        /// </summary>
        [Input("categoryType")]
        public Input<string>? CategoryType { get; set; }

        /// <summary>
        /// A filter to return only log analytics category whose name matches the entire name given. The match is case-insensitive.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        public GetLogAnalyticsCategoriesListInvokeArgs()
        {
        }
        public static new GetLogAnalyticsCategoriesListInvokeArgs Empty => new GetLogAnalyticsCategoriesListInvokeArgs();
    }


    [OutputType]
    public sealed class GetLogAnalyticsCategoriesListResult
    {
        public readonly string? CategoryDisplayText;
        public readonly string? CategoryType;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// An array of categories.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLogAnalyticsCategoriesListItemResult> Items;
        /// <summary>
        /// The unique name that identifies the category.
        /// </summary>
        public readonly string? Name;
        public readonly string Namespace;

        [OutputConstructor]
        private GetLogAnalyticsCategoriesListResult(
            string? categoryDisplayText,

            string? categoryType,

            string id,

            ImmutableArray<Outputs.GetLogAnalyticsCategoriesListItemResult> items,

            string? name,

            string @namespace)
        {
            CategoryDisplayText = categoryDisplayText;
            CategoryType = categoryType;
            Id = id;
            Items = items;
            Name = name;
            Namespace = @namespace;
        }
    }
}