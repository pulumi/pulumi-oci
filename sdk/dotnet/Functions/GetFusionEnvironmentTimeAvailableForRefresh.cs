// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions
{
    public static class GetFusionEnvironmentTimeAvailableForRefresh
    {
        /// <summary>
        /// This data source provides details about a specific Fusion Environment Time Available For Refresh resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets available refresh time for this fusion environment
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
        ///     var testFusionEnvironmentTimeAvailableForRefresh = Oci.Functions.GetFusionEnvironmentTimeAvailableForRefresh.Invoke(new()
        ///     {
        ///         FusionEnvironmentId = testFusionEnvironment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetFusionEnvironmentTimeAvailableForRefreshResult> InvokeAsync(GetFusionEnvironmentTimeAvailableForRefreshArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFusionEnvironmentTimeAvailableForRefreshResult>("oci:Functions/getFusionEnvironmentTimeAvailableForRefresh:getFusionEnvironmentTimeAvailableForRefresh", args ?? new GetFusionEnvironmentTimeAvailableForRefreshArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fusion Environment Time Available For Refresh resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets available refresh time for this fusion environment
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
        ///     var testFusionEnvironmentTimeAvailableForRefresh = Oci.Functions.GetFusionEnvironmentTimeAvailableForRefresh.Invoke(new()
        ///     {
        ///         FusionEnvironmentId = testFusionEnvironment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFusionEnvironmentTimeAvailableForRefreshResult> Invoke(GetFusionEnvironmentTimeAvailableForRefreshInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFusionEnvironmentTimeAvailableForRefreshResult>("oci:Functions/getFusionEnvironmentTimeAvailableForRefresh:getFusionEnvironmentTimeAvailableForRefresh", args ?? new GetFusionEnvironmentTimeAvailableForRefreshInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fusion Environment Time Available For Refresh resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets available refresh time for this fusion environment
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
        ///     var testFusionEnvironmentTimeAvailableForRefresh = Oci.Functions.GetFusionEnvironmentTimeAvailableForRefresh.Invoke(new()
        ///     {
        ///         FusionEnvironmentId = testFusionEnvironment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFusionEnvironmentTimeAvailableForRefreshResult> Invoke(GetFusionEnvironmentTimeAvailableForRefreshInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetFusionEnvironmentTimeAvailableForRefreshResult>("oci:Functions/getFusionEnvironmentTimeAvailableForRefresh:getFusionEnvironmentTimeAvailableForRefresh", args ?? new GetFusionEnvironmentTimeAvailableForRefreshInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFusionEnvironmentTimeAvailableForRefreshArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique FusionEnvironment identifier
        /// </summary>
        [Input("fusionEnvironmentId", required: true)]
        public string FusionEnvironmentId { get; set; } = null!;

        public GetFusionEnvironmentTimeAvailableForRefreshArgs()
        {
        }
        public static new GetFusionEnvironmentTimeAvailableForRefreshArgs Empty => new GetFusionEnvironmentTimeAvailableForRefreshArgs();
    }

    public sealed class GetFusionEnvironmentTimeAvailableForRefreshInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique FusionEnvironment identifier
        /// </summary>
        [Input("fusionEnvironmentId", required: true)]
        public Input<string> FusionEnvironmentId { get; set; } = null!;

        public GetFusionEnvironmentTimeAvailableForRefreshInvokeArgs()
        {
        }
        public static new GetFusionEnvironmentTimeAvailableForRefreshInvokeArgs Empty => new GetFusionEnvironmentTimeAvailableForRefreshInvokeArgs();
    }


    [OutputType]
    public sealed class GetFusionEnvironmentTimeAvailableForRefreshResult
    {
        public readonly string FusionEnvironmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A list of available refresh time objects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFusionEnvironmentTimeAvailableForRefreshItemResult> Items;

        [OutputConstructor]
        private GetFusionEnvironmentTimeAvailableForRefreshResult(
            string fusionEnvironmentId,

            string id,

            ImmutableArray<Outputs.GetFusionEnvironmentTimeAvailableForRefreshItemResult> items)
        {
            FusionEnvironmentId = fusionEnvironmentId;
            Id = id;
            Items = items;
        }
    }
}
