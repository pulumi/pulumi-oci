// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetDbHomePatchHistoryEntries
    {
        /// <summary>
        /// This data source provides the list of Db Home Patch History Entries in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the history of patch operations on the specified Database Home.
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
        ///     var testDbHomePatchHistoryEntries = Oci.Database.GetDbHomePatchHistoryEntries.Invoke(new()
        ///     {
        ///         DbHomeId = testDbHome.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDbHomePatchHistoryEntriesResult> InvokeAsync(GetDbHomePatchHistoryEntriesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDbHomePatchHistoryEntriesResult>("oci:Database/getDbHomePatchHistoryEntries:getDbHomePatchHistoryEntries", args ?? new GetDbHomePatchHistoryEntriesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Db Home Patch History Entries in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the history of patch operations on the specified Database Home.
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
        ///     var testDbHomePatchHistoryEntries = Oci.Database.GetDbHomePatchHistoryEntries.Invoke(new()
        ///     {
        ///         DbHomeId = testDbHome.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDbHomePatchHistoryEntriesResult> Invoke(GetDbHomePatchHistoryEntriesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDbHomePatchHistoryEntriesResult>("oci:Database/getDbHomePatchHistoryEntries:getDbHomePatchHistoryEntries", args ?? new GetDbHomePatchHistoryEntriesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Db Home Patch History Entries in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the history of patch operations on the specified Database Home.
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
        ///     var testDbHomePatchHistoryEntries = Oci.Database.GetDbHomePatchHistoryEntries.Invoke(new()
        ///     {
        ///         DbHomeId = testDbHome.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDbHomePatchHistoryEntriesResult> Invoke(GetDbHomePatchHistoryEntriesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDbHomePatchHistoryEntriesResult>("oci:Database/getDbHomePatchHistoryEntries:getDbHomePatchHistoryEntries", args ?? new GetDbHomePatchHistoryEntriesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDbHomePatchHistoryEntriesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("dbHomeId", required: true)]
        public string DbHomeId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetDbHomePatchHistoryEntriesFilterArgs>? _filters;
        public List<Inputs.GetDbHomePatchHistoryEntriesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDbHomePatchHistoryEntriesFilterArgs>());
            set => _filters = value;
        }

        public GetDbHomePatchHistoryEntriesArgs()
        {
        }
        public static new GetDbHomePatchHistoryEntriesArgs Empty => new GetDbHomePatchHistoryEntriesArgs();
    }

    public sealed class GetDbHomePatchHistoryEntriesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("dbHomeId", required: true)]
        public Input<string> DbHomeId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetDbHomePatchHistoryEntriesFilterInputArgs>? _filters;
        public InputList<Inputs.GetDbHomePatchHistoryEntriesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDbHomePatchHistoryEntriesFilterInputArgs>());
            set => _filters = value;
        }

        public GetDbHomePatchHistoryEntriesInvokeArgs()
        {
        }
        public static new GetDbHomePatchHistoryEntriesInvokeArgs Empty => new GetDbHomePatchHistoryEntriesInvokeArgs();
    }


    [OutputType]
    public sealed class GetDbHomePatchHistoryEntriesResult
    {
        public readonly string DbHomeId;
        public readonly ImmutableArray<Outputs.GetDbHomePatchHistoryEntriesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of patch_history_entries.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbHomePatchHistoryEntriesPatchHistoryEntryResult> PatchHistoryEntries;

        [OutputConstructor]
        private GetDbHomePatchHistoryEntriesResult(
            string dbHomeId,

            ImmutableArray<Outputs.GetDbHomePatchHistoryEntriesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetDbHomePatchHistoryEntriesPatchHistoryEntryResult> patchHistoryEntries)
        {
            DbHomeId = dbHomeId;
            Filters = filters;
            Id = id;
            PatchHistoryEntries = patchHistoryEntries;
        }
    }
}
