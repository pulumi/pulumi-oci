// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetDbNodeConsoleHistory
    {
        /// <summary>
        /// This data source provides details about a specific Db Node Console History resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified database node console history.
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
        ///     var testDbNodeConsoleHistory = Oci.Database.GetDbNodeConsoleHistory.Invoke(new()
        ///     {
        ///         ConsoleHistoryId = testConsoleHistory.Id,
        ///         DbNodeId = testDbNode.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDbNodeConsoleHistoryResult> InvokeAsync(GetDbNodeConsoleHistoryArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDbNodeConsoleHistoryResult>("oci:Database/getDbNodeConsoleHistory:getDbNodeConsoleHistory", args ?? new GetDbNodeConsoleHistoryArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Db Node Console History resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified database node console history.
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
        ///     var testDbNodeConsoleHistory = Oci.Database.GetDbNodeConsoleHistory.Invoke(new()
        ///     {
        ///         ConsoleHistoryId = testConsoleHistory.Id,
        ///         DbNodeId = testDbNode.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDbNodeConsoleHistoryResult> Invoke(GetDbNodeConsoleHistoryInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDbNodeConsoleHistoryResult>("oci:Database/getDbNodeConsoleHistory:getDbNodeConsoleHistory", args ?? new GetDbNodeConsoleHistoryInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Db Node Console History resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified database node console history.
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
        ///     var testDbNodeConsoleHistory = Oci.Database.GetDbNodeConsoleHistory.Invoke(new()
        ///     {
        ///         ConsoleHistoryId = testConsoleHistory.Id,
        ///         DbNodeId = testDbNode.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDbNodeConsoleHistoryResult> Invoke(GetDbNodeConsoleHistoryInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDbNodeConsoleHistoryResult>("oci:Database/getDbNodeConsoleHistory:getDbNodeConsoleHistory", args ?? new GetDbNodeConsoleHistoryInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDbNodeConsoleHistoryArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the console history.
        /// </summary>
        [Input("consoleHistoryId", required: true)]
        public string ConsoleHistoryId { get; set; } = null!;

        /// <summary>
        /// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("dbNodeId", required: true)]
        public string DbNodeId { get; set; } = null!;

        public GetDbNodeConsoleHistoryArgs()
        {
        }
        public static new GetDbNodeConsoleHistoryArgs Empty => new GetDbNodeConsoleHistoryArgs();
    }

    public sealed class GetDbNodeConsoleHistoryInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the console history.
        /// </summary>
        [Input("consoleHistoryId", required: true)]
        public Input<string> ConsoleHistoryId { get; set; } = null!;

        /// <summary>
        /// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("dbNodeId", required: true)]
        public Input<string> DbNodeId { get; set; } = null!;

        public GetDbNodeConsoleHistoryInvokeArgs()
        {
        }
        public static new GetDbNodeConsoleHistoryInvokeArgs Empty => new GetDbNodeConsoleHistoryInvokeArgs();
    }


    [OutputType]
    public sealed class GetDbNodeConsoleHistoryResult
    {
        /// <summary>
        /// The OCID of the compartment containing the console history.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string ConsoleHistoryId;
        /// <summary>
        /// The OCID of the database node.
        /// </summary>
        public readonly string DbNodeId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The user-friendly name for the console history. The name does not need to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the console history.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current state of the console history.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the console history was created.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetDbNodeConsoleHistoryResult(
            string compartmentId,

            string consoleHistoryId,

            string dbNodeId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string state,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            ConsoleHistoryId = consoleHistoryId;
            DbNodeId = dbNodeId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
