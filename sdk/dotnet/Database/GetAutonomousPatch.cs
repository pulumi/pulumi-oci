// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousPatch
    {
        /// <summary>
        /// This data source provides details about a specific Autonomous Patch resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about a specific autonomous patch.
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
        ///     var testAutonomousPatch = Oci.Database.GetAutonomousPatch.Invoke(new()
        ///     {
        ///         AutonomousPatchId = testAutonomousPatchOciDatabaseAutonomousPatch.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAutonomousPatchResult> InvokeAsync(GetAutonomousPatchArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousPatchResult>("oci:Database/getAutonomousPatch:getAutonomousPatch", args ?? new GetAutonomousPatchArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Autonomous Patch resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about a specific autonomous patch.
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
        ///     var testAutonomousPatch = Oci.Database.GetAutonomousPatch.Invoke(new()
        ///     {
        ///         AutonomousPatchId = testAutonomousPatchOciDatabaseAutonomousPatch.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousPatchResult> Invoke(GetAutonomousPatchInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousPatchResult>("oci:Database/getAutonomousPatch:getAutonomousPatch", args ?? new GetAutonomousPatchInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Autonomous Patch resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about a specific autonomous patch.
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
        ///     var testAutonomousPatch = Oci.Database.GetAutonomousPatch.Invoke(new()
        ///     {
        ///         AutonomousPatchId = testAutonomousPatchOciDatabaseAutonomousPatch.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousPatchResult> Invoke(GetAutonomousPatchInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousPatchResult>("oci:Database/getAutonomousPatch:getAutonomousPatch", args ?? new GetAutonomousPatchInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAutonomousPatchArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The autonomous patch [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousPatchId", required: true)]
        public string AutonomousPatchId { get; set; } = null!;

        public GetAutonomousPatchArgs()
        {
        }
        public static new GetAutonomousPatchArgs Empty => new GetAutonomousPatchArgs();
    }

    public sealed class GetAutonomousPatchInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The autonomous patch [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousPatchId", required: true)]
        public Input<string> AutonomousPatchId { get; set; } = null!;

        public GetAutonomousPatchInvokeArgs()
        {
        }
        public static new GetAutonomousPatchInvokeArgs Empty => new GetAutonomousPatchInvokeArgs();
    }


    [OutputType]
    public sealed class GetAutonomousPatchResult
    {
        public readonly string AutonomousPatchId;
        /// <summary>
        /// Maintenance run type, either "QUARTERLY" or "TIMEZONE".
        /// </summary>
        public readonly string AutonomousPatchType;
        /// <summary>
        /// The text describing this patch package.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A descriptive text associated with the lifecycleState. Typically can contain additional displayable text.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Database patching model preference. See [My Oracle Support note 2285040.1](https://support.oracle.com/rs?type=doc&amp;id=2285040.1) for information on the Release Update (RU) and Release Update Revision (RUR) patching models.
        /// </summary>
        public readonly string PatchModel;
        /// <summary>
        /// First month of the quarter in which the patch was released.
        /// </summary>
        public readonly string Quarter;
        /// <summary>
        /// The current state of the patch as a result of lastAction.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time that the patch was released.
        /// </summary>
        public readonly string TimeReleased;
        /// <summary>
        /// The type of patch. BUNDLE is one example.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// The version of this patch package.
        /// </summary>
        public readonly string Version;
        /// <summary>
        /// Year in which the patch was released.
        /// </summary>
        public readonly string Year;

        [OutputConstructor]
        private GetAutonomousPatchResult(
            string autonomousPatchId,

            string autonomousPatchType,

            string description,

            string id,

            string lifecycleDetails,

            string patchModel,

            string quarter,

            string state,

            string timeReleased,

            string type,

            string version,

            string year)
        {
            AutonomousPatchId = autonomousPatchId;
            AutonomousPatchType = autonomousPatchType;
            Description = description;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            PatchModel = patchModel;
            Quarter = quarter;
            State = state;
            TimeReleased = timeReleased;
            Type = type;
            Version = version;
            Year = year;
        }
    }
}
