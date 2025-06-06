// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Adm
{
    public static class GetRemediationRun
    {
        /// <summary>
        /// This data source provides details about a specific Remediation Run resource in Oracle Cloud Infrastructure Adm service.
        /// 
        /// Returns the details of the specified remediation run.
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
        ///     var testRemediationRun = Oci.Adm.GetRemediationRun.Invoke(new()
        ///     {
        ///         RemediationRunId = testRemediationRunOciAdmRemediationRun.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetRemediationRunResult> InvokeAsync(GetRemediationRunArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetRemediationRunResult>("oci:Adm/getRemediationRun:getRemediationRun", args ?? new GetRemediationRunArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Remediation Run resource in Oracle Cloud Infrastructure Adm service.
        /// 
        /// Returns the details of the specified remediation run.
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
        ///     var testRemediationRun = Oci.Adm.GetRemediationRun.Invoke(new()
        ///     {
        ///         RemediationRunId = testRemediationRunOciAdmRemediationRun.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRemediationRunResult> Invoke(GetRemediationRunInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetRemediationRunResult>("oci:Adm/getRemediationRun:getRemediationRun", args ?? new GetRemediationRunInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Remediation Run resource in Oracle Cloud Infrastructure Adm service.
        /// 
        /// Returns the details of the specified remediation run.
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
        ///     var testRemediationRun = Oci.Adm.GetRemediationRun.Invoke(new()
        ///     {
        ///         RemediationRunId = testRemediationRunOciAdmRemediationRun.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRemediationRunResult> Invoke(GetRemediationRunInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetRemediationRunResult>("oci:Adm/getRemediationRun:getRemediationRun", args ?? new GetRemediationRunInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRemediationRunArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique Remediation Run identifier path parameter.
        /// </summary>
        [Input("remediationRunId", required: true)]
        public string RemediationRunId { get; set; } = null!;

        public GetRemediationRunArgs()
        {
        }
        public static new GetRemediationRunArgs Empty => new GetRemediationRunArgs();
    }

    public sealed class GetRemediationRunInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique Remediation Run identifier path parameter.
        /// </summary>
        [Input("remediationRunId", required: true)]
        public Input<string> RemediationRunId { get; set; } = null!;

        public GetRemediationRunInvokeArgs()
        {
        }
        public static new GetRemediationRunInvokeArgs Empty => new GetRemediationRunInvokeArgs();
    }


    [OutputType]
    public sealed class GetRemediationRunResult
    {
        /// <summary>
        /// The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The type of the current stage of the remediation run.
        /// </summary>
        public readonly string CurrentStageType;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The name of the remediation run.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.
        /// </summary>
        public readonly string RemediationRecipeId;
        public readonly string RemediationRunId;
        /// <summary>
        /// The source that triggered the Remediation Recipe.
        /// </summary>
        public readonly string RemediationRunSource;
        /// <summary>
        /// The list of remediation run stage summaries.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRemediationRunStageResult> Stages;
        /// <summary>
        /// The current lifecycle state of the remediation run.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The creation date and time of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time of the finish of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeFinished;
        /// <summary>
        /// The date and time of the start of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeStarted;
        /// <summary>
        /// The date and time the remediation run was last updated (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetRemediationRunResult(
            string compartmentId,

            string currentStageType,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string remediationRecipeId,

            string remediationRunId,

            string remediationRunSource,

            ImmutableArray<Outputs.GetRemediationRunStageResult> stages,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeFinished,

            string timeStarted,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            CurrentStageType = currentStageType;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            RemediationRecipeId = remediationRecipeId;
            RemediationRunId = remediationRunId;
            RemediationRunSource = remediationRunSource;
            Stages = stages;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeFinished = timeFinished;
            TimeStarted = timeStarted;
            TimeUpdated = timeUpdated;
        }
    }
}
