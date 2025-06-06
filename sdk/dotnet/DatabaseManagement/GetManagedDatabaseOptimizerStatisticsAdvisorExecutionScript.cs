// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScript
    {
        /// <summary>
        /// This data source provides details about a specific Managed Database Optimizer Statistics Advisor Execution Script resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the Oracle system-generated script for the specified Optimizer Statistics Advisor execution.
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
        ///     var testManagedDatabaseOptimizerStatisticsAdvisorExecutionScript = Oci.DatabaseManagement.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScript.Invoke(new()
        ///     {
        ///         ExecutionName = managedDatabaseOptimizerStatisticsAdvisorExecutionScriptExecutionName,
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         TaskName = managedDatabaseOptimizerStatisticsAdvisorExecutionScriptTaskName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptResult> InvokeAsync(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptResult>("oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsAdvisorExecutionScript:getManagedDatabaseOptimizerStatisticsAdvisorExecutionScript", args ?? new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Database Optimizer Statistics Advisor Execution Script resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the Oracle system-generated script for the specified Optimizer Statistics Advisor execution.
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
        ///     var testManagedDatabaseOptimizerStatisticsAdvisorExecutionScript = Oci.DatabaseManagement.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScript.Invoke(new()
        ///     {
        ///         ExecutionName = managedDatabaseOptimizerStatisticsAdvisorExecutionScriptExecutionName,
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         TaskName = managedDatabaseOptimizerStatisticsAdvisorExecutionScriptTaskName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptResult> Invoke(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptResult>("oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsAdvisorExecutionScript:getManagedDatabaseOptimizerStatisticsAdvisorExecutionScript", args ?? new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Database Optimizer Statistics Advisor Execution Script resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the Oracle system-generated script for the specified Optimizer Statistics Advisor execution.
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
        ///     var testManagedDatabaseOptimizerStatisticsAdvisorExecutionScript = Oci.DatabaseManagement.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScript.Invoke(new()
        ///     {
        ///         ExecutionName = managedDatabaseOptimizerStatisticsAdvisorExecutionScriptExecutionName,
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         TaskName = managedDatabaseOptimizerStatisticsAdvisorExecutionScriptTaskName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptResult> Invoke(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptResult>("oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsAdvisorExecutionScript:getManagedDatabaseOptimizerStatisticsAdvisorExecutionScript", args ?? new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the Optimizer Statistics Advisor execution.
        /// </summary>
        [Input("executionName", required: true)]
        public string ExecutionName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public string ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// The name of the optimizer statistics collection execution task.
        /// </summary>
        [Input("taskName", required: true)]
        public string TaskName { get; set; } = null!;

        public GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs()
        {
        }
        public static new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs Empty => new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs();
    }

    public sealed class GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the Optimizer Statistics Advisor execution.
        /// </summary>
        [Input("executionName", required: true)]
        public Input<string> ExecutionName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public Input<string> ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// The name of the optimizer statistics collection execution task.
        /// </summary>
        [Input("taskName", required: true)]
        public Input<string> TaskName { get; set; } = null!;

        public GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptInvokeArgs()
        {
        }
        public static new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptInvokeArgs Empty => new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptResult
    {
        public readonly string ExecutionName;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string ManagedDatabaseId;
        /// <summary>
        /// The Optimizer Statistics Advisor execution script.
        /// </summary>
        public readonly string Script;
        public readonly string TaskName;

        [OutputConstructor]
        private GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptResult(
            string executionName,

            string id,

            string managedDatabaseId,

            string script,

            string taskName)
        {
            ExecutionName = executionName;
            Id = id;
            ManagedDatabaseId = managedDatabaseId;
            Script = script;
            TaskName = taskName;
        }
    }
}
