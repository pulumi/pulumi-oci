// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration
{
    public static class GetJobOutput
    {
        /// <summary>
        /// This data source provides details about a specific Job Output resource in Oracle Cloud Infrastructure Database Migration service.
        /// 
        /// List the Job Outputs
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
        ///     var testJobOutput = Oci.DatabaseMigration.GetJobOutput.Invoke(new()
        ///     {
        ///         JobId = oci_database_migration_job.Test_job.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetJobOutputResult> InvokeAsync(GetJobOutputArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetJobOutputResult>("oci:DatabaseMigration/getJobOutput:getJobOutput", args ?? new GetJobOutputArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Job Output resource in Oracle Cloud Infrastructure Database Migration service.
        /// 
        /// List the Job Outputs
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
        ///     var testJobOutput = Oci.DatabaseMigration.GetJobOutput.Invoke(new()
        ///     {
        ///         JobId = oci_database_migration_job.Test_job.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetJobOutputResult> Invoke(GetJobOutputInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetJobOutputResult>("oci:DatabaseMigration/getJobOutput:getJobOutput", args ?? new GetJobOutputInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetJobOutputArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the job
        /// </summary>
        [Input("jobId", required: true)]
        public string JobId { get; set; } = null!;

        public GetJobOutputArgs()
        {
        }
        public static new GetJobOutputArgs Empty => new GetJobOutputArgs();
    }

    public sealed class GetJobOutputInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the job
        /// </summary>
        [Input("jobId", required: true)]
        public Input<string> JobId { get; set; } = null!;

        public GetJobOutputInvokeArgs()
        {
        }
        public static new GetJobOutputInvokeArgs Empty => new GetJobOutputInvokeArgs();
    }


    [OutputType]
    public sealed class GetJobOutputResult
    {
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Items in collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobOutputItemResult> Items;
        public readonly string JobId;

        [OutputConstructor]
        private GetJobOutputResult(
            string id,

            ImmutableArray<Outputs.GetJobOutputItemResult> items,

            string jobId)
        {
            Id = id;
            Items = items;
            JobId = jobId;
        }
    }
}