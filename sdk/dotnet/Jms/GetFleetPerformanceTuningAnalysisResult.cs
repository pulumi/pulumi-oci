// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms
{
    public static class GetFleetPerformanceTuningAnalysisResult
    {
        /// <summary>
        /// This data source provides details about a specific Fleet Performance Tuning Analysis Result resource in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Retrieve metadata of the Performance Tuning Analysis result.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testFleetPerformanceTuningAnalysisResult = Oci.Jms.GetFleetPerformanceTuningAnalysisResult.Invoke(new()
        ///     {
        ///         FleetId = oci_jms_fleet.Test_fleet.Id,
        ///         PerformanceTuningAnalysisResultId = oci_apm_synthetics_result.Test_result.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetFleetPerformanceTuningAnalysisResultResult> InvokeAsync(GetFleetPerformanceTuningAnalysisResultArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFleetPerformanceTuningAnalysisResultResult>("oci:Jms/getFleetPerformanceTuningAnalysisResult:getFleetPerformanceTuningAnalysisResult", args ?? new GetFleetPerformanceTuningAnalysisResultArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fleet Performance Tuning Analysis Result resource in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Retrieve metadata of the Performance Tuning Analysis result.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testFleetPerformanceTuningAnalysisResult = Oci.Jms.GetFleetPerformanceTuningAnalysisResult.Invoke(new()
        ///     {
        ///         FleetId = oci_jms_fleet.Test_fleet.Id,
        ///         PerformanceTuningAnalysisResultId = oci_apm_synthetics_result.Test_result.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetFleetPerformanceTuningAnalysisResultResult> Invoke(GetFleetPerformanceTuningAnalysisResultInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFleetPerformanceTuningAnalysisResultResult>("oci:Jms/getFleetPerformanceTuningAnalysisResult:getFleetPerformanceTuningAnalysisResult", args ?? new GetFleetPerformanceTuningAnalysisResultInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFleetPerformanceTuningAnalysisResultArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        [Input("fleetId", required: true)]
        public string FleetId { get; set; } = null!;

        /// <summary>
        /// The OCID of the performance tuning analysis result.
        /// </summary>
        [Input("performanceTuningAnalysisResultId", required: true)]
        public string PerformanceTuningAnalysisResultId { get; set; } = null!;

        public GetFleetPerformanceTuningAnalysisResultArgs()
        {
        }
        public static new GetFleetPerformanceTuningAnalysisResultArgs Empty => new GetFleetPerformanceTuningAnalysisResultArgs();
    }

    public sealed class GetFleetPerformanceTuningAnalysisResultInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        [Input("fleetId", required: true)]
        public Input<string> FleetId { get; set; } = null!;

        /// <summary>
        /// The OCID of the performance tuning analysis result.
        /// </summary>
        [Input("performanceTuningAnalysisResultId", required: true)]
        public Input<string> PerformanceTuningAnalysisResultId { get; set; } = null!;

        public GetFleetPerformanceTuningAnalysisResultInvokeArgs()
        {
        }
        public static new GetFleetPerformanceTuningAnalysisResultInvokeArgs Empty => new GetFleetPerformanceTuningAnalysisResultInvokeArgs();
    }


    [OutputType]
    public sealed class GetFleetPerformanceTuningAnalysisResultResult
    {
        /// <summary>
        /// The OCID of the application for which the report has been generated.
        /// </summary>
        public readonly string ApplicationId;
        /// <summary>
        /// The internal identifier of the application installation for which the report has been generated.
        /// </summary>
        public readonly string ApplicationInstallationId;
        /// <summary>
        /// The installation path of the application for which the report has been generated.
        /// </summary>
        public readonly string ApplicationInstallationPath;
        /// <summary>
        /// The name of the application for which the report has been generated.
        /// </summary>
        public readonly string ApplicationName;
        /// <summary>
        /// The Object Storage bucket name of this analysis result.
        /// </summary>
        public readonly string Bucket;
        /// <summary>
        /// The fleet OCID.
        /// </summary>
        public readonly string FleetId;
        /// <summary>
        /// The hostname of the managed instance.
        /// </summary>
        public readonly string HostName;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The managed instance OCID.
        /// </summary>
        public readonly string ManagedInstanceId;
        /// <summary>
        /// The Object Storage namespace of this analysis result.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// The Object Storage object name of this analysis result.
        /// </summary>
        public readonly string Object;
        public readonly string PerformanceTuningAnalysisResultId;
        /// <summary>
        /// Result of the analysis based on whether warnings have been found or not.
        /// </summary>
        public readonly string Result;
        /// <summary>
        /// The time the result is compiled.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the JFR capture finished.
        /// </summary>
        public readonly string TimeFinished;
        /// <summary>
        /// The time the JFR capture started.
        /// </summary>
        public readonly string TimeStarted;
        /// <summary>
        /// Total number of warnings reported by the analysis.
        /// </summary>
        public readonly int WarningCount;
        /// <summary>
        /// The OCID of the work request to start the analysis.
        /// </summary>
        public readonly string WorkRequestId;

        [OutputConstructor]
        private GetFleetPerformanceTuningAnalysisResultResult(
            string applicationId,

            string applicationInstallationId,

            string applicationInstallationPath,

            string applicationName,

            string bucket,

            string fleetId,

            string hostName,

            string id,

            string managedInstanceId,

            string @namespace,

            string @object,

            string performanceTuningAnalysisResultId,

            string result,

            string timeCreated,

            string timeFinished,

            string timeStarted,

            int warningCount,

            string workRequestId)
        {
            ApplicationId = applicationId;
            ApplicationInstallationId = applicationInstallationId;
            ApplicationInstallationPath = applicationInstallationPath;
            ApplicationName = applicationName;
            Bucket = bucket;
            FleetId = fleetId;
            HostName = hostName;
            Id = id;
            ManagedInstanceId = managedInstanceId;
            Namespace = @namespace;
            Object = @object;
            PerformanceTuningAnalysisResultId = performanceTuningAnalysisResultId;
            Result = result;
            TimeCreated = timeCreated;
            TimeFinished = timeFinished;
            TimeStarted = timeStarted;
            WarningCount = warningCount;
            WorkRequestId = workRequestId;
        }
    }
}