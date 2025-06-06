// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Outputs
{

    [OutputType]
    public sealed class GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollectionItemResult
    {
        /// <summary>
        /// Execution type of the application for an application type, such as WAR and EAR, that is deployed or installed.
        /// </summary>
        public readonly string ApplicationExecutionType;
        /// <summary>
        /// The unique key that identifies the application.
        /// </summary>
        public readonly string ApplicationKey;
        /// <summary>
        /// The name of the application.
        /// </summary>
        public readonly string ApplicationName;
        /// <summary>
        /// The installation path of the application for which the Java migration analysis was performed.
        /// </summary>
        public readonly string ApplicationPath;
        /// <summary>
        /// The name of the object storage bucket that contains the results of the migration analysis.
        /// </summary>
        public readonly string Bucket;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        public readonly string FleetId;
        /// <summary>
        /// The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
        /// </summary>
        public readonly string HostName;
        /// <summary>
        /// The OCID of the migration analysis report.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The Fleet-unique identifier of the related managed instance.
        /// </summary>
        public readonly string ManagedInstanceId;
        /// <summary>
        /// Additional info reserved for future use.
        /// </summary>
        public readonly string Metadata;
        /// <summary>
        /// The object storage namespace that contains the results of the migration analysis.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// The names of the object storage objects that contain the results of the migration analysis.
        /// </summary>
        public readonly ImmutableArray<string> ObjectLists;
        /// <summary>
        /// The directory path of the object storage bucket that contains the results of the migration analysis.
        /// </summary>
        public readonly string ObjectStorageUploadDirPath;
        /// <summary>
        /// The source JDK version of the application that's currently running.
        /// </summary>
        public readonly string SourceJdkVersion;
        /// <summary>
        /// The target JDK version of the application to be migrated.
        /// </summary>
        public readonly string TargetJdkVersion;
        /// <summary>
        /// The time the result is compiled.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The OCID of the work request of this analysis.
        /// </summary>
        public readonly string WorkRequestId;

        [OutputConstructor]
        private GetFleetJavaMigrationAnalysisResultsJavaMigrationAnalysisResultCollectionItemResult(
            string applicationExecutionType,

            string applicationKey,

            string applicationName,

            string applicationPath,

            string bucket,

            string fleetId,

            string hostName,

            string id,

            string managedInstanceId,

            string metadata,

            string @namespace,

            ImmutableArray<string> objectLists,

            string objectStorageUploadDirPath,

            string sourceJdkVersion,

            string targetJdkVersion,

            string timeCreated,

            string workRequestId)
        {
            ApplicationExecutionType = applicationExecutionType;
            ApplicationKey = applicationKey;
            ApplicationName = applicationName;
            ApplicationPath = applicationPath;
            Bucket = bucket;
            FleetId = fleetId;
            HostName = hostName;
            Id = id;
            ManagedInstanceId = managedInstanceId;
            Metadata = metadata;
            Namespace = @namespace;
            ObjectLists = objectLists;
            ObjectStorageUploadDirPath = objectStorageUploadDirPath;
            SourceJdkVersion = sourceJdkVersion;
            TargetJdkVersion = targetJdkVersion;
            TimeCreated = timeCreated;
            WorkRequestId = workRequestId;
        }
    }
}
