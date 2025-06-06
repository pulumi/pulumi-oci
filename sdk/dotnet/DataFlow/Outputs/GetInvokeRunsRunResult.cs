// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataFlow.Outputs
{

    [OutputType]
    public sealed class GetInvokeRunsRunResult
    {
        /// <summary>
        /// The ID of the application.
        /// </summary>
        public readonly string ApplicationId;
        /// <summary>
        /// Logging details of Application logs for Data Flow Run.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvokeRunsRunApplicationLogConfigResult> ApplicationLogConfigs;
        /// <summary>
        /// A comma separated list of one or more archive files as Oracle Cloud Infrastructure URIs. For example, ``oci://path/to/a.zip,oci://path/to/b.zip``. An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution of a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        /// </summary>
        public readonly string ArchiveUri;
        /// <summary>
        /// The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ "--input", "${input_file}", "--name", "John Doe" ]` If "input_file" has a value of "mydata.xml", then the value above will be translated to `--input mydata.xml --name "John Doe"`
        /// </summary>
        public readonly ImmutableArray<string> Arguments;
        public readonly bool Asynchronous;
        /// <summary>
        /// The class for the application.
        /// </summary>
        public readonly string ClassName;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { "spark.app.name" : "My App Name", "spark.shuffle.io.maxRetries" : "4" } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
        /// </summary>
        public readonly ImmutableDictionary<string, string> Configuration;
        /// <summary>
        /// The data read by the run in bytes.
        /// </summary>
        public readonly string DataReadInBytes;
        /// <summary>
        /// The data written by the run in bytes.
        /// </summary>
        public readonly string DataWrittenInBytes;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The query parameter for the Spark application name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The VM shape for the driver. Sets the driver cores and memory.
        /// </summary>
        public readonly string DriverShape;
        /// <summary>
        /// This is used to configure the shape of the driver or executor if a flexible shape is used.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvokeRunsRunDriverShapeConfigResult> DriverShapeConfigs;
        /// <summary>
        /// The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include ``--class``, ``--file``, ``--jars``, ``--conf``, ``--py-files``, and main application file with arguments. Example: ``--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10`` Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
        /// </summary>
        public readonly string Execute;
        /// <summary>
        /// The VM shape for the executors. Sets the executor cores and memory.
        /// </summary>
        public readonly string ExecutorShape;
        /// <summary>
        /// This is used to configure the shape of the driver or executor if a flexible shape is used.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvokeRunsRunExecutorShapeConfigResult> ExecutorShapeConfigs;
        /// <summary>
        /// An Oracle Cloud Infrastructure URI of the file containing the application to execute. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        /// </summary>
        public readonly string FileUri;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The ID of a run.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The timeout value in minutes used to manage Runs. A Run would be stopped after inactivity for this amount of time period. Note: This parameter is currently only applicable for Runs of type `SESSION`. Default value is 2880 minutes (2 days)
        /// </summary>
        public readonly string IdleTimeoutInMinutes;
        /// <summary>
        /// The Spark language.
        /// </summary>
        public readonly string Language;
        /// <summary>
        /// The detailed messages about the lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        /// </summary>
        public readonly string LogsBucketUri;
        /// <summary>
        /// The maximum duration in minutes for which an Application should run. Data Flow Run would be terminated once it reaches this duration from the time it transitions to `IN_PROGRESS` state.
        /// </summary>
        public readonly string MaxDurationInMinutes;
        /// <summary>
        /// The OCID of Oracle Cloud Infrastructure Hive Metastore.
        /// </summary>
        public readonly string MetastoreId;
        /// <summary>
        /// The number of executor VMs requested.
        /// </summary>
        public readonly int NumExecutors;
        public readonly string OpcParentRptUrl;
        /// <summary>
        /// Unique Oracle assigned identifier for the request. If you need to contact Oracle about a particular request, please provide the request ID.
        /// </summary>
        public readonly string OpcRequestId;
        /// <summary>
        /// The OCID of the user who created the resource.
        /// </summary>
        public readonly string OwnerPrincipalId;
        /// <summary>
        /// The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
        /// </summary>
        public readonly string OwnerUserName;
        /// <summary>
        /// An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: "iterations", value: "10"}, { name: "input_file", value: "mydata.xml" }, { name: "variable_x", value: "${x}"} ]
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvokeRunsRunParameterResult> Parameters;
        /// <summary>
        /// The ID of the pool.
        /// </summary>
        public readonly string PoolId;
        /// <summary>
        /// An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
        /// </summary>
        public readonly ImmutableArray<string> PrivateEndpointDnsZones;
        /// <summary>
        /// The OCID of a private endpoint.
        /// </summary>
        public readonly string PrivateEndpointId;
        /// <summary>
        /// The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
        /// </summary>
        public readonly int PrivateEndpointMaxHostCount;
        /// <summary>
        /// An array of network security group OCIDs.
        /// </summary>
        public readonly ImmutableArray<string> PrivateEndpointNsgIds;
        /// <summary>
        /// The OCID of a subnet.
        /// </summary>
        public readonly string PrivateEndpointSubnetId;
        /// <summary>
        /// The duration of the run in milliseconds.
        /// </summary>
        public readonly string RunDurationInMilliseconds;
        /// <summary>
        /// The Spark version utilized to run the application.
        /// </summary>
        public readonly string SparkVersion;
        /// <summary>
        /// The LifecycleState of the run.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The total number of oCPU requested by the run.
        /// </summary>
        public readonly int TotalOcpu;
        /// <summary>
        /// The Spark application processing type.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        /// </summary>
        public readonly string WarehouseBucketUri;

        [OutputConstructor]
        private GetInvokeRunsRunResult(
            string applicationId,

            ImmutableArray<Outputs.GetInvokeRunsRunApplicationLogConfigResult> applicationLogConfigs,

            string archiveUri,

            ImmutableArray<string> arguments,

            bool asynchronous,

            string className,

            string compartmentId,

            ImmutableDictionary<string, string> configuration,

            string dataReadInBytes,

            string dataWrittenInBytes,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string driverShape,

            ImmutableArray<Outputs.GetInvokeRunsRunDriverShapeConfigResult> driverShapeConfigs,

            string execute,

            string executorShape,

            ImmutableArray<Outputs.GetInvokeRunsRunExecutorShapeConfigResult> executorShapeConfigs,

            string fileUri,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string idleTimeoutInMinutes,

            string language,

            string lifecycleDetails,

            string logsBucketUri,

            string maxDurationInMinutes,

            string metastoreId,

            int numExecutors,

            string opcParentRptUrl,

            string opcRequestId,

            string ownerPrincipalId,

            string ownerUserName,

            ImmutableArray<Outputs.GetInvokeRunsRunParameterResult> parameters,

            string poolId,

            ImmutableArray<string> privateEndpointDnsZones,

            string privateEndpointId,

            int privateEndpointMaxHostCount,

            ImmutableArray<string> privateEndpointNsgIds,

            string privateEndpointSubnetId,

            string runDurationInMilliseconds,

            string sparkVersion,

            string state,

            string timeCreated,

            string timeUpdated,

            int totalOcpu,

            string type,

            string warehouseBucketUri)
        {
            ApplicationId = applicationId;
            ApplicationLogConfigs = applicationLogConfigs;
            ArchiveUri = archiveUri;
            Arguments = arguments;
            Asynchronous = asynchronous;
            ClassName = className;
            CompartmentId = compartmentId;
            Configuration = configuration;
            DataReadInBytes = dataReadInBytes;
            DataWrittenInBytes = dataWrittenInBytes;
            DefinedTags = definedTags;
            DisplayName = displayName;
            DriverShape = driverShape;
            DriverShapeConfigs = driverShapeConfigs;
            Execute = execute;
            ExecutorShape = executorShape;
            ExecutorShapeConfigs = executorShapeConfigs;
            FileUri = fileUri;
            FreeformTags = freeformTags;
            Id = id;
            IdleTimeoutInMinutes = idleTimeoutInMinutes;
            Language = language;
            LifecycleDetails = lifecycleDetails;
            LogsBucketUri = logsBucketUri;
            MaxDurationInMinutes = maxDurationInMinutes;
            MetastoreId = metastoreId;
            NumExecutors = numExecutors;
            OpcParentRptUrl = opcParentRptUrl;
            OpcRequestId = opcRequestId;
            OwnerPrincipalId = ownerPrincipalId;
            OwnerUserName = ownerUserName;
            Parameters = parameters;
            PoolId = poolId;
            PrivateEndpointDnsZones = privateEndpointDnsZones;
            PrivateEndpointId = privateEndpointId;
            PrivateEndpointMaxHostCount = privateEndpointMaxHostCount;
            PrivateEndpointNsgIds = privateEndpointNsgIds;
            PrivateEndpointSubnetId = privateEndpointSubnetId;
            RunDurationInMilliseconds = runDurationInMilliseconds;
            SparkVersion = sparkVersion;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            TotalOcpu = totalOcpu;
            Type = type;
            WarehouseBucketUri = warehouseBucketUri;
        }
    }
}
