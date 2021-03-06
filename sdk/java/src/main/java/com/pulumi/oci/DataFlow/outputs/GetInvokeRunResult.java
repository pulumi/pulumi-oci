// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataFlow.outputs.GetInvokeRunParameter;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetInvokeRunResult {
    /**
     * @return The application ID.
     * 
     */
    private final String applicationId;
    /**
     * @return An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    private final String archiveUri;
    /**
     * @return The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ &#34;--input&#34;, &#34;${input_file}&#34;, &#34;--name&#34;, &#34;John Doe&#34; ]` If &#34;input_file&#34; has a value of &#34;mydata.xml&#34;, then the value above will be translated to `--input mydata.xml --name &#34;John Doe&#34;`
     * 
     */
    private final List<String> arguments;
    private final Boolean asynchronous;
    /**
     * @return The class for the application.
     * 
     */
    private final String className;
    /**
     * @return The OCID of a compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { &#34;spark.app.name&#34; : &#34;My App Name&#34;, &#34;spark.shuffle.io.maxRetries&#34; : &#34;4&#34; } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
     * 
     */
    private final Map<String,Object> configuration;
    /**
     * @return The data read by the run in bytes.
     * 
     */
    private final String dataReadInBytes;
    /**
     * @return The data written by the run in bytes.
     * 
     */
    private final String dataWrittenInBytes;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return A user-friendly name. This name is not necessarily unique.
     * 
     */
    private final String displayName;
    /**
     * @return The VM shape for the driver. Sets the driver cores and memory.
     * 
     */
    private final String driverShape;
    /**
     * @return The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include ``--class``, ``--file``, ``--jars``, ``--conf``, ``--py-files``, and main application file with arguments. Example: ``--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10`` Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
     * 
     */
    private final String execute;
    /**
     * @return The VM shape for the executors. Sets the executor cores and memory.
     * 
     */
    private final String executorShape;
    /**
     * @return An Oracle Cloud Infrastructure URI of the file containing the application to execute. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    private final String fileUri;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The ID of a run.
     * 
     */
    private final String id;
    /**
     * @return The Spark language.
     * 
     */
    private final String language;
    /**
     * @return The detailed messages about the lifecycle state.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    private final String logsBucketUri;
    /**
     * @return The OCID of Oracle Cloud Infrastructure Hive Metastore.
     * 
     */
    private final String metastoreId;
    /**
     * @return The number of executor VMs requested.
     * 
     */
    private final Integer numExecutors;
    /**
     * @return Unique Oracle assigned identifier for the request. If you need to contact Oracle about a particular request, please provide the request ID.
     * 
     */
    private final String opcRequestId;
    /**
     * @return The OCID of the user who created the resource.
     * 
     */
    private final String ownerPrincipalId;
    /**
     * @return The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     * 
     */
    private final String ownerUserName;
    /**
     * @return An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: &#34;iterations&#34;, value: &#34;10&#34;}, { name: &#34;input_file&#34;, value: &#34;mydata.xml&#34; }, { name: &#34;variable_x&#34;, value: &#34;${x}&#34;} ]
     * 
     */
    private final List<GetInvokeRunParameter> parameters;
    /**
     * @return An array of DNS zone names. Example: `[ &#34;app.examplecorp.com&#34;, &#34;app.examplecorp2.com&#34; ]`
     * 
     */
    private final List<String> privateEndpointDnsZones;
    /**
     * @return The OCID of a private endpoint.
     * 
     */
    private final String privateEndpointId;
    /**
     * @return The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
     * 
     */
    private final Integer privateEndpointMaxHostCount;
    /**
     * @return An array of network security group OCIDs.
     * 
     */
    private final List<String> privateEndpointNsgIds;
    /**
     * @return The OCID of a subnet.
     * 
     */
    private final String privateEndpointSubnetId;
    /**
     * @return The duration of the run in milliseconds.
     * 
     */
    private final String runDurationInMilliseconds;
    private final String runId;
    /**
     * @return The Spark version utilized to run the application.
     * 
     */
    private final String sparkVersion;
    /**
     * @return The current state of this run.
     * 
     */
    private final String state;
    /**
     * @return The date and time a application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return The date and time a application was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private final String timeUpdated;
    /**
     * @return The total number of oCPU requested by the run.
     * 
     */
    private final Integer totalOcpu;
    /**
     * @return The Spark application processing type.
     * 
     */
    private final String type;
    /**
     * @return An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    private final String warehouseBucketUri;

    @CustomType.Constructor
    private GetInvokeRunResult(
        @CustomType.Parameter("applicationId") String applicationId,
        @CustomType.Parameter("archiveUri") String archiveUri,
        @CustomType.Parameter("arguments") List<String> arguments,
        @CustomType.Parameter("asynchronous") Boolean asynchronous,
        @CustomType.Parameter("className") String className,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("configuration") Map<String,Object> configuration,
        @CustomType.Parameter("dataReadInBytes") String dataReadInBytes,
        @CustomType.Parameter("dataWrittenInBytes") String dataWrittenInBytes,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("driverShape") String driverShape,
        @CustomType.Parameter("execute") String execute,
        @CustomType.Parameter("executorShape") String executorShape,
        @CustomType.Parameter("fileUri") String fileUri,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("language") String language,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("logsBucketUri") String logsBucketUri,
        @CustomType.Parameter("metastoreId") String metastoreId,
        @CustomType.Parameter("numExecutors") Integer numExecutors,
        @CustomType.Parameter("opcRequestId") String opcRequestId,
        @CustomType.Parameter("ownerPrincipalId") String ownerPrincipalId,
        @CustomType.Parameter("ownerUserName") String ownerUserName,
        @CustomType.Parameter("parameters") List<GetInvokeRunParameter> parameters,
        @CustomType.Parameter("privateEndpointDnsZones") List<String> privateEndpointDnsZones,
        @CustomType.Parameter("privateEndpointId") String privateEndpointId,
        @CustomType.Parameter("privateEndpointMaxHostCount") Integer privateEndpointMaxHostCount,
        @CustomType.Parameter("privateEndpointNsgIds") List<String> privateEndpointNsgIds,
        @CustomType.Parameter("privateEndpointSubnetId") String privateEndpointSubnetId,
        @CustomType.Parameter("runDurationInMilliseconds") String runDurationInMilliseconds,
        @CustomType.Parameter("runId") String runId,
        @CustomType.Parameter("sparkVersion") String sparkVersion,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeUpdated") String timeUpdated,
        @CustomType.Parameter("totalOcpu") Integer totalOcpu,
        @CustomType.Parameter("type") String type,
        @CustomType.Parameter("warehouseBucketUri") String warehouseBucketUri) {
        this.applicationId = applicationId;
        this.archiveUri = archiveUri;
        this.arguments = arguments;
        this.asynchronous = asynchronous;
        this.className = className;
        this.compartmentId = compartmentId;
        this.configuration = configuration;
        this.dataReadInBytes = dataReadInBytes;
        this.dataWrittenInBytes = dataWrittenInBytes;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.driverShape = driverShape;
        this.execute = execute;
        this.executorShape = executorShape;
        this.fileUri = fileUri;
        this.freeformTags = freeformTags;
        this.id = id;
        this.language = language;
        this.lifecycleDetails = lifecycleDetails;
        this.logsBucketUri = logsBucketUri;
        this.metastoreId = metastoreId;
        this.numExecutors = numExecutors;
        this.opcRequestId = opcRequestId;
        this.ownerPrincipalId = ownerPrincipalId;
        this.ownerUserName = ownerUserName;
        this.parameters = parameters;
        this.privateEndpointDnsZones = privateEndpointDnsZones;
        this.privateEndpointId = privateEndpointId;
        this.privateEndpointMaxHostCount = privateEndpointMaxHostCount;
        this.privateEndpointNsgIds = privateEndpointNsgIds;
        this.privateEndpointSubnetId = privateEndpointSubnetId;
        this.runDurationInMilliseconds = runDurationInMilliseconds;
        this.runId = runId;
        this.sparkVersion = sparkVersion;
        this.state = state;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
        this.totalOcpu = totalOcpu;
        this.type = type;
        this.warehouseBucketUri = warehouseBucketUri;
    }

    /**
     * @return The application ID.
     * 
     */
    public String applicationId() {
        return this.applicationId;
    }
    /**
     * @return An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    public String archiveUri() {
        return this.archiveUri;
    }
    /**
     * @return The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ &#34;--input&#34;, &#34;${input_file}&#34;, &#34;--name&#34;, &#34;John Doe&#34; ]` If &#34;input_file&#34; has a value of &#34;mydata.xml&#34;, then the value above will be translated to `--input mydata.xml --name &#34;John Doe&#34;`
     * 
     */
    public List<String> arguments() {
        return this.arguments;
    }
    public Boolean asynchronous() {
        return this.asynchronous;
    }
    /**
     * @return The class for the application.
     * 
     */
    public String className() {
        return this.className;
    }
    /**
     * @return The OCID of a compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { &#34;spark.app.name&#34; : &#34;My App Name&#34;, &#34;spark.shuffle.io.maxRetries&#34; : &#34;4&#34; } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
     * 
     */
    public Map<String,Object> configuration() {
        return this.configuration;
    }
    /**
     * @return The data read by the run in bytes.
     * 
     */
    public String dataReadInBytes() {
        return this.dataReadInBytes;
    }
    /**
     * @return The data written by the run in bytes.
     * 
     */
    public String dataWrittenInBytes() {
        return this.dataWrittenInBytes;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly name. This name is not necessarily unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The VM shape for the driver. Sets the driver cores and memory.
     * 
     */
    public String driverShape() {
        return this.driverShape;
    }
    /**
     * @return The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include ``--class``, ``--file``, ``--jars``, ``--conf``, ``--py-files``, and main application file with arguments. Example: ``--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10`` Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
     * 
     */
    public String execute() {
        return this.execute;
    }
    /**
     * @return The VM shape for the executors. Sets the executor cores and memory.
     * 
     */
    public String executorShape() {
        return this.executorShape;
    }
    /**
     * @return An Oracle Cloud Infrastructure URI of the file containing the application to execute. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    public String fileUri() {
        return this.fileUri;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The ID of a run.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The Spark language.
     * 
     */
    public String language() {
        return this.language;
    }
    /**
     * @return The detailed messages about the lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    public String logsBucketUri() {
        return this.logsBucketUri;
    }
    /**
     * @return The OCID of Oracle Cloud Infrastructure Hive Metastore.
     * 
     */
    public String metastoreId() {
        return this.metastoreId;
    }
    /**
     * @return The number of executor VMs requested.
     * 
     */
    public Integer numExecutors() {
        return this.numExecutors;
    }
    /**
     * @return Unique Oracle assigned identifier for the request. If you need to contact Oracle about a particular request, please provide the request ID.
     * 
     */
    public String opcRequestId() {
        return this.opcRequestId;
    }
    /**
     * @return The OCID of the user who created the resource.
     * 
     */
    public String ownerPrincipalId() {
        return this.ownerPrincipalId;
    }
    /**
     * @return The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     * 
     */
    public String ownerUserName() {
        return this.ownerUserName;
    }
    /**
     * @return An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: &#34;iterations&#34;, value: &#34;10&#34;}, { name: &#34;input_file&#34;, value: &#34;mydata.xml&#34; }, { name: &#34;variable_x&#34;, value: &#34;${x}&#34;} ]
     * 
     */
    public List<GetInvokeRunParameter> parameters() {
        return this.parameters;
    }
    /**
     * @return An array of DNS zone names. Example: `[ &#34;app.examplecorp.com&#34;, &#34;app.examplecorp2.com&#34; ]`
     * 
     */
    public List<String> privateEndpointDnsZones() {
        return this.privateEndpointDnsZones;
    }
    /**
     * @return The OCID of a private endpoint.
     * 
     */
    public String privateEndpointId() {
        return this.privateEndpointId;
    }
    /**
     * @return The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
     * 
     */
    public Integer privateEndpointMaxHostCount() {
        return this.privateEndpointMaxHostCount;
    }
    /**
     * @return An array of network security group OCIDs.
     * 
     */
    public List<String> privateEndpointNsgIds() {
        return this.privateEndpointNsgIds;
    }
    /**
     * @return The OCID of a subnet.
     * 
     */
    public String privateEndpointSubnetId() {
        return this.privateEndpointSubnetId;
    }
    /**
     * @return The duration of the run in milliseconds.
     * 
     */
    public String runDurationInMilliseconds() {
        return this.runDurationInMilliseconds;
    }
    public String runId() {
        return this.runId;
    }
    /**
     * @return The Spark version utilized to run the application.
     * 
     */
    public String sparkVersion() {
        return this.sparkVersion;
    }
    /**
     * @return The current state of this run.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time a application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time a application was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The total number of oCPU requested by the run.
     * 
     */
    public Integer totalOcpu() {
        return this.totalOcpu;
    }
    /**
     * @return The Spark application processing type.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    public String warehouseBucketUri() {
        return this.warehouseBucketUri;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInvokeRunResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String applicationId;
        private String archiveUri;
        private List<String> arguments;
        private Boolean asynchronous;
        private String className;
        private String compartmentId;
        private Map<String,Object> configuration;
        private String dataReadInBytes;
        private String dataWrittenInBytes;
        private Map<String,Object> definedTags;
        private String displayName;
        private String driverShape;
        private String execute;
        private String executorShape;
        private String fileUri;
        private Map<String,Object> freeformTags;
        private String id;
        private String language;
        private String lifecycleDetails;
        private String logsBucketUri;
        private String metastoreId;
        private Integer numExecutors;
        private String opcRequestId;
        private String ownerPrincipalId;
        private String ownerUserName;
        private List<GetInvokeRunParameter> parameters;
        private List<String> privateEndpointDnsZones;
        private String privateEndpointId;
        private Integer privateEndpointMaxHostCount;
        private List<String> privateEndpointNsgIds;
        private String privateEndpointSubnetId;
        private String runDurationInMilliseconds;
        private String runId;
        private String sparkVersion;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        private Integer totalOcpu;
        private String type;
        private String warehouseBucketUri;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInvokeRunResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationId = defaults.applicationId;
    	      this.archiveUri = defaults.archiveUri;
    	      this.arguments = defaults.arguments;
    	      this.asynchronous = defaults.asynchronous;
    	      this.className = defaults.className;
    	      this.compartmentId = defaults.compartmentId;
    	      this.configuration = defaults.configuration;
    	      this.dataReadInBytes = defaults.dataReadInBytes;
    	      this.dataWrittenInBytes = defaults.dataWrittenInBytes;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.driverShape = defaults.driverShape;
    	      this.execute = defaults.execute;
    	      this.executorShape = defaults.executorShape;
    	      this.fileUri = defaults.fileUri;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.language = defaults.language;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.logsBucketUri = defaults.logsBucketUri;
    	      this.metastoreId = defaults.metastoreId;
    	      this.numExecutors = defaults.numExecutors;
    	      this.opcRequestId = defaults.opcRequestId;
    	      this.ownerPrincipalId = defaults.ownerPrincipalId;
    	      this.ownerUserName = defaults.ownerUserName;
    	      this.parameters = defaults.parameters;
    	      this.privateEndpointDnsZones = defaults.privateEndpointDnsZones;
    	      this.privateEndpointId = defaults.privateEndpointId;
    	      this.privateEndpointMaxHostCount = defaults.privateEndpointMaxHostCount;
    	      this.privateEndpointNsgIds = defaults.privateEndpointNsgIds;
    	      this.privateEndpointSubnetId = defaults.privateEndpointSubnetId;
    	      this.runDurationInMilliseconds = defaults.runDurationInMilliseconds;
    	      this.runId = defaults.runId;
    	      this.sparkVersion = defaults.sparkVersion;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.totalOcpu = defaults.totalOcpu;
    	      this.type = defaults.type;
    	      this.warehouseBucketUri = defaults.warehouseBucketUri;
        }

        public Builder applicationId(String applicationId) {
            this.applicationId = Objects.requireNonNull(applicationId);
            return this;
        }
        public Builder archiveUri(String archiveUri) {
            this.archiveUri = Objects.requireNonNull(archiveUri);
            return this;
        }
        public Builder arguments(List<String> arguments) {
            this.arguments = Objects.requireNonNull(arguments);
            return this;
        }
        public Builder arguments(String... arguments) {
            return arguments(List.of(arguments));
        }
        public Builder asynchronous(Boolean asynchronous) {
            this.asynchronous = Objects.requireNonNull(asynchronous);
            return this;
        }
        public Builder className(String className) {
            this.className = Objects.requireNonNull(className);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder configuration(Map<String,Object> configuration) {
            this.configuration = Objects.requireNonNull(configuration);
            return this;
        }
        public Builder dataReadInBytes(String dataReadInBytes) {
            this.dataReadInBytes = Objects.requireNonNull(dataReadInBytes);
            return this;
        }
        public Builder dataWrittenInBytes(String dataWrittenInBytes) {
            this.dataWrittenInBytes = Objects.requireNonNull(dataWrittenInBytes);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder driverShape(String driverShape) {
            this.driverShape = Objects.requireNonNull(driverShape);
            return this;
        }
        public Builder execute(String execute) {
            this.execute = Objects.requireNonNull(execute);
            return this;
        }
        public Builder executorShape(String executorShape) {
            this.executorShape = Objects.requireNonNull(executorShape);
            return this;
        }
        public Builder fileUri(String fileUri) {
            this.fileUri = Objects.requireNonNull(fileUri);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder language(String language) {
            this.language = Objects.requireNonNull(language);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder logsBucketUri(String logsBucketUri) {
            this.logsBucketUri = Objects.requireNonNull(logsBucketUri);
            return this;
        }
        public Builder metastoreId(String metastoreId) {
            this.metastoreId = Objects.requireNonNull(metastoreId);
            return this;
        }
        public Builder numExecutors(Integer numExecutors) {
            this.numExecutors = Objects.requireNonNull(numExecutors);
            return this;
        }
        public Builder opcRequestId(String opcRequestId) {
            this.opcRequestId = Objects.requireNonNull(opcRequestId);
            return this;
        }
        public Builder ownerPrincipalId(String ownerPrincipalId) {
            this.ownerPrincipalId = Objects.requireNonNull(ownerPrincipalId);
            return this;
        }
        public Builder ownerUserName(String ownerUserName) {
            this.ownerUserName = Objects.requireNonNull(ownerUserName);
            return this;
        }
        public Builder parameters(List<GetInvokeRunParameter> parameters) {
            this.parameters = Objects.requireNonNull(parameters);
            return this;
        }
        public Builder parameters(GetInvokeRunParameter... parameters) {
            return parameters(List.of(parameters));
        }
        public Builder privateEndpointDnsZones(List<String> privateEndpointDnsZones) {
            this.privateEndpointDnsZones = Objects.requireNonNull(privateEndpointDnsZones);
            return this;
        }
        public Builder privateEndpointDnsZones(String... privateEndpointDnsZones) {
            return privateEndpointDnsZones(List.of(privateEndpointDnsZones));
        }
        public Builder privateEndpointId(String privateEndpointId) {
            this.privateEndpointId = Objects.requireNonNull(privateEndpointId);
            return this;
        }
        public Builder privateEndpointMaxHostCount(Integer privateEndpointMaxHostCount) {
            this.privateEndpointMaxHostCount = Objects.requireNonNull(privateEndpointMaxHostCount);
            return this;
        }
        public Builder privateEndpointNsgIds(List<String> privateEndpointNsgIds) {
            this.privateEndpointNsgIds = Objects.requireNonNull(privateEndpointNsgIds);
            return this;
        }
        public Builder privateEndpointNsgIds(String... privateEndpointNsgIds) {
            return privateEndpointNsgIds(List.of(privateEndpointNsgIds));
        }
        public Builder privateEndpointSubnetId(String privateEndpointSubnetId) {
            this.privateEndpointSubnetId = Objects.requireNonNull(privateEndpointSubnetId);
            return this;
        }
        public Builder runDurationInMilliseconds(String runDurationInMilliseconds) {
            this.runDurationInMilliseconds = Objects.requireNonNull(runDurationInMilliseconds);
            return this;
        }
        public Builder runId(String runId) {
            this.runId = Objects.requireNonNull(runId);
            return this;
        }
        public Builder sparkVersion(String sparkVersion) {
            this.sparkVersion = Objects.requireNonNull(sparkVersion);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public Builder totalOcpu(Integer totalOcpu) {
            this.totalOcpu = Objects.requireNonNull(totalOcpu);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public Builder warehouseBucketUri(String warehouseBucketUri) {
            this.warehouseBucketUri = Objects.requireNonNull(warehouseBucketUri);
            return this;
        }        public GetInvokeRunResult build() {
            return new GetInvokeRunResult(applicationId, archiveUri, arguments, asynchronous, className, compartmentId, configuration, dataReadInBytes, dataWrittenInBytes, definedTags, displayName, driverShape, execute, executorShape, fileUri, freeformTags, id, language, lifecycleDetails, logsBucketUri, metastoreId, numExecutors, opcRequestId, ownerPrincipalId, ownerUserName, parameters, privateEndpointDnsZones, privateEndpointId, privateEndpointMaxHostCount, privateEndpointNsgIds, privateEndpointSubnetId, runDurationInMilliseconds, runId, sparkVersion, state, timeCreated, timeUpdated, totalOcpu, type, warehouseBucketUri);
        }
    }
}
