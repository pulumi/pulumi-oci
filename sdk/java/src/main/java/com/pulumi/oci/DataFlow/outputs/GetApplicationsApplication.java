// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataFlow.outputs.GetApplicationsApplicationApplicationLogConfig;
import com.pulumi.oci.DataFlow.outputs.GetApplicationsApplicationDriverShapeConfig;
import com.pulumi.oci.DataFlow.outputs.GetApplicationsApplicationExecutorShapeConfig;
import com.pulumi.oci.DataFlow.outputs.GetApplicationsApplicationParameter;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetApplicationsApplication {
    /**
     * @return Logging details of Application logs for Data Flow Run.
     * 
     */
    private List<GetApplicationsApplicationApplicationLogConfig> applicationLogConfigs;
    /**
     * @return A comma separated list of one or more archive files as Oracle Cloud Infrastructure URIs. For example, ``oci://path/to/a.zip,oci://path/to/b.zip``. An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution of a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    private String archiveUri;
    /**
     * @return The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ &#34;--input&#34;, &#34;${input_file}&#34;, &#34;--name&#34;, &#34;John Doe&#34; ]` If &#34;input_file&#34; has a value of &#34;mydata.xml&#34;, then the value above will be translated to `--input mydata.xml --name &#34;John Doe&#34;`
     * 
     */
    private List<String> arguments;
    /**
     * @return The class for the application.
     * 
     */
    private String className;
    /**
     * @return The OCID of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { &#34;spark.app.name&#34; : &#34;My App Name&#34;, &#34;spark.shuffle.io.maxRetries&#34; : &#34;4&#34; } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
     * 
     */
    private Map<String,String> configuration;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A user-friendly description.
     * 
     */
    private String description;
    /**
     * @return The query parameter for the Spark application name.
     * 
     */
    private String displayName;
    /**
     * @return The VM shape for the driver. Sets the driver cores and memory.
     * 
     */
    private String driverShape;
    /**
     * @return This is used to configure the shape of the driver or executor if a flexible shape is used.
     * 
     */
    private List<GetApplicationsApplicationDriverShapeConfig> driverShapeConfigs;
    /**
     * @return The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include ``--class``, ``--file``, ``--jars``, ``--conf``, ``--py-files``, and main application file with arguments. Example: ``--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10`` Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
     * 
     */
    private String execute;
    /**
     * @return The VM shape for the executors. Sets the executor cores and memory.
     * 
     */
    private String executorShape;
    /**
     * @return This is used to configure the shape of the driver or executor if a flexible shape is used.
     * 
     */
    private List<GetApplicationsApplicationExecutorShapeConfig> executorShapeConfigs;
    /**
     * @return An Oracle Cloud Infrastructure URI of the file containing the application to execute. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    private String fileUri;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The application ID.
     * 
     */
    private String id;
    /**
     * @return The timeout value in minutes used to manage Runs. A Run would be stopped after inactivity for this amount of time period. Note: This parameter is currently only applicable for Runs of type `SESSION`. Default value is 2880 minutes (2 days)
     * 
     */
    private String idleTimeoutInMinutes;
    /**
     * @return The Spark language.
     * 
     */
    private String language;
    /**
     * @return An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    private String logsBucketUri;
    /**
     * @return The maximum duration in minutes for which an Application should run. Data Flow Run would be terminated once it reaches this duration from the time it transitions to `IN_PROGRESS` state.
     * 
     */
    private String maxDurationInMinutes;
    /**
     * @return The OCID of Oracle Cloud Infrastructure Hive Metastore.
     * 
     */
    private String metastoreId;
    /**
     * @return The number of executor VMs requested.
     * 
     */
    private Integer numExecutors;
    /**
     * @return The OCID of the user who created the resource.
     * 
     */
    private String ownerPrincipalId;
    /**
     * @return The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     * 
     */
    private String ownerUserName;
    /**
     * @return An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: &#34;iterations&#34;, value: &#34;10&#34;}, { name: &#34;input_file&#34;, value: &#34;mydata.xml&#34; }, { name: &#34;variable_x&#34;, value: &#34;${x}&#34;} ]
     * 
     */
    private List<GetApplicationsApplicationParameter> parameters;
    /**
     * @return The OCID of a pool. Unique Id to indentify a dataflow pool resource.
     * 
     */
    private String poolId;
    /**
     * @return The OCID of a private endpoint.
     * 
     */
    private String privateEndpointId;
    /**
     * @return The Spark version utilized to run the application.
     * 
     */
    private String sparkVersion;
    /**
     * @return The current state of this application.
     * 
     */
    private String state;
    private Boolean terminateRunsOnDeletion;
    /**
     * @return The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private String timeUpdated;
    /**
     * @return The Spark application processing type.
     * 
     */
    private String type;
    /**
     * @return An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    private String warehouseBucketUri;

    private GetApplicationsApplication() {}
    /**
     * @return Logging details of Application logs for Data Flow Run.
     * 
     */
    public List<GetApplicationsApplicationApplicationLogConfig> applicationLogConfigs() {
        return this.applicationLogConfigs;
    }
    /**
     * @return A comma separated list of one or more archive files as Oracle Cloud Infrastructure URIs. For example, ``oci://path/to/a.zip,oci://path/to/b.zip``. An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution of a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
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
    /**
     * @return The class for the application.
     * 
     */
    public String className() {
        return this.className;
    }
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { &#34;spark.app.name&#34; : &#34;My App Name&#34;, &#34;spark.shuffle.io.maxRetries&#34; : &#34;4&#34; } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
     * 
     */
    public Map<String,String> configuration() {
        return this.configuration;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly description.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The query parameter for the Spark application name.
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
     * @return This is used to configure the shape of the driver or executor if a flexible shape is used.
     * 
     */
    public List<GetApplicationsApplicationDriverShapeConfig> driverShapeConfigs() {
        return this.driverShapeConfigs;
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
     * @return This is used to configure the shape of the driver or executor if a flexible shape is used.
     * 
     */
    public List<GetApplicationsApplicationExecutorShapeConfig> executorShapeConfigs() {
        return this.executorShapeConfigs;
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
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The application ID.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The timeout value in minutes used to manage Runs. A Run would be stopped after inactivity for this amount of time period. Note: This parameter is currently only applicable for Runs of type `SESSION`. Default value is 2880 minutes (2 days)
     * 
     */
    public String idleTimeoutInMinutes() {
        return this.idleTimeoutInMinutes;
    }
    /**
     * @return The Spark language.
     * 
     */
    public String language() {
        return this.language;
    }
    /**
     * @return An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     * 
     */
    public String logsBucketUri() {
        return this.logsBucketUri;
    }
    /**
     * @return The maximum duration in minutes for which an Application should run. Data Flow Run would be terminated once it reaches this duration from the time it transitions to `IN_PROGRESS` state.
     * 
     */
    public String maxDurationInMinutes() {
        return this.maxDurationInMinutes;
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
    public List<GetApplicationsApplicationParameter> parameters() {
        return this.parameters;
    }
    /**
     * @return The OCID of a pool. Unique Id to indentify a dataflow pool resource.
     * 
     */
    public String poolId() {
        return this.poolId;
    }
    /**
     * @return The OCID of a private endpoint.
     * 
     */
    public String privateEndpointId() {
        return this.privateEndpointId;
    }
    /**
     * @return The Spark version utilized to run the application.
     * 
     */
    public String sparkVersion() {
        return this.sparkVersion;
    }
    /**
     * @return The current state of this application.
     * 
     */
    public String state() {
        return this.state;
    }
    public Boolean terminateRunsOnDeletion() {
        return this.terminateRunsOnDeletion;
    }
    /**
     * @return The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
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

    public static Builder builder(GetApplicationsApplication defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApplicationsApplicationApplicationLogConfig> applicationLogConfigs;
        private String archiveUri;
        private List<String> arguments;
        private String className;
        private String compartmentId;
        private Map<String,String> configuration;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private String driverShape;
        private List<GetApplicationsApplicationDriverShapeConfig> driverShapeConfigs;
        private String execute;
        private String executorShape;
        private List<GetApplicationsApplicationExecutorShapeConfig> executorShapeConfigs;
        private String fileUri;
        private Map<String,String> freeformTags;
        private String id;
        private String idleTimeoutInMinutes;
        private String language;
        private String logsBucketUri;
        private String maxDurationInMinutes;
        private String metastoreId;
        private Integer numExecutors;
        private String ownerPrincipalId;
        private String ownerUserName;
        private List<GetApplicationsApplicationParameter> parameters;
        private String poolId;
        private String privateEndpointId;
        private String sparkVersion;
        private String state;
        private Boolean terminateRunsOnDeletion;
        private String timeCreated;
        private String timeUpdated;
        private String type;
        private String warehouseBucketUri;
        public Builder() {}
        public Builder(GetApplicationsApplication defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationLogConfigs = defaults.applicationLogConfigs;
    	      this.archiveUri = defaults.archiveUri;
    	      this.arguments = defaults.arguments;
    	      this.className = defaults.className;
    	      this.compartmentId = defaults.compartmentId;
    	      this.configuration = defaults.configuration;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.driverShape = defaults.driverShape;
    	      this.driverShapeConfigs = defaults.driverShapeConfigs;
    	      this.execute = defaults.execute;
    	      this.executorShape = defaults.executorShape;
    	      this.executorShapeConfigs = defaults.executorShapeConfigs;
    	      this.fileUri = defaults.fileUri;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.idleTimeoutInMinutes = defaults.idleTimeoutInMinutes;
    	      this.language = defaults.language;
    	      this.logsBucketUri = defaults.logsBucketUri;
    	      this.maxDurationInMinutes = defaults.maxDurationInMinutes;
    	      this.metastoreId = defaults.metastoreId;
    	      this.numExecutors = defaults.numExecutors;
    	      this.ownerPrincipalId = defaults.ownerPrincipalId;
    	      this.ownerUserName = defaults.ownerUserName;
    	      this.parameters = defaults.parameters;
    	      this.poolId = defaults.poolId;
    	      this.privateEndpointId = defaults.privateEndpointId;
    	      this.sparkVersion = defaults.sparkVersion;
    	      this.state = defaults.state;
    	      this.terminateRunsOnDeletion = defaults.terminateRunsOnDeletion;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.type = defaults.type;
    	      this.warehouseBucketUri = defaults.warehouseBucketUri;
        }

        @CustomType.Setter
        public Builder applicationLogConfigs(List<GetApplicationsApplicationApplicationLogConfig> applicationLogConfigs) {
            if (applicationLogConfigs == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "applicationLogConfigs");
            }
            this.applicationLogConfigs = applicationLogConfigs;
            return this;
        }
        public Builder applicationLogConfigs(GetApplicationsApplicationApplicationLogConfig... applicationLogConfigs) {
            return applicationLogConfigs(List.of(applicationLogConfigs));
        }
        @CustomType.Setter
        public Builder archiveUri(String archiveUri) {
            if (archiveUri == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "archiveUri");
            }
            this.archiveUri = archiveUri;
            return this;
        }
        @CustomType.Setter
        public Builder arguments(List<String> arguments) {
            if (arguments == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "arguments");
            }
            this.arguments = arguments;
            return this;
        }
        public Builder arguments(String... arguments) {
            return arguments(List.of(arguments));
        }
        @CustomType.Setter
        public Builder className(String className) {
            if (className == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "className");
            }
            this.className = className;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder configuration(Map<String,String> configuration) {
            if (configuration == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "configuration");
            }
            this.configuration = configuration;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder driverShape(String driverShape) {
            if (driverShape == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "driverShape");
            }
            this.driverShape = driverShape;
            return this;
        }
        @CustomType.Setter
        public Builder driverShapeConfigs(List<GetApplicationsApplicationDriverShapeConfig> driverShapeConfigs) {
            if (driverShapeConfigs == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "driverShapeConfigs");
            }
            this.driverShapeConfigs = driverShapeConfigs;
            return this;
        }
        public Builder driverShapeConfigs(GetApplicationsApplicationDriverShapeConfig... driverShapeConfigs) {
            return driverShapeConfigs(List.of(driverShapeConfigs));
        }
        @CustomType.Setter
        public Builder execute(String execute) {
            if (execute == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "execute");
            }
            this.execute = execute;
            return this;
        }
        @CustomType.Setter
        public Builder executorShape(String executorShape) {
            if (executorShape == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "executorShape");
            }
            this.executorShape = executorShape;
            return this;
        }
        @CustomType.Setter
        public Builder executorShapeConfigs(List<GetApplicationsApplicationExecutorShapeConfig> executorShapeConfigs) {
            if (executorShapeConfigs == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "executorShapeConfigs");
            }
            this.executorShapeConfigs = executorShapeConfigs;
            return this;
        }
        public Builder executorShapeConfigs(GetApplicationsApplicationExecutorShapeConfig... executorShapeConfigs) {
            return executorShapeConfigs(List.of(executorShapeConfigs));
        }
        @CustomType.Setter
        public Builder fileUri(String fileUri) {
            if (fileUri == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "fileUri");
            }
            this.fileUri = fileUri;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder idleTimeoutInMinutes(String idleTimeoutInMinutes) {
            if (idleTimeoutInMinutes == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "idleTimeoutInMinutes");
            }
            this.idleTimeoutInMinutes = idleTimeoutInMinutes;
            return this;
        }
        @CustomType.Setter
        public Builder language(String language) {
            if (language == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "language");
            }
            this.language = language;
            return this;
        }
        @CustomType.Setter
        public Builder logsBucketUri(String logsBucketUri) {
            if (logsBucketUri == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "logsBucketUri");
            }
            this.logsBucketUri = logsBucketUri;
            return this;
        }
        @CustomType.Setter
        public Builder maxDurationInMinutes(String maxDurationInMinutes) {
            if (maxDurationInMinutes == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "maxDurationInMinutes");
            }
            this.maxDurationInMinutes = maxDurationInMinutes;
            return this;
        }
        @CustomType.Setter
        public Builder metastoreId(String metastoreId) {
            if (metastoreId == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "metastoreId");
            }
            this.metastoreId = metastoreId;
            return this;
        }
        @CustomType.Setter
        public Builder numExecutors(Integer numExecutors) {
            if (numExecutors == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "numExecutors");
            }
            this.numExecutors = numExecutors;
            return this;
        }
        @CustomType.Setter
        public Builder ownerPrincipalId(String ownerPrincipalId) {
            if (ownerPrincipalId == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "ownerPrincipalId");
            }
            this.ownerPrincipalId = ownerPrincipalId;
            return this;
        }
        @CustomType.Setter
        public Builder ownerUserName(String ownerUserName) {
            if (ownerUserName == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "ownerUserName");
            }
            this.ownerUserName = ownerUserName;
            return this;
        }
        @CustomType.Setter
        public Builder parameters(List<GetApplicationsApplicationParameter> parameters) {
            if (parameters == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "parameters");
            }
            this.parameters = parameters;
            return this;
        }
        public Builder parameters(GetApplicationsApplicationParameter... parameters) {
            return parameters(List.of(parameters));
        }
        @CustomType.Setter
        public Builder poolId(String poolId) {
            if (poolId == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "poolId");
            }
            this.poolId = poolId;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointId(String privateEndpointId) {
            if (privateEndpointId == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "privateEndpointId");
            }
            this.privateEndpointId = privateEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder sparkVersion(String sparkVersion) {
            if (sparkVersion == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "sparkVersion");
            }
            this.sparkVersion = sparkVersion;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder terminateRunsOnDeletion(Boolean terminateRunsOnDeletion) {
            if (terminateRunsOnDeletion == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "terminateRunsOnDeletion");
            }
            this.terminateRunsOnDeletion = terminateRunsOnDeletion;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder warehouseBucketUri(String warehouseBucketUri) {
            if (warehouseBucketUri == null) {
              throw new MissingRequiredPropertyException("GetApplicationsApplication", "warehouseBucketUri");
            }
            this.warehouseBucketUri = warehouseBucketUri;
            return this;
        }
        public GetApplicationsApplication build() {
            final var _resultValue = new GetApplicationsApplication();
            _resultValue.applicationLogConfigs = applicationLogConfigs;
            _resultValue.archiveUri = archiveUri;
            _resultValue.arguments = arguments;
            _resultValue.className = className;
            _resultValue.compartmentId = compartmentId;
            _resultValue.configuration = configuration;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.driverShape = driverShape;
            _resultValue.driverShapeConfigs = driverShapeConfigs;
            _resultValue.execute = execute;
            _resultValue.executorShape = executorShape;
            _resultValue.executorShapeConfigs = executorShapeConfigs;
            _resultValue.fileUri = fileUri;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.idleTimeoutInMinutes = idleTimeoutInMinutes;
            _resultValue.language = language;
            _resultValue.logsBucketUri = logsBucketUri;
            _resultValue.maxDurationInMinutes = maxDurationInMinutes;
            _resultValue.metastoreId = metastoreId;
            _resultValue.numExecutors = numExecutors;
            _resultValue.ownerPrincipalId = ownerPrincipalId;
            _resultValue.ownerUserName = ownerUserName;
            _resultValue.parameters = parameters;
            _resultValue.poolId = poolId;
            _resultValue.privateEndpointId = privateEndpointId;
            _resultValue.sparkVersion = sparkVersion;
            _resultValue.state = state;
            _resultValue.terminateRunsOnDeletion = terminateRunsOnDeletion;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.type = type;
            _resultValue.warehouseBucketUri = warehouseBucketUri;
            return _resultValue;
        }
    }
}
