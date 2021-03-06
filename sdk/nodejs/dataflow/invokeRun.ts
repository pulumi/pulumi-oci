// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Invoke Run resource in Oracle Cloud Infrastructure Data Flow service.
 *
 * Creates a run for an application.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInvokeRun = new oci.dataflow.InvokeRun("testInvokeRun", {
 *     compartmentId: _var.compartment_id,
 *     applicationId: oci_dataflow_application.test_application.id,
 *     archiveUri: _var.invoke_run_archive_uri,
 *     arguments: _var.invoke_run_arguments,
 *     configuration: _var.invoke_run_configuration,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: _var.invoke_run_display_name,
 *     driverShape: _var.invoke_run_driver_shape,
 *     execute: _var.invoke_run_execute,
 *     executorShape: _var.invoke_run_executor_shape,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     logsBucketUri: _var.invoke_run_logs_bucket_uri,
 *     metastoreId: _var.metastore_id,
 *     numExecutors: _var.invoke_run_num_executors,
 *     parameters: [{
 *         name: _var.invoke_run_parameters_name,
 *         value: _var.invoke_run_parameters_value,
 *     }],
 *     sparkVersion: _var.invoke_run_spark_version,
 *     type: _var.invoke_run_type,
 *     warehouseBucketUri: _var.invoke_run_warehouse_bucket_uri,
 * });
 * ```
 * ## Note
 *
 * At a time service allows only one run to succeed if user is trying to invoke runs on multiple applications which have Private Endpoints and service will proceed invoking only one run and put the rest of them in failed state.
 *
 * ## Import
 *
 * InvokeRuns can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DataFlow/invokeRun:InvokeRun test_invoke_run "id"
 * ```
 */
export class InvokeRun extends pulumi.CustomResource {
    /**
     * Get an existing InvokeRun resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: InvokeRunState, opts?: pulumi.CustomResourceOptions): InvokeRun {
        return new InvokeRun(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataFlow/invokeRun:InvokeRun';

    /**
     * Returns true if the given object is an instance of InvokeRun.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is InvokeRun {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === InvokeRun.__pulumiType;
    }

    /**
     * The OCID of the associated application. If this value is set, then no value for the execute parameter is required. If this value is not set, then a value for the execute parameter is required, and a new application is created and associated with the new run.
     */
    public readonly applicationId!: pulumi.Output<string>;
    /**
     * An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    public readonly archiveUri!: pulumi.Output<string>;
    /**
     * The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ "--input", "${input_file}", "--name", "John Doe" ]` If "inputFile" has a value of "mydata.xml", then the value above will be translated to `--input mydata.xml --name "John Doe"`
     */
    public readonly arguments!: pulumi.Output<string[]>;
    public readonly asynchronous!: pulumi.Output<boolean | undefined>;
    /**
     * The class for the application.
     */
    public /*out*/ readonly className!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of a compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties Example: { "spark.app.name" : "My App Name", "spark.shuffle.io.maxRetries" : "4" } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
     */
    public readonly configuration!: pulumi.Output<{[key: string]: any}>;
    /**
     * The data read by the run in bytes.
     */
    public /*out*/ readonly dataReadInBytes!: pulumi.Output<string>;
    /**
     * The data written by the run in bytes.
     */
    public /*out*/ readonly dataWrittenInBytes!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * A user-friendly name that does not have to be unique. Avoid entering confidential information. If this value is not specified, it will be derived from the associated application's displayName or set by API using fileUri's application file name.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The VM shape for the driver. Sets the driver cores and memory.
     */
    public readonly driverShape!: pulumi.Output<string>;
    /**
     * The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include ``--class``, ``--file``, ``--jars``, ``--conf``, ``--py-files``, and main application file with arguments. Example: ``--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10`` Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
     */
    public readonly execute!: pulumi.Output<string>;
    /**
     * The VM shape for the executors. Sets the executor cores and memory.
     */
    public readonly executorShape!: pulumi.Output<string>;
    /**
     * An Oracle Cloud Infrastructure URI of the file containing the application to execute. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    public /*out*/ readonly fileUri!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The Spark language.
     */
    public /*out*/ readonly language!: pulumi.Output<string>;
    /**
     * The detailed messages about the lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    public readonly logsBucketUri!: pulumi.Output<string>;
    /**
     * The OCID of Oracle Cloud Infrastructure Hive Metastore.
     */
    public readonly metastoreId!: pulumi.Output<string>;
    /**
     * The number of executor VMs requested.
     */
    public readonly numExecutors!: pulumi.Output<number>;
    /**
     * Unique Oracle assigned identifier for the request. If you need to contact Oracle about a particular request, please provide the request ID.
     */
    public /*out*/ readonly opcRequestId!: pulumi.Output<string>;
    /**
     * The OCID of the user who created the resource.
     */
    public /*out*/ readonly ownerPrincipalId!: pulumi.Output<string>;
    /**
     * The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     */
    public /*out*/ readonly ownerUserName!: pulumi.Output<string>;
    /**
     * An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: "iterations", value: "10"}, { name: "inputFile", value: "mydata.xml" }, { name: "variableX", value: "${x}"} ]
     */
    public readonly parameters!: pulumi.Output<outputs.DataFlow.InvokeRunParameter[]>;
    /**
     * An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
     */
    public /*out*/ readonly privateEndpointDnsZones!: pulumi.Output<string[]>;
    /**
     * The OCID of a private endpoint.
     */
    public /*out*/ readonly privateEndpointId!: pulumi.Output<string>;
    /**
     * The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
     */
    public /*out*/ readonly privateEndpointMaxHostCount!: pulumi.Output<number>;
    /**
     * An array of network security group OCIDs.
     */
    public /*out*/ readonly privateEndpointNsgIds!: pulumi.Output<string[]>;
    /**
     * The OCID of a subnet.
     */
    public /*out*/ readonly privateEndpointSubnetId!: pulumi.Output<string>;
    /**
     * The duration of the run in milliseconds.
     */
    public /*out*/ readonly runDurationInMilliseconds!: pulumi.Output<string>;
    /**
     * The Spark version utilized to run the application. This value may be set if applicationId is not since the Spark version will be taken from the associated application.
     */
    public readonly sparkVersion!: pulumi.Output<string>;
    /**
     * The current state of this run.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time a application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time a application was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * The total number of oCPU requested by the run.
     */
    public /*out*/ readonly totalOcpu!: pulumi.Output<number>;
    /**
     * The Spark application processing type.
     */
    public readonly type!: pulumi.Output<string>;
    /**
     * An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    public readonly warehouseBucketUri!: pulumi.Output<string>;

    /**
     * Create a InvokeRun resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: InvokeRunArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: InvokeRunArgs | InvokeRunState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as InvokeRunState | undefined;
            resourceInputs["applicationId"] = state ? state.applicationId : undefined;
            resourceInputs["archiveUri"] = state ? state.archiveUri : undefined;
            resourceInputs["arguments"] = state ? state.arguments : undefined;
            resourceInputs["asynchronous"] = state ? state.asynchronous : undefined;
            resourceInputs["className"] = state ? state.className : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["configuration"] = state ? state.configuration : undefined;
            resourceInputs["dataReadInBytes"] = state ? state.dataReadInBytes : undefined;
            resourceInputs["dataWrittenInBytes"] = state ? state.dataWrittenInBytes : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["driverShape"] = state ? state.driverShape : undefined;
            resourceInputs["execute"] = state ? state.execute : undefined;
            resourceInputs["executorShape"] = state ? state.executorShape : undefined;
            resourceInputs["fileUri"] = state ? state.fileUri : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["language"] = state ? state.language : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["logsBucketUri"] = state ? state.logsBucketUri : undefined;
            resourceInputs["metastoreId"] = state ? state.metastoreId : undefined;
            resourceInputs["numExecutors"] = state ? state.numExecutors : undefined;
            resourceInputs["opcRequestId"] = state ? state.opcRequestId : undefined;
            resourceInputs["ownerPrincipalId"] = state ? state.ownerPrincipalId : undefined;
            resourceInputs["ownerUserName"] = state ? state.ownerUserName : undefined;
            resourceInputs["parameters"] = state ? state.parameters : undefined;
            resourceInputs["privateEndpointDnsZones"] = state ? state.privateEndpointDnsZones : undefined;
            resourceInputs["privateEndpointId"] = state ? state.privateEndpointId : undefined;
            resourceInputs["privateEndpointMaxHostCount"] = state ? state.privateEndpointMaxHostCount : undefined;
            resourceInputs["privateEndpointNsgIds"] = state ? state.privateEndpointNsgIds : undefined;
            resourceInputs["privateEndpointSubnetId"] = state ? state.privateEndpointSubnetId : undefined;
            resourceInputs["runDurationInMilliseconds"] = state ? state.runDurationInMilliseconds : undefined;
            resourceInputs["sparkVersion"] = state ? state.sparkVersion : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["totalOcpu"] = state ? state.totalOcpu : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
            resourceInputs["warehouseBucketUri"] = state ? state.warehouseBucketUri : undefined;
        } else {
            const args = argsOrState as InvokeRunArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            resourceInputs["applicationId"] = args ? args.applicationId : undefined;
            resourceInputs["archiveUri"] = args ? args.archiveUri : undefined;
            resourceInputs["arguments"] = args ? args.arguments : undefined;
            resourceInputs["asynchronous"] = args ? args.asynchronous : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["configuration"] = args ? args.configuration : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["driverShape"] = args ? args.driverShape : undefined;
            resourceInputs["execute"] = args ? args.execute : undefined;
            resourceInputs["executorShape"] = args ? args.executorShape : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["logsBucketUri"] = args ? args.logsBucketUri : undefined;
            resourceInputs["metastoreId"] = args ? args.metastoreId : undefined;
            resourceInputs["numExecutors"] = args ? args.numExecutors : undefined;
            resourceInputs["parameters"] = args ? args.parameters : undefined;
            resourceInputs["sparkVersion"] = args ? args.sparkVersion : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["warehouseBucketUri"] = args ? args.warehouseBucketUri : undefined;
            resourceInputs["className"] = undefined /*out*/;
            resourceInputs["dataReadInBytes"] = undefined /*out*/;
            resourceInputs["dataWrittenInBytes"] = undefined /*out*/;
            resourceInputs["fileUri"] = undefined /*out*/;
            resourceInputs["language"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["opcRequestId"] = undefined /*out*/;
            resourceInputs["ownerPrincipalId"] = undefined /*out*/;
            resourceInputs["ownerUserName"] = undefined /*out*/;
            resourceInputs["privateEndpointDnsZones"] = undefined /*out*/;
            resourceInputs["privateEndpointId"] = undefined /*out*/;
            resourceInputs["privateEndpointMaxHostCount"] = undefined /*out*/;
            resourceInputs["privateEndpointNsgIds"] = undefined /*out*/;
            resourceInputs["privateEndpointSubnetId"] = undefined /*out*/;
            resourceInputs["runDurationInMilliseconds"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["totalOcpu"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(InvokeRun.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering InvokeRun resources.
 */
export interface InvokeRunState {
    /**
     * The OCID of the associated application. If this value is set, then no value for the execute parameter is required. If this value is not set, then a value for the execute parameter is required, and a new application is created and associated with the new run.
     */
    applicationId?: pulumi.Input<string>;
    /**
     * An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    archiveUri?: pulumi.Input<string>;
    /**
     * The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ "--input", "${input_file}", "--name", "John Doe" ]` If "inputFile" has a value of "mydata.xml", then the value above will be translated to `--input mydata.xml --name "John Doe"`
     */
    arguments?: pulumi.Input<pulumi.Input<string>[]>;
    asynchronous?: pulumi.Input<boolean>;
    /**
     * The class for the application.
     */
    className?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of a compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties Example: { "spark.app.name" : "My App Name", "spark.shuffle.io.maxRetries" : "4" } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
     */
    configuration?: pulumi.Input<{[key: string]: any}>;
    /**
     * The data read by the run in bytes.
     */
    dataReadInBytes?: pulumi.Input<string>;
    /**
     * The data written by the run in bytes.
     */
    dataWrittenInBytes?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A user-friendly name that does not have to be unique. Avoid entering confidential information. If this value is not specified, it will be derived from the associated application's displayName or set by API using fileUri's application file name.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The VM shape for the driver. Sets the driver cores and memory.
     */
    driverShape?: pulumi.Input<string>;
    /**
     * The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include ``--class``, ``--file``, ``--jars``, ``--conf``, ``--py-files``, and main application file with arguments. Example: ``--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10`` Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
     */
    execute?: pulumi.Input<string>;
    /**
     * The VM shape for the executors. Sets the executor cores and memory.
     */
    executorShape?: pulumi.Input<string>;
    /**
     * An Oracle Cloud Infrastructure URI of the file containing the application to execute. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    fileUri?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The Spark language.
     */
    language?: pulumi.Input<string>;
    /**
     * The detailed messages about the lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    logsBucketUri?: pulumi.Input<string>;
    /**
     * The OCID of Oracle Cloud Infrastructure Hive Metastore.
     */
    metastoreId?: pulumi.Input<string>;
    /**
     * The number of executor VMs requested.
     */
    numExecutors?: pulumi.Input<number>;
    /**
     * Unique Oracle assigned identifier for the request. If you need to contact Oracle about a particular request, please provide the request ID.
     */
    opcRequestId?: pulumi.Input<string>;
    /**
     * The OCID of the user who created the resource.
     */
    ownerPrincipalId?: pulumi.Input<string>;
    /**
     * The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     */
    ownerUserName?: pulumi.Input<string>;
    /**
     * An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: "iterations", value: "10"}, { name: "inputFile", value: "mydata.xml" }, { name: "variableX", value: "${x}"} ]
     */
    parameters?: pulumi.Input<pulumi.Input<inputs.DataFlow.InvokeRunParameter>[]>;
    /**
     * An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
     */
    privateEndpointDnsZones?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of a private endpoint.
     */
    privateEndpointId?: pulumi.Input<string>;
    /**
     * The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
     */
    privateEndpointMaxHostCount?: pulumi.Input<number>;
    /**
     * An array of network security group OCIDs.
     */
    privateEndpointNsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of a subnet.
     */
    privateEndpointSubnetId?: pulumi.Input<string>;
    /**
     * The duration of the run in milliseconds.
     */
    runDurationInMilliseconds?: pulumi.Input<string>;
    /**
     * The Spark version utilized to run the application. This value may be set if applicationId is not since the Spark version will be taken from the associated application.
     */
    sparkVersion?: pulumi.Input<string>;
    /**
     * The current state of this run.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time a application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time a application was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * The total number of oCPU requested by the run.
     */
    totalOcpu?: pulumi.Input<number>;
    /**
     * The Spark application processing type.
     */
    type?: pulumi.Input<string>;
    /**
     * An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    warehouseBucketUri?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a InvokeRun resource.
 */
export interface InvokeRunArgs {
    /**
     * The OCID of the associated application. If this value is set, then no value for the execute parameter is required. If this value is not set, then a value for the execute parameter is required, and a new application is created and associated with the new run.
     */
    applicationId?: pulumi.Input<string>;
    /**
     * An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    archiveUri?: pulumi.Input<string>;
    /**
     * The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ "--input", "${input_file}", "--name", "John Doe" ]` If "inputFile" has a value of "mydata.xml", then the value above will be translated to `--input mydata.xml --name "John Doe"`
     */
    arguments?: pulumi.Input<pulumi.Input<string>[]>;
    asynchronous?: pulumi.Input<boolean>;
    /**
     * (Updatable) The OCID of a compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties Example: { "spark.app.name" : "My App Name", "spark.shuffle.io.maxRetries" : "4" } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
     */
    configuration?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A user-friendly name that does not have to be unique. Avoid entering confidential information. If this value is not specified, it will be derived from the associated application's displayName or set by API using fileUri's application file name.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The VM shape for the driver. Sets the driver cores and memory.
     */
    driverShape?: pulumi.Input<string>;
    /**
     * The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include ``--class``, ``--file``, ``--jars``, ``--conf``, ``--py-files``, and main application file with arguments. Example: ``--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10`` Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
     */
    execute?: pulumi.Input<string>;
    /**
     * The VM shape for the executors. Sets the executor cores and memory.
     */
    executorShape?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    logsBucketUri?: pulumi.Input<string>;
    /**
     * The OCID of Oracle Cloud Infrastructure Hive Metastore.
     */
    metastoreId?: pulumi.Input<string>;
    /**
     * The number of executor VMs requested.
     */
    numExecutors?: pulumi.Input<number>;
    /**
     * An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: "iterations", value: "10"}, { name: "inputFile", value: "mydata.xml" }, { name: "variableX", value: "${x}"} ]
     */
    parameters?: pulumi.Input<pulumi.Input<inputs.DataFlow.InvokeRunParameter>[]>;
    /**
     * The Spark version utilized to run the application. This value may be set if applicationId is not since the Spark version will be taken from the associated application.
     */
    sparkVersion?: pulumi.Input<string>;
    /**
     * The Spark application processing type.
     */
    type?: pulumi.Input<string>;
    /**
     * An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
     */
    warehouseBucketUri?: pulumi.Input<string>;
}
