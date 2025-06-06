// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dataflow

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Application resource in Oracle Cloud Infrastructure Data Flow service.
//
// Retrieves an application using an `applicationId`.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/dataflow"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := dataflow.GetApplication(ctx, &dataflow.GetApplicationArgs{
//				ApplicationId: testApplicationOciDataflowApplication.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupApplication(ctx *pulumi.Context, args *LookupApplicationArgs, opts ...pulumi.InvokeOption) (*LookupApplicationResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupApplicationResult
	err := ctx.Invoke("oci:DataFlow/getApplication:getApplication", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getApplication.
type LookupApplicationArgs struct {
	// The unique ID for an application.
	ApplicationId string `pulumi:"applicationId"`
}

// A collection of values returned by getApplication.
type LookupApplicationResult struct {
	ApplicationId string `pulumi:"applicationId"`
	// Logging details of Application logs for Data Flow Run.
	ApplicationLogConfigs []GetApplicationApplicationLogConfig `pulumi:"applicationLogConfigs"`
	// A comma separated list of one or more archive files as Oracle Cloud Infrastructure URIs. For example, ``oci://path/to/a.zip,oci://path/to/b.zip``. An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution of a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
	ArchiveUri string `pulumi:"archiveUri"`
	// The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ "--input", "${input_file}", "--name", "John Doe" ]` If "inputFile" has a value of "mydata.xml", then the value above will be translated to `--input mydata.xml --name "John Doe"`
	Arguments []string `pulumi:"arguments"`
	// The class for the application.
	ClassName string `pulumi:"className"`
	// The OCID of a compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { "spark.app.name" : "My App Name", "spark.shuffle.io.maxRetries" : "4" } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
	Configuration map[string]string `pulumi:"configuration"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// A user-friendly description.
	Description string `pulumi:"description"`
	// A user-friendly name. This name is not necessarily unique.
	DisplayName string `pulumi:"displayName"`
	// The VM shape for the driver. Sets the driver cores and memory.
	DriverShape string `pulumi:"driverShape"`
	// This is used to configure the shape of the driver or executor if a flexible shape is used.
	DriverShapeConfigs []GetApplicationDriverShapeConfig `pulumi:"driverShapeConfigs"`
	// The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include ``--class``, ``--file``, ``--jars``, ``--conf``, ``--py-files``, and main application file with arguments. Example: ``--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10`` Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
	Execute string `pulumi:"execute"`
	// The VM shape for the executors. Sets the executor cores and memory.
	ExecutorShape string `pulumi:"executorShape"`
	// This is used to configure the shape of the driver or executor if a flexible shape is used.
	ExecutorShapeConfigs []GetApplicationExecutorShapeConfig `pulumi:"executorShapeConfigs"`
	// An Oracle Cloud Infrastructure URI of the file containing the application to execute. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
	FileUri string `pulumi:"fileUri"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The application ID.
	Id string `pulumi:"id"`
	// The timeout value in minutes used to manage Runs. A Run would be stopped after inactivity for this amount of time period. Note: This parameter is currently only applicable for Runs of type `SESSION`. Default value is 2880 minutes (2 days)
	IdleTimeoutInMinutes string `pulumi:"idleTimeoutInMinutes"`
	// The Spark language.
	Language string `pulumi:"language"`
	// An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
	LogsBucketUri string `pulumi:"logsBucketUri"`
	// The maximum duration in minutes for which an Application should run. Data Flow Run would be terminated once it reaches this duration from the time it transitions to `IN_PROGRESS` state.
	MaxDurationInMinutes string `pulumi:"maxDurationInMinutes"`
	// The OCID of Oracle Cloud Infrastructure Hive Metastore.
	MetastoreId string `pulumi:"metastoreId"`
	// The number of executor VMs requested.
	NumExecutors int `pulumi:"numExecutors"`
	// The OCID of the user who created the resource.
	OwnerPrincipalId string `pulumi:"ownerPrincipalId"`
	// The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
	OwnerUserName string `pulumi:"ownerUserName"`
	// An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: "iterations", value: "10"}, { name: "inputFile", value: "mydata.xml" }, { name: "variableX", value: "${x}"} ]
	Parameters []GetApplicationParameter `pulumi:"parameters"`
	// The OCID of a pool. Unique Id to indentify a dataflow pool resource.
	PoolId string `pulumi:"poolId"`
	// The OCID of a private endpoint.
	PrivateEndpointId string `pulumi:"privateEndpointId"`
	// The Spark version utilized to run the application.
	SparkVersion string `pulumi:"sparkVersion"`
	// The current state of this application.
	State string `pulumi:"state"`
	// A boolean flag which indicates whether related non-terminal Run(s) for the Application should be terminated along with Application deletion or not.
	TerminateRunsOnDeletion bool `pulumi:"terminateRunsOnDeletion"`
	// The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
	TimeUpdated string `pulumi:"timeUpdated"`
	// The Spark application processing type.
	Type string `pulumi:"type"`
	// An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
	WarehouseBucketUri string `pulumi:"warehouseBucketUri"`
}

func LookupApplicationOutput(ctx *pulumi.Context, args LookupApplicationOutputArgs, opts ...pulumi.InvokeOption) LookupApplicationResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupApplicationResultOutput, error) {
			args := v.(LookupApplicationArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataFlow/getApplication:getApplication", args, LookupApplicationResultOutput{}, options).(LookupApplicationResultOutput), nil
		}).(LookupApplicationResultOutput)
}

// A collection of arguments for invoking getApplication.
type LookupApplicationOutputArgs struct {
	// The unique ID for an application.
	ApplicationId pulumi.StringInput `pulumi:"applicationId"`
}

func (LookupApplicationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupApplicationArgs)(nil)).Elem()
}

// A collection of values returned by getApplication.
type LookupApplicationResultOutput struct{ *pulumi.OutputState }

func (LookupApplicationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupApplicationResult)(nil)).Elem()
}

func (o LookupApplicationResultOutput) ToLookupApplicationResultOutput() LookupApplicationResultOutput {
	return o
}

func (o LookupApplicationResultOutput) ToLookupApplicationResultOutputWithContext(ctx context.Context) LookupApplicationResultOutput {
	return o
}

func (o LookupApplicationResultOutput) ApplicationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.ApplicationId }).(pulumi.StringOutput)
}

// Logging details of Application logs for Data Flow Run.
func (o LookupApplicationResultOutput) ApplicationLogConfigs() GetApplicationApplicationLogConfigArrayOutput {
	return o.ApplyT(func(v LookupApplicationResult) []GetApplicationApplicationLogConfig { return v.ApplicationLogConfigs }).(GetApplicationApplicationLogConfigArrayOutput)
}

// A comma separated list of one or more archive files as Oracle Cloud Infrastructure URIs. For example, “oci://path/to/a.zip,oci://path/to/b.zip“. An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution of a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
func (o LookupApplicationResultOutput) ArchiveUri() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.ArchiveUri }).(pulumi.StringOutput)
}

// The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ "--input", "${input_file}", "--name", "John Doe" ]` If "inputFile" has a value of "mydata.xml", then the value above will be translated to `--input mydata.xml --name "John Doe"`
func (o LookupApplicationResultOutput) Arguments() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupApplicationResult) []string { return v.Arguments }).(pulumi.StringArrayOutput)
}

// The class for the application.
func (o LookupApplicationResultOutput) ClassName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.ClassName }).(pulumi.StringOutput)
}

// The OCID of a compartment.
func (o LookupApplicationResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { "spark.app.name" : "My App Name", "spark.shuffle.io.maxRetries" : "4" } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
func (o LookupApplicationResultOutput) Configuration() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupApplicationResult) map[string]string { return v.Configuration }).(pulumi.StringMapOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupApplicationResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupApplicationResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// A user-friendly description.
func (o LookupApplicationResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.Description }).(pulumi.StringOutput)
}

// A user-friendly name. This name is not necessarily unique.
func (o LookupApplicationResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The VM shape for the driver. Sets the driver cores and memory.
func (o LookupApplicationResultOutput) DriverShape() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.DriverShape }).(pulumi.StringOutput)
}

// This is used to configure the shape of the driver or executor if a flexible shape is used.
func (o LookupApplicationResultOutput) DriverShapeConfigs() GetApplicationDriverShapeConfigArrayOutput {
	return o.ApplyT(func(v LookupApplicationResult) []GetApplicationDriverShapeConfig { return v.DriverShapeConfigs }).(GetApplicationDriverShapeConfigArrayOutput)
}

// The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include “--class“, “--file“, “--jars“, “--conf“, “--py-files“, and main application file with arguments. Example: “--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10“ Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
func (o LookupApplicationResultOutput) Execute() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.Execute }).(pulumi.StringOutput)
}

// The VM shape for the executors. Sets the executor cores and memory.
func (o LookupApplicationResultOutput) ExecutorShape() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.ExecutorShape }).(pulumi.StringOutput)
}

// This is used to configure the shape of the driver or executor if a flexible shape is used.
func (o LookupApplicationResultOutput) ExecutorShapeConfigs() GetApplicationExecutorShapeConfigArrayOutput {
	return o.ApplyT(func(v LookupApplicationResult) []GetApplicationExecutorShapeConfig { return v.ExecutorShapeConfigs }).(GetApplicationExecutorShapeConfigArrayOutput)
}

// An Oracle Cloud Infrastructure URI of the file containing the application to execute. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
func (o LookupApplicationResultOutput) FileUri() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.FileUri }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupApplicationResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupApplicationResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The application ID.
func (o LookupApplicationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.Id }).(pulumi.StringOutput)
}

// The timeout value in minutes used to manage Runs. A Run would be stopped after inactivity for this amount of time period. Note: This parameter is currently only applicable for Runs of type `SESSION`. Default value is 2880 minutes (2 days)
func (o LookupApplicationResultOutput) IdleTimeoutInMinutes() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.IdleTimeoutInMinutes }).(pulumi.StringOutput)
}

// The Spark language.
func (o LookupApplicationResultOutput) Language() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.Language }).(pulumi.StringOutput)
}

// An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
func (o LookupApplicationResultOutput) LogsBucketUri() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.LogsBucketUri }).(pulumi.StringOutput)
}

// The maximum duration in minutes for which an Application should run. Data Flow Run would be terminated once it reaches this duration from the time it transitions to `IN_PROGRESS` state.
func (o LookupApplicationResultOutput) MaxDurationInMinutes() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.MaxDurationInMinutes }).(pulumi.StringOutput)
}

// The OCID of Oracle Cloud Infrastructure Hive Metastore.
func (o LookupApplicationResultOutput) MetastoreId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.MetastoreId }).(pulumi.StringOutput)
}

// The number of executor VMs requested.
func (o LookupApplicationResultOutput) NumExecutors() pulumi.IntOutput {
	return o.ApplyT(func(v LookupApplicationResult) int { return v.NumExecutors }).(pulumi.IntOutput)
}

// The OCID of the user who created the resource.
func (o LookupApplicationResultOutput) OwnerPrincipalId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.OwnerPrincipalId }).(pulumi.StringOutput)
}

// The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
func (o LookupApplicationResultOutput) OwnerUserName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.OwnerUserName }).(pulumi.StringOutput)
}

// An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: "iterations", value: "10"}, { name: "inputFile", value: "mydata.xml" }, { name: "variableX", value: "${x}"} ]
func (o LookupApplicationResultOutput) Parameters() GetApplicationParameterArrayOutput {
	return o.ApplyT(func(v LookupApplicationResult) []GetApplicationParameter { return v.Parameters }).(GetApplicationParameterArrayOutput)
}

// The OCID of a pool. Unique Id to indentify a dataflow pool resource.
func (o LookupApplicationResultOutput) PoolId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.PoolId }).(pulumi.StringOutput)
}

// The OCID of a private endpoint.
func (o LookupApplicationResultOutput) PrivateEndpointId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.PrivateEndpointId }).(pulumi.StringOutput)
}

// The Spark version utilized to run the application.
func (o LookupApplicationResultOutput) SparkVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.SparkVersion }).(pulumi.StringOutput)
}

// The current state of this application.
func (o LookupApplicationResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.State }).(pulumi.StringOutput)
}

// A boolean flag which indicates whether related non-terminal Run(s) for the Application should be terminated along with Application deletion or not.
func (o LookupApplicationResultOutput) TerminateRunsOnDeletion() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupApplicationResult) bool { return v.TerminateRunsOnDeletion }).(pulumi.BoolOutput)
}

// The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
func (o LookupApplicationResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
func (o LookupApplicationResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The Spark application processing type.
func (o LookupApplicationResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.Type }).(pulumi.StringOutput)
}

// An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
func (o LookupApplicationResultOutput) WarehouseBucketUri() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApplicationResult) string { return v.WarehouseBucketUri }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupApplicationResultOutput{})
}
