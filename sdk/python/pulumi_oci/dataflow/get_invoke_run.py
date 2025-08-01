# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins as _builtins
import warnings
import sys
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict, TypeAlias
else:
    from typing_extensions import NotRequired, TypedDict, TypeAlias
from .. import _utilities
from . import outputs

__all__ = [
    'GetInvokeRunResult',
    'AwaitableGetInvokeRunResult',
    'get_invoke_run',
    'get_invoke_run_output',
]

@pulumi.output_type
class GetInvokeRunResult:
    """
    A collection of values returned by getInvokeRun.
    """
    def __init__(__self__, application_id=None, application_log_configs=None, archive_uri=None, arguments=None, asynchronous=None, class_name=None, compartment_id=None, configuration=None, data_read_in_bytes=None, data_written_in_bytes=None, defined_tags=None, display_name=None, driver_shape=None, driver_shape_configs=None, execute=None, executor_shape=None, executor_shape_configs=None, file_uri=None, freeform_tags=None, id=None, idle_timeout_in_minutes=None, language=None, lifecycle_details=None, logs_bucket_uri=None, max_duration_in_minutes=None, metastore_id=None, num_executors=None, opc_parent_rpt_url=None, opc_request_id=None, owner_principal_id=None, owner_user_name=None, parameters=None, pool_id=None, private_endpoint_dns_zones=None, private_endpoint_id=None, private_endpoint_max_host_count=None, private_endpoint_nsg_ids=None, private_endpoint_subnet_id=None, run_duration_in_milliseconds=None, run_id=None, spark_version=None, state=None, time_created=None, time_updated=None, total_ocpu=None, type=None, warehouse_bucket_uri=None):
        if application_id and not isinstance(application_id, str):
            raise TypeError("Expected argument 'application_id' to be a str")
        pulumi.set(__self__, "application_id", application_id)
        if application_log_configs and not isinstance(application_log_configs, list):
            raise TypeError("Expected argument 'application_log_configs' to be a list")
        pulumi.set(__self__, "application_log_configs", application_log_configs)
        if archive_uri and not isinstance(archive_uri, str):
            raise TypeError("Expected argument 'archive_uri' to be a str")
        pulumi.set(__self__, "archive_uri", archive_uri)
        if arguments and not isinstance(arguments, list):
            raise TypeError("Expected argument 'arguments' to be a list")
        pulumi.set(__self__, "arguments", arguments)
        if asynchronous and not isinstance(asynchronous, bool):
            raise TypeError("Expected argument 'asynchronous' to be a bool")
        pulumi.set(__self__, "asynchronous", asynchronous)
        if class_name and not isinstance(class_name, str):
            raise TypeError("Expected argument 'class_name' to be a str")
        pulumi.set(__self__, "class_name", class_name)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if configuration and not isinstance(configuration, dict):
            raise TypeError("Expected argument 'configuration' to be a dict")
        pulumi.set(__self__, "configuration", configuration)
        if data_read_in_bytes and not isinstance(data_read_in_bytes, str):
            raise TypeError("Expected argument 'data_read_in_bytes' to be a str")
        pulumi.set(__self__, "data_read_in_bytes", data_read_in_bytes)
        if data_written_in_bytes and not isinstance(data_written_in_bytes, str):
            raise TypeError("Expected argument 'data_written_in_bytes' to be a str")
        pulumi.set(__self__, "data_written_in_bytes", data_written_in_bytes)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if driver_shape and not isinstance(driver_shape, str):
            raise TypeError("Expected argument 'driver_shape' to be a str")
        pulumi.set(__self__, "driver_shape", driver_shape)
        if driver_shape_configs and not isinstance(driver_shape_configs, list):
            raise TypeError("Expected argument 'driver_shape_configs' to be a list")
        pulumi.set(__self__, "driver_shape_configs", driver_shape_configs)
        if execute and not isinstance(execute, str):
            raise TypeError("Expected argument 'execute' to be a str")
        pulumi.set(__self__, "execute", execute)
        if executor_shape and not isinstance(executor_shape, str):
            raise TypeError("Expected argument 'executor_shape' to be a str")
        pulumi.set(__self__, "executor_shape", executor_shape)
        if executor_shape_configs and not isinstance(executor_shape_configs, list):
            raise TypeError("Expected argument 'executor_shape_configs' to be a list")
        pulumi.set(__self__, "executor_shape_configs", executor_shape_configs)
        if file_uri and not isinstance(file_uri, str):
            raise TypeError("Expected argument 'file_uri' to be a str")
        pulumi.set(__self__, "file_uri", file_uri)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if idle_timeout_in_minutes and not isinstance(idle_timeout_in_minutes, str):
            raise TypeError("Expected argument 'idle_timeout_in_minutes' to be a str")
        pulumi.set(__self__, "idle_timeout_in_minutes", idle_timeout_in_minutes)
        if language and not isinstance(language, str):
            raise TypeError("Expected argument 'language' to be a str")
        pulumi.set(__self__, "language", language)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if logs_bucket_uri and not isinstance(logs_bucket_uri, str):
            raise TypeError("Expected argument 'logs_bucket_uri' to be a str")
        pulumi.set(__self__, "logs_bucket_uri", logs_bucket_uri)
        if max_duration_in_minutes and not isinstance(max_duration_in_minutes, str):
            raise TypeError("Expected argument 'max_duration_in_minutes' to be a str")
        pulumi.set(__self__, "max_duration_in_minutes", max_duration_in_minutes)
        if metastore_id and not isinstance(metastore_id, str):
            raise TypeError("Expected argument 'metastore_id' to be a str")
        pulumi.set(__self__, "metastore_id", metastore_id)
        if num_executors and not isinstance(num_executors, int):
            raise TypeError("Expected argument 'num_executors' to be a int")
        pulumi.set(__self__, "num_executors", num_executors)
        if opc_parent_rpt_url and not isinstance(opc_parent_rpt_url, str):
            raise TypeError("Expected argument 'opc_parent_rpt_url' to be a str")
        pulumi.set(__self__, "opc_parent_rpt_url", opc_parent_rpt_url)
        if opc_request_id and not isinstance(opc_request_id, str):
            raise TypeError("Expected argument 'opc_request_id' to be a str")
        pulumi.set(__self__, "opc_request_id", opc_request_id)
        if owner_principal_id and not isinstance(owner_principal_id, str):
            raise TypeError("Expected argument 'owner_principal_id' to be a str")
        pulumi.set(__self__, "owner_principal_id", owner_principal_id)
        if owner_user_name and not isinstance(owner_user_name, str):
            raise TypeError("Expected argument 'owner_user_name' to be a str")
        pulumi.set(__self__, "owner_user_name", owner_user_name)
        if parameters and not isinstance(parameters, list):
            raise TypeError("Expected argument 'parameters' to be a list")
        pulumi.set(__self__, "parameters", parameters)
        if pool_id and not isinstance(pool_id, str):
            raise TypeError("Expected argument 'pool_id' to be a str")
        pulumi.set(__self__, "pool_id", pool_id)
        if private_endpoint_dns_zones and not isinstance(private_endpoint_dns_zones, list):
            raise TypeError("Expected argument 'private_endpoint_dns_zones' to be a list")
        pulumi.set(__self__, "private_endpoint_dns_zones", private_endpoint_dns_zones)
        if private_endpoint_id and not isinstance(private_endpoint_id, str):
            raise TypeError("Expected argument 'private_endpoint_id' to be a str")
        pulumi.set(__self__, "private_endpoint_id", private_endpoint_id)
        if private_endpoint_max_host_count and not isinstance(private_endpoint_max_host_count, int):
            raise TypeError("Expected argument 'private_endpoint_max_host_count' to be a int")
        pulumi.set(__self__, "private_endpoint_max_host_count", private_endpoint_max_host_count)
        if private_endpoint_nsg_ids and not isinstance(private_endpoint_nsg_ids, list):
            raise TypeError("Expected argument 'private_endpoint_nsg_ids' to be a list")
        pulumi.set(__self__, "private_endpoint_nsg_ids", private_endpoint_nsg_ids)
        if private_endpoint_subnet_id and not isinstance(private_endpoint_subnet_id, str):
            raise TypeError("Expected argument 'private_endpoint_subnet_id' to be a str")
        pulumi.set(__self__, "private_endpoint_subnet_id", private_endpoint_subnet_id)
        if run_duration_in_milliseconds and not isinstance(run_duration_in_milliseconds, str):
            raise TypeError("Expected argument 'run_duration_in_milliseconds' to be a str")
        pulumi.set(__self__, "run_duration_in_milliseconds", run_duration_in_milliseconds)
        if run_id and not isinstance(run_id, str):
            raise TypeError("Expected argument 'run_id' to be a str")
        pulumi.set(__self__, "run_id", run_id)
        if spark_version and not isinstance(spark_version, str):
            raise TypeError("Expected argument 'spark_version' to be a str")
        pulumi.set(__self__, "spark_version", spark_version)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if total_ocpu and not isinstance(total_ocpu, int):
            raise TypeError("Expected argument 'total_ocpu' to be a int")
        pulumi.set(__self__, "total_ocpu", total_ocpu)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)
        if warehouse_bucket_uri and not isinstance(warehouse_bucket_uri, str):
            raise TypeError("Expected argument 'warehouse_bucket_uri' to be a str")
        pulumi.set(__self__, "warehouse_bucket_uri", warehouse_bucket_uri)

    @_builtins.property
    @pulumi.getter(name="applicationId")
    def application_id(self) -> _builtins.str:
        """
        The application ID.
        """
        return pulumi.get(self, "application_id")

    @_builtins.property
    @pulumi.getter(name="applicationLogConfigs")
    def application_log_configs(self) -> Sequence['outputs.GetInvokeRunApplicationLogConfigResult']:
        """
        Logging details of Application logs for Data Flow Run.
        """
        return pulumi.get(self, "application_log_configs")

    @_builtins.property
    @pulumi.getter(name="archiveUri")
    def archive_uri(self) -> _builtins.str:
        """
        A comma separated list of one or more archive files as Oracle Cloud Infrastructure URIs. For example, ``oci://path/to/a.zip,oci://path/to/b.zip``. An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution of a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        """
        return pulumi.get(self, "archive_uri")

    @_builtins.property
    @pulumi.getter
    def arguments(self) -> Sequence[_builtins.str]:
        """
        The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ "--input", "${input_file}", "--name", "John Doe" ]` If "input_file" has a value of "mydata.xml", then the value above will be translated to `--input mydata.xml --name "John Doe"`
        """
        return pulumi.get(self, "arguments")

    @_builtins.property
    @pulumi.getter
    def asynchronous(self) -> _builtins.bool:
        return pulumi.get(self, "asynchronous")

    @_builtins.property
    @pulumi.getter(name="className")
    def class_name(self) -> _builtins.str:
        """
        The class for the application.
        """
        return pulumi.get(self, "class_name")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of a compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def configuration(self) -> Mapping[str, _builtins.str]:
        """
        The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { "spark.app.name" : "My App Name", "spark.shuffle.io.maxRetries" : "4" } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
        """
        return pulumi.get(self, "configuration")

    @_builtins.property
    @pulumi.getter(name="dataReadInBytes")
    def data_read_in_bytes(self) -> _builtins.str:
        """
        The data read by the run in bytes.
        """
        return pulumi.get(self, "data_read_in_bytes")

    @_builtins.property
    @pulumi.getter(name="dataWrittenInBytes")
    def data_written_in_bytes(self) -> _builtins.str:
        """
        The data written by the run in bytes.
        """
        return pulumi.get(self, "data_written_in_bytes")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. This name is not necessarily unique.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="driverShape")
    def driver_shape(self) -> _builtins.str:
        """
        The VM shape for the driver. Sets the driver cores and memory.
        """
        return pulumi.get(self, "driver_shape")

    @_builtins.property
    @pulumi.getter(name="driverShapeConfigs")
    def driver_shape_configs(self) -> Sequence['outputs.GetInvokeRunDriverShapeConfigResult']:
        """
        This is used to configure the shape of the driver or executor if a flexible shape is used.
        """
        return pulumi.get(self, "driver_shape_configs")

    @_builtins.property
    @pulumi.getter
    def execute(self) -> _builtins.str:
        """
        The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include ``--class``, ``--file``, ``--jars``, ``--conf``, ``--py-files``, and main application file with arguments. Example: ``--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10`` Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
        """
        return pulumi.get(self, "execute")

    @_builtins.property
    @pulumi.getter(name="executorShape")
    def executor_shape(self) -> _builtins.str:
        """
        The VM shape for the executors. Sets the executor cores and memory.
        """
        return pulumi.get(self, "executor_shape")

    @_builtins.property
    @pulumi.getter(name="executorShapeConfigs")
    def executor_shape_configs(self) -> Sequence['outputs.GetInvokeRunExecutorShapeConfigResult']:
        """
        This is used to configure the shape of the driver or executor if a flexible shape is used.
        """
        return pulumi.get(self, "executor_shape_configs")

    @_builtins.property
    @pulumi.getter(name="fileUri")
    def file_uri(self) -> _builtins.str:
        """
        An Oracle Cloud Infrastructure URI of the file containing the application to execute. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        """
        return pulumi.get(self, "file_uri")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The ID of a run.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="idleTimeoutInMinutes")
    def idle_timeout_in_minutes(self) -> _builtins.str:
        """
        The timeout value in minutes used to manage Runs. A Run would be stopped after inactivity for this amount of time period. Note: This parameter is currently only applicable for Runs of type `SESSION`. Default value is 2880 minutes (2 days)
        """
        return pulumi.get(self, "idle_timeout_in_minutes")

    @_builtins.property
    @pulumi.getter
    def language(self) -> _builtins.str:
        """
        The Spark language.
        """
        return pulumi.get(self, "language")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        The detailed messages about the lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="logsBucketUri")
    def logs_bucket_uri(self) -> _builtins.str:
        """
        An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        """
        return pulumi.get(self, "logs_bucket_uri")

    @_builtins.property
    @pulumi.getter(name="maxDurationInMinutes")
    def max_duration_in_minutes(self) -> _builtins.str:
        """
        The maximum duration in minutes for which an Application should run. Data Flow Run would be terminated once it reaches this duration from the time it transitions to `IN_PROGRESS` state.
        """
        return pulumi.get(self, "max_duration_in_minutes")

    @_builtins.property
    @pulumi.getter(name="metastoreId")
    def metastore_id(self) -> _builtins.str:
        """
        The OCID of Oracle Cloud Infrastructure Hive Metastore.
        """
        return pulumi.get(self, "metastore_id")

    @_builtins.property
    @pulumi.getter(name="numExecutors")
    def num_executors(self) -> _builtins.int:
        """
        The number of executor VMs requested.
        """
        return pulumi.get(self, "num_executors")

    @_builtins.property
    @pulumi.getter(name="opcParentRptUrl")
    def opc_parent_rpt_url(self) -> _builtins.str:
        return pulumi.get(self, "opc_parent_rpt_url")

    @_builtins.property
    @pulumi.getter(name="opcRequestId")
    def opc_request_id(self) -> _builtins.str:
        """
        Unique Oracle assigned identifier for the request. If you need to contact Oracle about a particular request, please provide the request ID.
        """
        return pulumi.get(self, "opc_request_id")

    @_builtins.property
    @pulumi.getter(name="ownerPrincipalId")
    def owner_principal_id(self) -> _builtins.str:
        """
        The OCID of the user who created the resource.
        """
        return pulumi.get(self, "owner_principal_id")

    @_builtins.property
    @pulumi.getter(name="ownerUserName")
    def owner_user_name(self) -> _builtins.str:
        """
        The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
        """
        return pulumi.get(self, "owner_user_name")

    @_builtins.property
    @pulumi.getter
    def parameters(self) -> Sequence['outputs.GetInvokeRunParameterResult']:
        """
        An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: "iterations", value: "10"}, { name: "input_file", value: "mydata.xml" }, { name: "variable_x", value: "${x}"} ]
        """
        return pulumi.get(self, "parameters")

    @_builtins.property
    @pulumi.getter(name="poolId")
    def pool_id(self) -> _builtins.str:
        """
        The OCID of a pool. Unique Id to indentify a dataflow pool resource.
        """
        return pulumi.get(self, "pool_id")

    @_builtins.property
    @pulumi.getter(name="privateEndpointDnsZones")
    def private_endpoint_dns_zones(self) -> Sequence[_builtins.str]:
        """
        An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
        """
        return pulumi.get(self, "private_endpoint_dns_zones")

    @_builtins.property
    @pulumi.getter(name="privateEndpointId")
    def private_endpoint_id(self) -> _builtins.str:
        """
        The OCID of a private endpoint.
        """
        return pulumi.get(self, "private_endpoint_id")

    @_builtins.property
    @pulumi.getter(name="privateEndpointMaxHostCount")
    def private_endpoint_max_host_count(self) -> _builtins.int:
        """
        The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
        """
        return pulumi.get(self, "private_endpoint_max_host_count")

    @_builtins.property
    @pulumi.getter(name="privateEndpointNsgIds")
    def private_endpoint_nsg_ids(self) -> Sequence[_builtins.str]:
        """
        An array of network security group OCIDs.
        """
        return pulumi.get(self, "private_endpoint_nsg_ids")

    @_builtins.property
    @pulumi.getter(name="privateEndpointSubnetId")
    def private_endpoint_subnet_id(self) -> _builtins.str:
        """
        The OCID of a subnet.
        """
        return pulumi.get(self, "private_endpoint_subnet_id")

    @_builtins.property
    @pulumi.getter(name="runDurationInMilliseconds")
    def run_duration_in_milliseconds(self) -> _builtins.str:
        """
        The duration of the run in milliseconds.
        """
        return pulumi.get(self, "run_duration_in_milliseconds")

    @_builtins.property
    @pulumi.getter(name="runId")
    def run_id(self) -> _builtins.str:
        return pulumi.get(self, "run_id")

    @_builtins.property
    @pulumi.getter(name="sparkVersion")
    def spark_version(self) -> _builtins.str:
        """
        The Spark version utilized to run the application.
        """
        return pulumi.get(self, "spark_version")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of this run.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        """
        return pulumi.get(self, "time_updated")

    @_builtins.property
    @pulumi.getter(name="totalOcpu")
    def total_ocpu(self) -> _builtins.int:
        """
        The total number of oCPU requested by the run.
        """
        return pulumi.get(self, "total_ocpu")

    @_builtins.property
    @pulumi.getter
    def type(self) -> _builtins.str:
        """
        The Spark application processing type.
        """
        return pulumi.get(self, "type")

    @_builtins.property
    @pulumi.getter(name="warehouseBucketUri")
    def warehouse_bucket_uri(self) -> _builtins.str:
        """
        An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        """
        return pulumi.get(self, "warehouse_bucket_uri")


class AwaitableGetInvokeRunResult(GetInvokeRunResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetInvokeRunResult(
            application_id=self.application_id,
            application_log_configs=self.application_log_configs,
            archive_uri=self.archive_uri,
            arguments=self.arguments,
            asynchronous=self.asynchronous,
            class_name=self.class_name,
            compartment_id=self.compartment_id,
            configuration=self.configuration,
            data_read_in_bytes=self.data_read_in_bytes,
            data_written_in_bytes=self.data_written_in_bytes,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            driver_shape=self.driver_shape,
            driver_shape_configs=self.driver_shape_configs,
            execute=self.execute,
            executor_shape=self.executor_shape,
            executor_shape_configs=self.executor_shape_configs,
            file_uri=self.file_uri,
            freeform_tags=self.freeform_tags,
            id=self.id,
            idle_timeout_in_minutes=self.idle_timeout_in_minutes,
            language=self.language,
            lifecycle_details=self.lifecycle_details,
            logs_bucket_uri=self.logs_bucket_uri,
            max_duration_in_minutes=self.max_duration_in_minutes,
            metastore_id=self.metastore_id,
            num_executors=self.num_executors,
            opc_parent_rpt_url=self.opc_parent_rpt_url,
            opc_request_id=self.opc_request_id,
            owner_principal_id=self.owner_principal_id,
            owner_user_name=self.owner_user_name,
            parameters=self.parameters,
            pool_id=self.pool_id,
            private_endpoint_dns_zones=self.private_endpoint_dns_zones,
            private_endpoint_id=self.private_endpoint_id,
            private_endpoint_max_host_count=self.private_endpoint_max_host_count,
            private_endpoint_nsg_ids=self.private_endpoint_nsg_ids,
            private_endpoint_subnet_id=self.private_endpoint_subnet_id,
            run_duration_in_milliseconds=self.run_duration_in_milliseconds,
            run_id=self.run_id,
            spark_version=self.spark_version,
            state=self.state,
            time_created=self.time_created,
            time_updated=self.time_updated,
            total_ocpu=self.total_ocpu,
            type=self.type,
            warehouse_bucket_uri=self.warehouse_bucket_uri)


def get_invoke_run(run_id: Optional[_builtins.str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetInvokeRunResult:
    """
    This data source provides details about a specific Invoke Run resource in Oracle Cloud Infrastructure Data Flow service.

    Retrieves the run for the specified `runId`.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_invoke_run = oci.DataFlow.get_invoke_run(run_id=test_run["id"])
    ```


    :param _builtins.str run_id: The unique ID for the run
    """
    __args__ = dict()
    __args__['runId'] = run_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataFlow/getInvokeRun:getInvokeRun', __args__, opts=opts, typ=GetInvokeRunResult).value

    return AwaitableGetInvokeRunResult(
        application_id=pulumi.get(__ret__, 'application_id'),
        application_log_configs=pulumi.get(__ret__, 'application_log_configs'),
        archive_uri=pulumi.get(__ret__, 'archive_uri'),
        arguments=pulumi.get(__ret__, 'arguments'),
        asynchronous=pulumi.get(__ret__, 'asynchronous'),
        class_name=pulumi.get(__ret__, 'class_name'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        configuration=pulumi.get(__ret__, 'configuration'),
        data_read_in_bytes=pulumi.get(__ret__, 'data_read_in_bytes'),
        data_written_in_bytes=pulumi.get(__ret__, 'data_written_in_bytes'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        driver_shape=pulumi.get(__ret__, 'driver_shape'),
        driver_shape_configs=pulumi.get(__ret__, 'driver_shape_configs'),
        execute=pulumi.get(__ret__, 'execute'),
        executor_shape=pulumi.get(__ret__, 'executor_shape'),
        executor_shape_configs=pulumi.get(__ret__, 'executor_shape_configs'),
        file_uri=pulumi.get(__ret__, 'file_uri'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        idle_timeout_in_minutes=pulumi.get(__ret__, 'idle_timeout_in_minutes'),
        language=pulumi.get(__ret__, 'language'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        logs_bucket_uri=pulumi.get(__ret__, 'logs_bucket_uri'),
        max_duration_in_minutes=pulumi.get(__ret__, 'max_duration_in_minutes'),
        metastore_id=pulumi.get(__ret__, 'metastore_id'),
        num_executors=pulumi.get(__ret__, 'num_executors'),
        opc_parent_rpt_url=pulumi.get(__ret__, 'opc_parent_rpt_url'),
        opc_request_id=pulumi.get(__ret__, 'opc_request_id'),
        owner_principal_id=pulumi.get(__ret__, 'owner_principal_id'),
        owner_user_name=pulumi.get(__ret__, 'owner_user_name'),
        parameters=pulumi.get(__ret__, 'parameters'),
        pool_id=pulumi.get(__ret__, 'pool_id'),
        private_endpoint_dns_zones=pulumi.get(__ret__, 'private_endpoint_dns_zones'),
        private_endpoint_id=pulumi.get(__ret__, 'private_endpoint_id'),
        private_endpoint_max_host_count=pulumi.get(__ret__, 'private_endpoint_max_host_count'),
        private_endpoint_nsg_ids=pulumi.get(__ret__, 'private_endpoint_nsg_ids'),
        private_endpoint_subnet_id=pulumi.get(__ret__, 'private_endpoint_subnet_id'),
        run_duration_in_milliseconds=pulumi.get(__ret__, 'run_duration_in_milliseconds'),
        run_id=pulumi.get(__ret__, 'run_id'),
        spark_version=pulumi.get(__ret__, 'spark_version'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'),
        total_ocpu=pulumi.get(__ret__, 'total_ocpu'),
        type=pulumi.get(__ret__, 'type'),
        warehouse_bucket_uri=pulumi.get(__ret__, 'warehouse_bucket_uri'))
def get_invoke_run_output(run_id: Optional[pulumi.Input[_builtins.str]] = None,
                          opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetInvokeRunResult]:
    """
    This data source provides details about a specific Invoke Run resource in Oracle Cloud Infrastructure Data Flow service.

    Retrieves the run for the specified `runId`.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_invoke_run = oci.DataFlow.get_invoke_run(run_id=test_run["id"])
    ```


    :param _builtins.str run_id: The unique ID for the run
    """
    __args__ = dict()
    __args__['runId'] = run_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataFlow/getInvokeRun:getInvokeRun', __args__, opts=opts, typ=GetInvokeRunResult)
    return __ret__.apply(lambda __response__: GetInvokeRunResult(
        application_id=pulumi.get(__response__, 'application_id'),
        application_log_configs=pulumi.get(__response__, 'application_log_configs'),
        archive_uri=pulumi.get(__response__, 'archive_uri'),
        arguments=pulumi.get(__response__, 'arguments'),
        asynchronous=pulumi.get(__response__, 'asynchronous'),
        class_name=pulumi.get(__response__, 'class_name'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        configuration=pulumi.get(__response__, 'configuration'),
        data_read_in_bytes=pulumi.get(__response__, 'data_read_in_bytes'),
        data_written_in_bytes=pulumi.get(__response__, 'data_written_in_bytes'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        driver_shape=pulumi.get(__response__, 'driver_shape'),
        driver_shape_configs=pulumi.get(__response__, 'driver_shape_configs'),
        execute=pulumi.get(__response__, 'execute'),
        executor_shape=pulumi.get(__response__, 'executor_shape'),
        executor_shape_configs=pulumi.get(__response__, 'executor_shape_configs'),
        file_uri=pulumi.get(__response__, 'file_uri'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        idle_timeout_in_minutes=pulumi.get(__response__, 'idle_timeout_in_minutes'),
        language=pulumi.get(__response__, 'language'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        logs_bucket_uri=pulumi.get(__response__, 'logs_bucket_uri'),
        max_duration_in_minutes=pulumi.get(__response__, 'max_duration_in_minutes'),
        metastore_id=pulumi.get(__response__, 'metastore_id'),
        num_executors=pulumi.get(__response__, 'num_executors'),
        opc_parent_rpt_url=pulumi.get(__response__, 'opc_parent_rpt_url'),
        opc_request_id=pulumi.get(__response__, 'opc_request_id'),
        owner_principal_id=pulumi.get(__response__, 'owner_principal_id'),
        owner_user_name=pulumi.get(__response__, 'owner_user_name'),
        parameters=pulumi.get(__response__, 'parameters'),
        pool_id=pulumi.get(__response__, 'pool_id'),
        private_endpoint_dns_zones=pulumi.get(__response__, 'private_endpoint_dns_zones'),
        private_endpoint_id=pulumi.get(__response__, 'private_endpoint_id'),
        private_endpoint_max_host_count=pulumi.get(__response__, 'private_endpoint_max_host_count'),
        private_endpoint_nsg_ids=pulumi.get(__response__, 'private_endpoint_nsg_ids'),
        private_endpoint_subnet_id=pulumi.get(__response__, 'private_endpoint_subnet_id'),
        run_duration_in_milliseconds=pulumi.get(__response__, 'run_duration_in_milliseconds'),
        run_id=pulumi.get(__response__, 'run_id'),
        spark_version=pulumi.get(__response__, 'spark_version'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated'),
        total_ocpu=pulumi.get(__response__, 'total_ocpu'),
        type=pulumi.get(__response__, 'type'),
        warehouse_bucket_uri=pulumi.get(__response__, 'warehouse_bucket_uri')))
