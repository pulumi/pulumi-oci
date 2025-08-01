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
    'GetDefaultConfigurationResult',
    'AwaitableGetDefaultConfigurationResult',
    'get_default_configuration',
    'get_default_configuration_output',
]

@pulumi.output_type
class GetDefaultConfigurationResult:
    """
    A collection of values returned by getDefaultConfiguration.
    """
    def __init__(__self__, configuration_details=None, db_version=None, default_configuration_id=None, description=None, display_name=None, id=None, instance_memory_size_in_gbs=None, instance_ocpu_count=None, is_flexible=None, lifecycle_details=None, shape=None, state=None, time_created=None):
        if configuration_details and not isinstance(configuration_details, list):
            raise TypeError("Expected argument 'configuration_details' to be a list")
        pulumi.set(__self__, "configuration_details", configuration_details)
        if db_version and not isinstance(db_version, str):
            raise TypeError("Expected argument 'db_version' to be a str")
        pulumi.set(__self__, "db_version", db_version)
        if default_configuration_id and not isinstance(default_configuration_id, str):
            raise TypeError("Expected argument 'default_configuration_id' to be a str")
        pulumi.set(__self__, "default_configuration_id", default_configuration_id)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if instance_memory_size_in_gbs and not isinstance(instance_memory_size_in_gbs, int):
            raise TypeError("Expected argument 'instance_memory_size_in_gbs' to be a int")
        pulumi.set(__self__, "instance_memory_size_in_gbs", instance_memory_size_in_gbs)
        if instance_ocpu_count and not isinstance(instance_ocpu_count, int):
            raise TypeError("Expected argument 'instance_ocpu_count' to be a int")
        pulumi.set(__self__, "instance_ocpu_count", instance_ocpu_count)
        if is_flexible and not isinstance(is_flexible, bool):
            raise TypeError("Expected argument 'is_flexible' to be a bool")
        pulumi.set(__self__, "is_flexible", is_flexible)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if shape and not isinstance(shape, str):
            raise TypeError("Expected argument 'shape' to be a str")
        pulumi.set(__self__, "shape", shape)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter(name="configurationDetails")
    def configuration_details(self) -> Sequence['outputs.GetDefaultConfigurationConfigurationDetailResult']:
        """
        List of default configuration values for databases.
        """
        return pulumi.get(self, "configuration_details")

    @_builtins.property
    @pulumi.getter(name="dbVersion")
    def db_version(self) -> _builtins.str:
        """
        Version of the PostgreSQL database.
        """
        return pulumi.get(self, "db_version")

    @_builtins.property
    @pulumi.getter(name="defaultConfigurationId")
    def default_configuration_id(self) -> _builtins.str:
        return pulumi.get(self, "default_configuration_id")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        A description for the configuration.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly display name for the configuration.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="instanceMemorySizeInGbs")
    def instance_memory_size_in_gbs(self) -> _builtins.int:
        """
        Memory size in gigabytes with 1GB increment.
        """
        return pulumi.get(self, "instance_memory_size_in_gbs")

    @_builtins.property
    @pulumi.getter(name="instanceOcpuCount")
    def instance_ocpu_count(self) -> _builtins.int:
        """
        CPU core count.
        """
        return pulumi.get(self, "instance_ocpu_count")

    @_builtins.property
    @pulumi.getter(name="isFlexible")
    def is_flexible(self) -> _builtins.bool:
        """
        True if the configuration supports flexible shapes, false otherwise.
        """
        return pulumi.get(self, "is_flexible")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def shape(self) -> _builtins.str:
        """
        The name of the shape for the configuration. Example: `VM.Standard.E4.Flex`
        """
        return pulumi.get(self, "shape")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the configuration.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time that the configuration was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")


class AwaitableGetDefaultConfigurationResult(GetDefaultConfigurationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDefaultConfigurationResult(
            configuration_details=self.configuration_details,
            db_version=self.db_version,
            default_configuration_id=self.default_configuration_id,
            description=self.description,
            display_name=self.display_name,
            id=self.id,
            instance_memory_size_in_gbs=self.instance_memory_size_in_gbs,
            instance_ocpu_count=self.instance_ocpu_count,
            is_flexible=self.is_flexible,
            lifecycle_details=self.lifecycle_details,
            shape=self.shape,
            state=self.state,
            time_created=self.time_created)


def get_default_configuration(default_configuration_id: Optional[_builtins.str] = None,
                              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDefaultConfigurationResult:
    """
    This data source provides details about a specific Default Configuration resource in Oracle Cloud Infrastructure Psql service.

    Gets a default configuration by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_default_configuration = oci.Psql.get_default_configuration(default_configuration_id=test_default_configuration_oci_psql_default_configuration["id"])
    ```


    :param _builtins.str default_configuration_id: A unique identifier for the configuration.
    """
    __args__ = dict()
    __args__['defaultConfigurationId'] = default_configuration_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Psql/getDefaultConfiguration:getDefaultConfiguration', __args__, opts=opts, typ=GetDefaultConfigurationResult).value

    return AwaitableGetDefaultConfigurationResult(
        configuration_details=pulumi.get(__ret__, 'configuration_details'),
        db_version=pulumi.get(__ret__, 'db_version'),
        default_configuration_id=pulumi.get(__ret__, 'default_configuration_id'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        id=pulumi.get(__ret__, 'id'),
        instance_memory_size_in_gbs=pulumi.get(__ret__, 'instance_memory_size_in_gbs'),
        instance_ocpu_count=pulumi.get(__ret__, 'instance_ocpu_count'),
        is_flexible=pulumi.get(__ret__, 'is_flexible'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        shape=pulumi.get(__ret__, 'shape'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'))
def get_default_configuration_output(default_configuration_id: Optional[pulumi.Input[_builtins.str]] = None,
                                     opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDefaultConfigurationResult]:
    """
    This data source provides details about a specific Default Configuration resource in Oracle Cloud Infrastructure Psql service.

    Gets a default configuration by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_default_configuration = oci.Psql.get_default_configuration(default_configuration_id=test_default_configuration_oci_psql_default_configuration["id"])
    ```


    :param _builtins.str default_configuration_id: A unique identifier for the configuration.
    """
    __args__ = dict()
    __args__['defaultConfigurationId'] = default_configuration_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Psql/getDefaultConfiguration:getDefaultConfiguration', __args__, opts=opts, typ=GetDefaultConfigurationResult)
    return __ret__.apply(lambda __response__: GetDefaultConfigurationResult(
        configuration_details=pulumi.get(__response__, 'configuration_details'),
        db_version=pulumi.get(__response__, 'db_version'),
        default_configuration_id=pulumi.get(__response__, 'default_configuration_id'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        id=pulumi.get(__response__, 'id'),
        instance_memory_size_in_gbs=pulumi.get(__response__, 'instance_memory_size_in_gbs'),
        instance_ocpu_count=pulumi.get(__response__, 'instance_ocpu_count'),
        is_flexible=pulumi.get(__response__, 'is_flexible'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        shape=pulumi.get(__response__, 'shape'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created')))
