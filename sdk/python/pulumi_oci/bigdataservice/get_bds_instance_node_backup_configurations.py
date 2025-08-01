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
from ._inputs import *

__all__ = [
    'GetBdsInstanceNodeBackupConfigurationsResult',
    'AwaitableGetBdsInstanceNodeBackupConfigurationsResult',
    'get_bds_instance_node_backup_configurations',
    'get_bds_instance_node_backup_configurations_output',
]

@pulumi.output_type
class GetBdsInstanceNodeBackupConfigurationsResult:
    """
    A collection of values returned by getBdsInstanceNodeBackupConfigurations.
    """
    def __init__(__self__, bds_instance_id=None, display_name=None, filters=None, id=None, node_backup_configurations=None, state=None):
        if bds_instance_id and not isinstance(bds_instance_id, str):
            raise TypeError("Expected argument 'bds_instance_id' to be a str")
        pulumi.set(__self__, "bds_instance_id", bds_instance_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if node_backup_configurations and not isinstance(node_backup_configurations, list):
            raise TypeError("Expected argument 'node_backup_configurations' to be a list")
        pulumi.set(__self__, "node_backup_configurations", node_backup_configurations)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="bdsInstanceId")
    def bds_instance_id(self) -> _builtins.str:
        """
        The OCID of the bdsInstance which is the parent resource id.
        """
        return pulumi.get(self, "bds_instance_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        A user-friendly name. Only ASCII alphanumeric characters with no spaces allowed. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetBdsInstanceNodeBackupConfigurationsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="nodeBackupConfigurations")
    def node_backup_configurations(self) -> Sequence['outputs.GetBdsInstanceNodeBackupConfigurationsNodeBackupConfigurationResult']:
        """
        The list of node_backup_configurations.
        """
        return pulumi.get(self, "node_backup_configurations")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The state of the NodeBackupConfiguration.
        """
        return pulumi.get(self, "state")


class AwaitableGetBdsInstanceNodeBackupConfigurationsResult(GetBdsInstanceNodeBackupConfigurationsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetBdsInstanceNodeBackupConfigurationsResult(
            bds_instance_id=self.bds_instance_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            node_backup_configurations=self.node_backup_configurations,
            state=self.state)


def get_bds_instance_node_backup_configurations(bds_instance_id: Optional[_builtins.str] = None,
                                                display_name: Optional[_builtins.str] = None,
                                                filters: Optional[Sequence[Union['GetBdsInstanceNodeBackupConfigurationsFilterArgs', 'GetBdsInstanceNodeBackupConfigurationsFilterArgsDict']]] = None,
                                                state: Optional[_builtins.str] = None,
                                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetBdsInstanceNodeBackupConfigurationsResult:
    """
    This data source provides the list of Bds Instance Node Backup Configurations in Oracle Cloud Infrastructure Big Data Service service.

    Returns information about the NodeBackupConfigurations.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_bds_instance_node_backup_configurations = oci.BigDataService.get_bds_instance_node_backup_configurations(bds_instance_id=test_bds_instance["id"],
        display_name=bds_instance_node_backup_configuration_display_name,
        state=bds_instance_node_backup_configuration_state)
    ```


    :param _builtins.str bds_instance_id: The OCID of the cluster.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str state: The state of the NodeBackupConfiguration configuration.
    """
    __args__ = dict()
    __args__['bdsInstanceId'] = bds_instance_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:BigDataService/getBdsInstanceNodeBackupConfigurations:getBdsInstanceNodeBackupConfigurations', __args__, opts=opts, typ=GetBdsInstanceNodeBackupConfigurationsResult).value

    return AwaitableGetBdsInstanceNodeBackupConfigurationsResult(
        bds_instance_id=pulumi.get(__ret__, 'bds_instance_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        node_backup_configurations=pulumi.get(__ret__, 'node_backup_configurations'),
        state=pulumi.get(__ret__, 'state'))
def get_bds_instance_node_backup_configurations_output(bds_instance_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                       display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                       filters: Optional[pulumi.Input[Optional[Sequence[Union['GetBdsInstanceNodeBackupConfigurationsFilterArgs', 'GetBdsInstanceNodeBackupConfigurationsFilterArgsDict']]]]] = None,
                                                       state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetBdsInstanceNodeBackupConfigurationsResult]:
    """
    This data source provides the list of Bds Instance Node Backup Configurations in Oracle Cloud Infrastructure Big Data Service service.

    Returns information about the NodeBackupConfigurations.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_bds_instance_node_backup_configurations = oci.BigDataService.get_bds_instance_node_backup_configurations(bds_instance_id=test_bds_instance["id"],
        display_name=bds_instance_node_backup_configuration_display_name,
        state=bds_instance_node_backup_configuration_state)
    ```


    :param _builtins.str bds_instance_id: The OCID of the cluster.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str state: The state of the NodeBackupConfiguration configuration.
    """
    __args__ = dict()
    __args__['bdsInstanceId'] = bds_instance_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:BigDataService/getBdsInstanceNodeBackupConfigurations:getBdsInstanceNodeBackupConfigurations', __args__, opts=opts, typ=GetBdsInstanceNodeBackupConfigurationsResult)
    return __ret__.apply(lambda __response__: GetBdsInstanceNodeBackupConfigurationsResult(
        bds_instance_id=pulumi.get(__response__, 'bds_instance_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        node_backup_configurations=pulumi.get(__response__, 'node_backup_configurations'),
        state=pulumi.get(__response__, 'state')))
