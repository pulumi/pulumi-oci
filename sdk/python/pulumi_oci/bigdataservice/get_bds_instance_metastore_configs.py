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
    'GetBdsInstanceMetastoreConfigsResult',
    'AwaitableGetBdsInstanceMetastoreConfigsResult',
    'get_bds_instance_metastore_configs',
    'get_bds_instance_metastore_configs_output',
]

@pulumi.output_type
class GetBdsInstanceMetastoreConfigsResult:
    """
    A collection of values returned by getBdsInstanceMetastoreConfigs.
    """
    def __init__(__self__, bds_api_key_id=None, bds_instance_id=None, bds_metastore_configurations=None, display_name=None, filters=None, id=None, metastore_id=None, metastore_type=None, state=None):
        if bds_api_key_id and not isinstance(bds_api_key_id, str):
            raise TypeError("Expected argument 'bds_api_key_id' to be a str")
        pulumi.set(__self__, "bds_api_key_id", bds_api_key_id)
        if bds_instance_id and not isinstance(bds_instance_id, str):
            raise TypeError("Expected argument 'bds_instance_id' to be a str")
        pulumi.set(__self__, "bds_instance_id", bds_instance_id)
        if bds_metastore_configurations and not isinstance(bds_metastore_configurations, list):
            raise TypeError("Expected argument 'bds_metastore_configurations' to be a list")
        pulumi.set(__self__, "bds_metastore_configurations", bds_metastore_configurations)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if metastore_id and not isinstance(metastore_id, str):
            raise TypeError("Expected argument 'metastore_id' to be a str")
        pulumi.set(__self__, "metastore_id", metastore_id)
        if metastore_type and not isinstance(metastore_type, str):
            raise TypeError("Expected argument 'metastore_type' to be a str")
        pulumi.set(__self__, "metastore_type", metastore_type)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="bdsApiKeyId")
    def bds_api_key_id(self) -> Optional[_builtins.str]:
        """
        The ID of BDS API Key used for metastore configuration. Set only if metastore's type is EXTERNAL.
        """
        return pulumi.get(self, "bds_api_key_id")

    @_builtins.property
    @pulumi.getter(name="bdsInstanceId")
    def bds_instance_id(self) -> _builtins.str:
        return pulumi.get(self, "bds_instance_id")

    @_builtins.property
    @pulumi.getter(name="bdsMetastoreConfigurations")
    def bds_metastore_configurations(self) -> Sequence['outputs.GetBdsInstanceMetastoreConfigsBdsMetastoreConfigurationResult']:
        """
        The list of bds_metastore_configurations.
        """
        return pulumi.get(self, "bds_metastore_configurations")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The display name of metastore configuration
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetBdsInstanceMetastoreConfigsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="metastoreId")
    def metastore_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the Data Catalog metastore. Set only if metastore's type is EXTERNAL.
        """
        return pulumi.get(self, "metastore_id")

    @_builtins.property
    @pulumi.getter(name="metastoreType")
    def metastore_type(self) -> Optional[_builtins.str]:
        """
        The type of the metastore in the metastore configuration.
        """
        return pulumi.get(self, "metastore_type")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        the lifecycle state of the metastore configuration.
        """
        return pulumi.get(self, "state")


class AwaitableGetBdsInstanceMetastoreConfigsResult(GetBdsInstanceMetastoreConfigsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetBdsInstanceMetastoreConfigsResult(
            bds_api_key_id=self.bds_api_key_id,
            bds_instance_id=self.bds_instance_id,
            bds_metastore_configurations=self.bds_metastore_configurations,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            metastore_id=self.metastore_id,
            metastore_type=self.metastore_type,
            state=self.state)


def get_bds_instance_metastore_configs(bds_api_key_id: Optional[_builtins.str] = None,
                                       bds_instance_id: Optional[_builtins.str] = None,
                                       display_name: Optional[_builtins.str] = None,
                                       filters: Optional[Sequence[Union['GetBdsInstanceMetastoreConfigsFilterArgs', 'GetBdsInstanceMetastoreConfigsFilterArgsDict']]] = None,
                                       metastore_id: Optional[_builtins.str] = None,
                                       metastore_type: Optional[_builtins.str] = None,
                                       state: Optional[_builtins.str] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetBdsInstanceMetastoreConfigsResult:
    """
    This data source provides the list of Bds Instance Metastore Configs in Oracle Cloud Infrastructure Big Data Service service.

    Returns a list of metastore configurations ssociated with this Big Data Service cluster.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_bds_instance_metastore_configs = oci.BigDataService.get_bds_instance_metastore_configs(bds_instance_id=test_bds_instance["id"],
        bds_api_key_id=test_api_key["id"],
        display_name=bds_instance_metastore_config_display_name,
        metastore_id=test_metastore["id"],
        metastore_type=bds_instance_metastore_config_metastore_type,
        state=bds_instance_metastore_config_state)
    ```


    :param _builtins.str bds_api_key_id: The ID of the API key that is associated with the external metastore in the metastore configuration
    :param _builtins.str bds_instance_id: The OCID of the cluster.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str metastore_id: The OCID of the Data Catalog metastore in the metastore configuration
    :param _builtins.str metastore_type: The type of the metastore in the metastore configuration
    :param _builtins.str state: The lifecycle state of the metastore in the metastore configuration
    """
    __args__ = dict()
    __args__['bdsApiKeyId'] = bds_api_key_id
    __args__['bdsInstanceId'] = bds_instance_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['metastoreId'] = metastore_id
    __args__['metastoreType'] = metastore_type
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:BigDataService/getBdsInstanceMetastoreConfigs:getBdsInstanceMetastoreConfigs', __args__, opts=opts, typ=GetBdsInstanceMetastoreConfigsResult).value

    return AwaitableGetBdsInstanceMetastoreConfigsResult(
        bds_api_key_id=pulumi.get(__ret__, 'bds_api_key_id'),
        bds_instance_id=pulumi.get(__ret__, 'bds_instance_id'),
        bds_metastore_configurations=pulumi.get(__ret__, 'bds_metastore_configurations'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        metastore_id=pulumi.get(__ret__, 'metastore_id'),
        metastore_type=pulumi.get(__ret__, 'metastore_type'),
        state=pulumi.get(__ret__, 'state'))
def get_bds_instance_metastore_configs_output(bds_api_key_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              bds_instance_id: Optional[pulumi.Input[_builtins.str]] = None,
                                              display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              filters: Optional[pulumi.Input[Optional[Sequence[Union['GetBdsInstanceMetastoreConfigsFilterArgs', 'GetBdsInstanceMetastoreConfigsFilterArgsDict']]]]] = None,
                                              metastore_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              metastore_type: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetBdsInstanceMetastoreConfigsResult]:
    """
    This data source provides the list of Bds Instance Metastore Configs in Oracle Cloud Infrastructure Big Data Service service.

    Returns a list of metastore configurations ssociated with this Big Data Service cluster.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_bds_instance_metastore_configs = oci.BigDataService.get_bds_instance_metastore_configs(bds_instance_id=test_bds_instance["id"],
        bds_api_key_id=test_api_key["id"],
        display_name=bds_instance_metastore_config_display_name,
        metastore_id=test_metastore["id"],
        metastore_type=bds_instance_metastore_config_metastore_type,
        state=bds_instance_metastore_config_state)
    ```


    :param _builtins.str bds_api_key_id: The ID of the API key that is associated with the external metastore in the metastore configuration
    :param _builtins.str bds_instance_id: The OCID of the cluster.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str metastore_id: The OCID of the Data Catalog metastore in the metastore configuration
    :param _builtins.str metastore_type: The type of the metastore in the metastore configuration
    :param _builtins.str state: The lifecycle state of the metastore in the metastore configuration
    """
    __args__ = dict()
    __args__['bdsApiKeyId'] = bds_api_key_id
    __args__['bdsInstanceId'] = bds_instance_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['metastoreId'] = metastore_id
    __args__['metastoreType'] = metastore_type
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:BigDataService/getBdsInstanceMetastoreConfigs:getBdsInstanceMetastoreConfigs', __args__, opts=opts, typ=GetBdsInstanceMetastoreConfigsResult)
    return __ret__.apply(lambda __response__: GetBdsInstanceMetastoreConfigsResult(
        bds_api_key_id=pulumi.get(__response__, 'bds_api_key_id'),
        bds_instance_id=pulumi.get(__response__, 'bds_instance_id'),
        bds_metastore_configurations=pulumi.get(__response__, 'bds_metastore_configurations'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        metastore_id=pulumi.get(__response__, 'metastore_id'),
        metastore_type=pulumi.get(__response__, 'metastore_type'),
        state=pulumi.get(__response__, 'state')))
