# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetConfigsResult',
    'AwaitableGetConfigsResult',
    'get_configs',
    'get_configs_output',
]

@pulumi.output_type
class GetConfigsResult:
    """
    A collection of values returned by getConfigs.
    """
    def __init__(__self__, apm_domain_id=None, config_collections=None, config_type=None, display_name=None, filters=None, id=None):
        if apm_domain_id and not isinstance(apm_domain_id, str):
            raise TypeError("Expected argument 'apm_domain_id' to be a str")
        pulumi.set(__self__, "apm_domain_id", apm_domain_id)
        if config_collections and not isinstance(config_collections, list):
            raise TypeError("Expected argument 'config_collections' to be a list")
        pulumi.set(__self__, "config_collections", config_collections)
        if config_type and not isinstance(config_type, str):
            raise TypeError("Expected argument 'config_type' to be a str")
        pulumi.set(__self__, "config_type", config_type)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter(name="apmDomainId")
    def apm_domain_id(self) -> str:
        return pulumi.get(self, "apm_domain_id")

    @property
    @pulumi.getter(name="configCollections")
    def config_collections(self) -> Sequence['outputs.GetConfigsConfigCollectionResult']:
        """
        The list of config_collection.
        """
        return pulumi.get(self, "config_collections")

    @property
    @pulumi.getter(name="configType")
    def config_type(self) -> Optional[str]:
        """
        The type of configuration item
        """
        return pulumi.get(self, "config_type")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly name that provides a short description this rule.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetConfigsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetConfigsResult(GetConfigsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetConfigsResult(
            apm_domain_id=self.apm_domain_id,
            config_collections=self.config_collections,
            config_type=self.config_type,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id)


def get_configs(apm_domain_id: Optional[str] = None,
                config_type: Optional[str] = None,
                display_name: Optional[str] = None,
                filters: Optional[Sequence[pulumi.InputType['GetConfigsFilterArgs']]] = None,
                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetConfigsResult:
    """
    This data source provides the list of Configs in Oracle Cloud Infrastructure Apm Config service.

    Returns all configured items optionally filtered by configuration type

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_configs = oci.ApmConfig.get_configs(apm_domain_id=oci_apm_apm_domain["test_apm_domain"]["id"],
        config_type=var["config_config_type"],
        display_name=var["config_display_name"])
    ```


    :param str apm_domain_id: The APM Domain Id the request is intended for.
    :param str config_type: A filter to match only configuration items of the given type. Supported values are SPAN_FILTER, METRIC_GROUP, and APDEX.
    :param str display_name: A filter to return only resources that match the entire display name given.
    """
    __args__ = dict()
    __args__['apmDomainId'] = apm_domain_id
    __args__['configType'] = config_type
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:ApmConfig/getConfigs:getConfigs', __args__, opts=opts, typ=GetConfigsResult).value

    return AwaitableGetConfigsResult(
        apm_domain_id=__ret__.apm_domain_id,
        config_collections=__ret__.config_collections,
        config_type=__ret__.config_type,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id)


@_utilities.lift_output_func(get_configs)
def get_configs_output(apm_domain_id: Optional[pulumi.Input[str]] = None,
                       config_type: Optional[pulumi.Input[Optional[str]]] = None,
                       display_name: Optional[pulumi.Input[Optional[str]]] = None,
                       filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetConfigsFilterArgs']]]]] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetConfigsResult]:
    """
    This data source provides the list of Configs in Oracle Cloud Infrastructure Apm Config service.

    Returns all configured items optionally filtered by configuration type

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_configs = oci.ApmConfig.get_configs(apm_domain_id=oci_apm_apm_domain["test_apm_domain"]["id"],
        config_type=var["config_config_type"],
        display_name=var["config_display_name"])
    ```


    :param str apm_domain_id: The APM Domain Id the request is intended for.
    :param str config_type: A filter to match only configuration items of the given type. Supported values are SPAN_FILTER, METRIC_GROUP, and APDEX.
    :param str display_name: A filter to return only resources that match the entire display name given.
    """
    ...
