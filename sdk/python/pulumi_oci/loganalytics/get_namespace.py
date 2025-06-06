# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins
import copy
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

__all__ = [
    'GetNamespaceResult',
    'AwaitableGetNamespaceResult',
    'get_namespace',
    'get_namespace_output',
]

@pulumi.output_type
class GetNamespaceResult:
    """
    A collection of values returned by getNamespace.
    """
    def __init__(__self__, compartment_id=None, id=None, is_archiving_enabled=None, is_data_ever_ingested=None, is_logset_enabled=None, is_onboarded=None, namespace=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_archiving_enabled and not isinstance(is_archiving_enabled, bool):
            raise TypeError("Expected argument 'is_archiving_enabled' to be a bool")
        pulumi.set(__self__, "is_archiving_enabled", is_archiving_enabled)
        if is_data_ever_ingested and not isinstance(is_data_ever_ingested, bool):
            raise TypeError("Expected argument 'is_data_ever_ingested' to be a bool")
        pulumi.set(__self__, "is_data_ever_ingested", is_data_ever_ingested)
        if is_logset_enabled and not isinstance(is_logset_enabled, bool):
            raise TypeError("Expected argument 'is_logset_enabled' to be a bool")
        pulumi.set(__self__, "is_logset_enabled", is_logset_enabled)
        if is_onboarded and not isinstance(is_onboarded, bool):
            raise TypeError("Expected argument 'is_onboarded' to be a bool")
        pulumi.set(__self__, "is_onboarded", is_onboarded)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> builtins.str:
        """
        The is the tenancy ID
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def id(self) -> builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isArchivingEnabled")
    def is_archiving_enabled(self) -> builtins.bool:
        """
        This indicates if old data can be archived for a tenancy
        """
        return pulumi.get(self, "is_archiving_enabled")

    @property
    @pulumi.getter(name="isDataEverIngested")
    def is_data_ever_ingested(self) -> builtins.bool:
        """
        This indicates if the tenancy is data ever ingested
        """
        return pulumi.get(self, "is_data_ever_ingested")

    @property
    @pulumi.getter(name="isLogsetEnabled")
    def is_logset_enabled(self) -> builtins.bool:
        return pulumi.get(self, "is_logset_enabled")

    @property
    @pulumi.getter(name="isOnboarded")
    def is_onboarded(self) -> builtins.bool:
        """
        This indicates if the tenancy is onboarded to Logging Analytics
        """
        return pulumi.get(self, "is_onboarded")

    @property
    @pulumi.getter
    def namespace(self) -> builtins.str:
        """
        This is the namespace name of a tenancy
        * `is_logSet_enabled` - This indicates if the tenancy is logSet enable
        """
        return pulumi.get(self, "namespace")


class AwaitableGetNamespaceResult(GetNamespaceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNamespaceResult(
            compartment_id=self.compartment_id,
            id=self.id,
            is_archiving_enabled=self.is_archiving_enabled,
            is_data_ever_ingested=self.is_data_ever_ingested,
            is_logset_enabled=self.is_logset_enabled,
            is_onboarded=self.is_onboarded,
            namespace=self.namespace)


def get_namespace(namespace: Optional[builtins.str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNamespaceResult:
    """
    This data source provides details about a specific Namespace resource in Oracle Cloud Infrastructure Log Analytics service.

    This API gets the namespace details of a tenancy already onboarded in Logging Analytics Application

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_namespace = oci.LogAnalytics.get_namespace(namespace=namespace_namespace)
    ```


    :param builtins.str namespace: The Logging Analytics namespace used for the request.
    """
    __args__ = dict()
    __args__['namespace'] = namespace
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:LogAnalytics/getNamespace:getNamespace', __args__, opts=opts, typ=GetNamespaceResult).value

    return AwaitableGetNamespaceResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        id=pulumi.get(__ret__, 'id'),
        is_archiving_enabled=pulumi.get(__ret__, 'is_archiving_enabled'),
        is_data_ever_ingested=pulumi.get(__ret__, 'is_data_ever_ingested'),
        is_logset_enabled=pulumi.get(__ret__, 'is_logset_enabled'),
        is_onboarded=pulumi.get(__ret__, 'is_onboarded'),
        namespace=pulumi.get(__ret__, 'namespace'))
def get_namespace_output(namespace: Optional[pulumi.Input[builtins.str]] = None,
                         opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNamespaceResult]:
    """
    This data source provides details about a specific Namespace resource in Oracle Cloud Infrastructure Log Analytics service.

    This API gets the namespace details of a tenancy already onboarded in Logging Analytics Application

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_namespace = oci.LogAnalytics.get_namespace(namespace=namespace_namespace)
    ```


    :param builtins.str namespace: The Logging Analytics namespace used for the request.
    """
    __args__ = dict()
    __args__['namespace'] = namespace
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:LogAnalytics/getNamespace:getNamespace', __args__, opts=opts, typ=GetNamespaceResult)
    return __ret__.apply(lambda __response__: GetNamespaceResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        id=pulumi.get(__response__, 'id'),
        is_archiving_enabled=pulumi.get(__response__, 'is_archiving_enabled'),
        is_data_ever_ingested=pulumi.get(__response__, 'is_data_ever_ingested'),
        is_logset_enabled=pulumi.get(__response__, 'is_logset_enabled'),
        is_onboarded=pulumi.get(__response__, 'is_onboarded'),
        namespace=pulumi.get(__response__, 'namespace')))
