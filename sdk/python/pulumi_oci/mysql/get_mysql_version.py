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
    'GetMysqlVersionResult',
    'AwaitableGetMysqlVersionResult',
    'get_mysql_version',
    'get_mysql_version_output',
]

@pulumi.output_type
class GetMysqlVersionResult:
    """
    A collection of values returned by getMysqlVersion.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, versions=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if versions and not isinstance(versions, list):
            raise TypeError("Expected argument 'versions' to be a list")
        pulumi.set(__self__, "versions", versions)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetMysqlVersionFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def versions(self) -> Sequence['outputs.GetMysqlVersionVersionResult']:
        """
        The list of supported MySQL Versions.
        """
        return pulumi.get(self, "versions")


class AwaitableGetMysqlVersionResult(GetMysqlVersionResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMysqlVersionResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            versions=self.versions)


def get_mysql_version(compartment_id: Optional[_builtins.str] = None,
                      filters: Optional[Sequence[Union['GetMysqlVersionFilterArgs', 'GetMysqlVersionFilterArgsDict']]] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMysqlVersionResult:
    """
    This data source provides the list of Mysql Versions in Oracle Cloud Infrastructure MySQL Database service.

    Get a list of supported and available MySQL database major versions.

    The list is sorted by version family.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_mysql_versions = oci.Mysql.get_mysql_version(compartment_id=compartment_id)
    ```


    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Mysql/getMysqlVersion:getMysqlVersion', __args__, opts=opts, typ=GetMysqlVersionResult).value

    return AwaitableGetMysqlVersionResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        versions=pulumi.get(__ret__, 'versions'))
def get_mysql_version_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                             filters: Optional[pulumi.Input[Optional[Sequence[Union['GetMysqlVersionFilterArgs', 'GetMysqlVersionFilterArgsDict']]]]] = None,
                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetMysqlVersionResult]:
    """
    This data source provides the list of Mysql Versions in Oracle Cloud Infrastructure MySQL Database service.

    Get a list of supported and available MySQL database major versions.

    The list is sorted by version family.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_mysql_versions = oci.Mysql.get_mysql_version(compartment_id=compartment_id)
    ```


    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Mysql/getMysqlVersion:getMysqlVersion', __args__, opts=opts, typ=GetMysqlVersionResult)
    return __ret__.apply(lambda __response__: GetMysqlVersionResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        versions=pulumi.get(__response__, 'versions')))
