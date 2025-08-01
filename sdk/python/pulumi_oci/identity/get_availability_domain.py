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

__all__ = [
    'GetAvailabilityDomainResult',
    'AwaitableGetAvailabilityDomainResult',
    'get_availability_domain',
    'get_availability_domain_output',
]

@pulumi.output_type
class GetAvailabilityDomainResult:
    """
    A collection of values returned by getAvailabilityDomain.
    """
    def __init__(__self__, ad_number=None, compartment_id=None, id=None, name=None):
        if ad_number and not isinstance(ad_number, int):
            raise TypeError("Expected argument 'ad_number' to be a int")
        pulumi.set(__self__, "ad_number", ad_number)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)

    @_builtins.property
    @pulumi.getter(name="adNumber")
    def ad_number(self) -> _builtins.int:
        """
        The number of the Availability Domain. For example, the `ad_number` for YXol:US-ASHBURN-AD-1 would be "1"
        """
        return pulumi.get(self, "ad_number")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the tenancy.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The OCID of the Availability Domain.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the Availability Domain.
        """
        return pulumi.get(self, "name")


class AwaitableGetAvailabilityDomainResult(GetAvailabilityDomainResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAvailabilityDomainResult(
            ad_number=self.ad_number,
            compartment_id=self.compartment_id,
            id=self.id,
            name=self.name)


def get_availability_domain(ad_number: Optional[_builtins.int] = None,
                            compartment_id: Optional[_builtins.str] = None,
                            id: Optional[_builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAvailabilityDomainResult:
    """
    This data source provides the details of a single Availability Domain in Oracle Cloud Infrastructure Identity service.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compartment = oci.Identity.get_availability_domain(compartment_id=tenancy_ocid,
        id=id,
        ad_number=ad_number)
    ```


    :param _builtins.int ad_number: The number of the Availability Domain. Required if `id` is not specified. This number corresponds to the integer in the Availability Domain `name`.
    :param _builtins.str compartment_id: The OCID of the tenancy.
    :param _builtins.str id: The OCID of the Availability Domain. Required if `ad_number` is not specified.
    """
    __args__ = dict()
    __args__['adNumber'] = ad_number
    __args__['compartmentId'] = compartment_id
    __args__['id'] = id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getAvailabilityDomain:getAvailabilityDomain', __args__, opts=opts, typ=GetAvailabilityDomainResult).value

    return AwaitableGetAvailabilityDomainResult(
        ad_number=pulumi.get(__ret__, 'ad_number'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'))
def get_availability_domain_output(ad_number: Optional[pulumi.Input[Optional[_builtins.int]]] = None,
                                   compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                   id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetAvailabilityDomainResult]:
    """
    This data source provides the details of a single Availability Domain in Oracle Cloud Infrastructure Identity service.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compartment = oci.Identity.get_availability_domain(compartment_id=tenancy_ocid,
        id=id,
        ad_number=ad_number)
    ```


    :param _builtins.int ad_number: The number of the Availability Domain. Required if `id` is not specified. This number corresponds to the integer in the Availability Domain `name`.
    :param _builtins.str compartment_id: The OCID of the tenancy.
    :param _builtins.str id: The OCID of the Availability Domain. Required if `ad_number` is not specified.
    """
    __args__ = dict()
    __args__['adNumber'] = ad_number
    __args__['compartmentId'] = compartment_id
    __args__['id'] = id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Identity/getAvailabilityDomain:getAvailabilityDomain', __args__, opts=opts, typ=GetAvailabilityDomainResult)
    return __ret__.apply(lambda __response__: GetAvailabilityDomainResult(
        ad_number=pulumi.get(__response__, 'ad_number'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name')))
