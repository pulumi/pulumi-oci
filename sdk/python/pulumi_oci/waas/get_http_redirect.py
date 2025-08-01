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
    'GetHttpRedirectResult',
    'AwaitableGetHttpRedirectResult',
    'get_http_redirect',
    'get_http_redirect_output',
]

@pulumi.output_type
class GetHttpRedirectResult:
    """
    A collection of values returned by getHttpRedirect.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, display_name=None, domain=None, freeform_tags=None, http_redirect_id=None, id=None, response_code=None, state=None, targets=None, time_created=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if domain and not isinstance(domain, str):
            raise TypeError("Expected argument 'domain' to be a str")
        pulumi.set(__self__, "domain", domain)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if http_redirect_id and not isinstance(http_redirect_id, str):
            raise TypeError("Expected argument 'http_redirect_id' to be a str")
        pulumi.set(__self__, "http_redirect_id", http_redirect_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if response_code and not isinstance(response_code, int):
            raise TypeError("Expected argument 'response_code' to be a int")
        pulumi.set(__self__, "response_code", response_code)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if targets and not isinstance(targets, list):
            raise TypeError("Expected argument 'targets' to be a list")
        pulumi.set(__self__, "targets", targets)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirect's compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        The user-friendly name of the HTTP Redirect. The name can be changed and does not need to be unique.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def domain(self) -> _builtins.str:
        """
        The domain from which traffic will be redirected.
        """
        return pulumi.get(self, "domain")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="httpRedirectId")
    def http_redirect_id(self) -> _builtins.str:
        return pulumi.get(self, "http_redirect_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirect.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="responseCode")
    def response_code(self) -> _builtins.int:
        """
        The response code returned for the redirect to the client. For more information, see [RFC 7231](https://tools.ietf.org/html/rfc7231#section-6.4).
        """
        return pulumi.get(self, "response_code")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current lifecycle state of the HTTP Redirect.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter
    def targets(self) -> Sequence['outputs.GetHttpRedirectTargetResult']:
        """
        The redirect target object including all the redirect data.
        """
        return pulumi.get(self, "targets")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the policy was created, expressed in RFC 3339 timestamp format.
        """
        return pulumi.get(self, "time_created")


class AwaitableGetHttpRedirectResult(GetHttpRedirectResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetHttpRedirectResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            domain=self.domain,
            freeform_tags=self.freeform_tags,
            http_redirect_id=self.http_redirect_id,
            id=self.id,
            response_code=self.response_code,
            state=self.state,
            targets=self.targets,
            time_created=self.time_created)


def get_http_redirect(http_redirect_id: Optional[_builtins.str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetHttpRedirectResult:
    """
    This data source provides details about a specific Http Redirect resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.

    Gets the details of a HTTP Redirect.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_http_redirect = oci.Waas.get_http_redirect(http_redirect_id=test_http_redirect_oci_waas_http_redirect["id"])
    ```


    :param _builtins.str http_redirect_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirect.
    """
    __args__ = dict()
    __args__['httpRedirectId'] = http_redirect_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Waas/getHttpRedirect:getHttpRedirect', __args__, opts=opts, typ=GetHttpRedirectResult).value

    return AwaitableGetHttpRedirectResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        domain=pulumi.get(__ret__, 'domain'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        http_redirect_id=pulumi.get(__ret__, 'http_redirect_id'),
        id=pulumi.get(__ret__, 'id'),
        response_code=pulumi.get(__ret__, 'response_code'),
        state=pulumi.get(__ret__, 'state'),
        targets=pulumi.get(__ret__, 'targets'),
        time_created=pulumi.get(__ret__, 'time_created'))
def get_http_redirect_output(http_redirect_id: Optional[pulumi.Input[_builtins.str]] = None,
                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetHttpRedirectResult]:
    """
    This data source provides details about a specific Http Redirect resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.

    Gets the details of a HTTP Redirect.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_http_redirect = oci.Waas.get_http_redirect(http_redirect_id=test_http_redirect_oci_waas_http_redirect["id"])
    ```


    :param _builtins.str http_redirect_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirect.
    """
    __args__ = dict()
    __args__['httpRedirectId'] = http_redirect_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Waas/getHttpRedirect:getHttpRedirect', __args__, opts=opts, typ=GetHttpRedirectResult)
    return __ret__.apply(lambda __response__: GetHttpRedirectResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        domain=pulumi.get(__response__, 'domain'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        http_redirect_id=pulumi.get(__response__, 'http_redirect_id'),
        id=pulumi.get(__response__, 'id'),
        response_code=pulumi.get(__response__, 'response_code'),
        state=pulumi.get(__response__, 'state'),
        targets=pulumi.get(__response__, 'targets'),
        time_created=pulumi.get(__response__, 'time_created')))
