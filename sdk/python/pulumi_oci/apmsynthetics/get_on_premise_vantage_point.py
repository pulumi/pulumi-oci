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
    'GetOnPremiseVantagePointResult',
    'AwaitableGetOnPremiseVantagePointResult',
    'get_on_premise_vantage_point',
    'get_on_premise_vantage_point_output',
]

@pulumi.output_type
class GetOnPremiseVantagePointResult:
    """
    A collection of values returned by getOnPremiseVantagePoint.
    """
    def __init__(__self__, apm_domain_id=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, name=None, on_premise_vantage_point_id=None, time_created=None, time_updated=None, type=None, workers_summaries=None):
        if apm_domain_id and not isinstance(apm_domain_id, str):
            raise TypeError("Expected argument 'apm_domain_id' to be a str")
        pulumi.set(__self__, "apm_domain_id", apm_domain_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if on_premise_vantage_point_id and not isinstance(on_premise_vantage_point_id, str):
            raise TypeError("Expected argument 'on_premise_vantage_point_id' to be a str")
        pulumi.set(__self__, "on_premise_vantage_point_id", on_premise_vantage_point_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)
        if workers_summaries and not isinstance(workers_summaries, list):
            raise TypeError("Expected argument 'workers_summaries' to be a list")
        pulumi.set(__self__, "workers_summaries", workers_summaries)

    @_builtins.property
    @pulumi.getter(name="apmDomainId")
    def apm_domain_id(self) -> _builtins.str:
        return pulumi.get(self, "apm_domain_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        A short description about the On-premise vantage point.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        Unique permanent name of the On-premise vantage point.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the On-premise vantage point.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        Unique On-premise vantage point name that cannot be edited. The name should not contain any confidential information.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="onPremiseVantagePointId")
    def on_premise_vantage_point_id(self) -> _builtins.str:
        return pulumi.get(self, "on_premise_vantage_point_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
        """
        return pulumi.get(self, "time_updated")

    @_builtins.property
    @pulumi.getter
    def type(self) -> _builtins.str:
        """
        Type of On-premise vantage point.
        """
        return pulumi.get(self, "type")

    @_builtins.property
    @pulumi.getter(name="workersSummaries")
    def workers_summaries(self) -> Sequence['outputs.GetOnPremiseVantagePointWorkersSummaryResult']:
        """
        Details of the workers in a specific On-premise vantage point.
        """
        return pulumi.get(self, "workers_summaries")


class AwaitableGetOnPremiseVantagePointResult(GetOnPremiseVantagePointResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetOnPremiseVantagePointResult(
            apm_domain_id=self.apm_domain_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            name=self.name,
            on_premise_vantage_point_id=self.on_premise_vantage_point_id,
            time_created=self.time_created,
            time_updated=self.time_updated,
            type=self.type,
            workers_summaries=self.workers_summaries)


def get_on_premise_vantage_point(apm_domain_id: Optional[_builtins.str] = None,
                                 on_premise_vantage_point_id: Optional[_builtins.str] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetOnPremiseVantagePointResult:
    """
    This data source provides details about a specific On Premise Vantage Point resource in Oracle Cloud Infrastructure APM Availability Monitoring service (aka APM Synthetics Service).

    Gets the details of the On-premise vantage point identified by the OCID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_on_premise_vantage_point = oci.ApmSynthetics.get_on_premise_vantage_point(apm_domain_id=test_apm_domain["id"],
        on_premise_vantage_point_id=test_on_premise_vantage_point_oci_apm_synthetics_on_premise_vantage_point["id"])
    ```


    :param _builtins.str apm_domain_id: The APM domain ID the request is intended for.
    :param _builtins.str on_premise_vantage_point_id: The OCID of the On-premise vantage point.
    """
    __args__ = dict()
    __args__['apmDomainId'] = apm_domain_id
    __args__['onPremiseVantagePointId'] = on_premise_vantage_point_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ApmSynthetics/getOnPremiseVantagePoint:getOnPremiseVantagePoint', __args__, opts=opts, typ=GetOnPremiseVantagePointResult).value

    return AwaitableGetOnPremiseVantagePointResult(
        apm_domain_id=pulumi.get(__ret__, 'apm_domain_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        on_premise_vantage_point_id=pulumi.get(__ret__, 'on_premise_vantage_point_id'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'),
        type=pulumi.get(__ret__, 'type'),
        workers_summaries=pulumi.get(__ret__, 'workers_summaries'))
def get_on_premise_vantage_point_output(apm_domain_id: Optional[pulumi.Input[_builtins.str]] = None,
                                        on_premise_vantage_point_id: Optional[pulumi.Input[_builtins.str]] = None,
                                        opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetOnPremiseVantagePointResult]:
    """
    This data source provides details about a specific On Premise Vantage Point resource in Oracle Cloud Infrastructure APM Availability Monitoring service (aka APM Synthetics Service).

    Gets the details of the On-premise vantage point identified by the OCID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_on_premise_vantage_point = oci.ApmSynthetics.get_on_premise_vantage_point(apm_domain_id=test_apm_domain["id"],
        on_premise_vantage_point_id=test_on_premise_vantage_point_oci_apm_synthetics_on_premise_vantage_point["id"])
    ```


    :param _builtins.str apm_domain_id: The APM domain ID the request is intended for.
    :param _builtins.str on_premise_vantage_point_id: The OCID of the On-premise vantage point.
    """
    __args__ = dict()
    __args__['apmDomainId'] = apm_domain_id
    __args__['onPremiseVantagePointId'] = on_premise_vantage_point_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:ApmSynthetics/getOnPremiseVantagePoint:getOnPremiseVantagePoint', __args__, opts=opts, typ=GetOnPremiseVantagePointResult)
    return __ret__.apply(lambda __response__: GetOnPremiseVantagePointResult(
        apm_domain_id=pulumi.get(__response__, 'apm_domain_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        on_premise_vantage_point_id=pulumi.get(__response__, 'on_premise_vantage_point_id'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated'),
        type=pulumi.get(__response__, 'type'),
        workers_summaries=pulumi.get(__response__, 'workers_summaries')))
