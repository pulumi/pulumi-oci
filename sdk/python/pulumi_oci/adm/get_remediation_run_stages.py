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
    'GetRemediationRunStagesResult',
    'AwaitableGetRemediationRunStagesResult',
    'get_remediation_run_stages',
    'get_remediation_run_stages_output',
]

@pulumi.output_type
class GetRemediationRunStagesResult:
    """
    A collection of values returned by getRemediationRunStages.
    """
    def __init__(__self__, filters=None, id=None, remediation_run_id=None, remediation_run_stage_collections=None, status=None, type=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if remediation_run_id and not isinstance(remediation_run_id, str):
            raise TypeError("Expected argument 'remediation_run_id' to be a str")
        pulumi.set(__self__, "remediation_run_id", remediation_run_id)
        if remediation_run_stage_collections and not isinstance(remediation_run_stage_collections, list):
            raise TypeError("Expected argument 'remediation_run_stage_collections' to be a list")
        pulumi.set(__self__, "remediation_run_stage_collections", remediation_run_stage_collections)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetRemediationRunStagesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="remediationRunId")
    def remediation_run_id(self) -> _builtins.str:
        """
        The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
        """
        return pulumi.get(self, "remediation_run_id")

    @_builtins.property
    @pulumi.getter(name="remediationRunStageCollections")
    def remediation_run_stage_collections(self) -> Sequence['outputs.GetRemediationRunStagesRemediationRunStageCollectionResult']:
        """
        The list of remediation_run_stage_collection.
        """
        return pulumi.get(self, "remediation_run_stage_collections")

    @_builtins.property
    @pulumi.getter
    def status(self) -> Optional[_builtins.str]:
        """
        The current status of a remediation run stage.
        """
        return pulumi.get(self, "status")

    @_builtins.property
    @pulumi.getter
    def type(self) -> Optional[_builtins.str]:
        """
        The type of the remediation run stage.
        """
        return pulumi.get(self, "type")


class AwaitableGetRemediationRunStagesResult(GetRemediationRunStagesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRemediationRunStagesResult(
            filters=self.filters,
            id=self.id,
            remediation_run_id=self.remediation_run_id,
            remediation_run_stage_collections=self.remediation_run_stage_collections,
            status=self.status,
            type=self.type)


def get_remediation_run_stages(filters: Optional[Sequence[Union['GetRemediationRunStagesFilterArgs', 'GetRemediationRunStagesFilterArgsDict']]] = None,
                               remediation_run_id: Optional[_builtins.str] = None,
                               status: Optional[_builtins.str] = None,
                               type: Optional[_builtins.str] = None,
                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRemediationRunStagesResult:
    """
    This data source provides the list of Remediation Run Stages in Oracle Cloud Infrastructure Adm service.

    Returns a list of Remediation Run Stages based on the specified query parameters and Remediation Run identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_remediation_run_stages = oci.Adm.get_remediation_run_stages(remediation_run_id=test_remediation_run["id"],
        status=remediation_run_stage_status,
        type=remediation_run_stage_type)
    ```


    :param _builtins.str remediation_run_id: Unique Remediation Run identifier path parameter.
    :param _builtins.str status: A filter to return only Stages that match the specified status.
    :param _builtins.str type: A filter to return only Stages that match the specified type.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['remediationRunId'] = remediation_run_id
    __args__['status'] = status
    __args__['type'] = type
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Adm/getRemediationRunStages:getRemediationRunStages', __args__, opts=opts, typ=GetRemediationRunStagesResult).value

    return AwaitableGetRemediationRunStagesResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        remediation_run_id=pulumi.get(__ret__, 'remediation_run_id'),
        remediation_run_stage_collections=pulumi.get(__ret__, 'remediation_run_stage_collections'),
        status=pulumi.get(__ret__, 'status'),
        type=pulumi.get(__ret__, 'type'))
def get_remediation_run_stages_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetRemediationRunStagesFilterArgs', 'GetRemediationRunStagesFilterArgsDict']]]]] = None,
                                      remediation_run_id: Optional[pulumi.Input[_builtins.str]] = None,
                                      status: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                      type: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                      opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetRemediationRunStagesResult]:
    """
    This data source provides the list of Remediation Run Stages in Oracle Cloud Infrastructure Adm service.

    Returns a list of Remediation Run Stages based on the specified query parameters and Remediation Run identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_remediation_run_stages = oci.Adm.get_remediation_run_stages(remediation_run_id=test_remediation_run["id"],
        status=remediation_run_stage_status,
        type=remediation_run_stage_type)
    ```


    :param _builtins.str remediation_run_id: Unique Remediation Run identifier path parameter.
    :param _builtins.str status: A filter to return only Stages that match the specified status.
    :param _builtins.str type: A filter to return only Stages that match the specified type.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['remediationRunId'] = remediation_run_id
    __args__['status'] = status
    __args__['type'] = type
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Adm/getRemediationRunStages:getRemediationRunStages', __args__, opts=opts, typ=GetRemediationRunStagesResult)
    return __ret__.apply(lambda __response__: GetRemediationRunStagesResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        remediation_run_id=pulumi.get(__response__, 'remediation_run_id'),
        remediation_run_stage_collections=pulumi.get(__response__, 'remediation_run_stage_collections'),
        status=pulumi.get(__response__, 'status'),
        type=pulumi.get(__response__, 'type')))
