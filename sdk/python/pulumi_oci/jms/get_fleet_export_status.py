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
    'GetFleetExportStatusResult',
    'AwaitableGetFleetExportStatusResult',
    'get_fleet_export_status',
    'get_fleet_export_status_output',
]

@pulumi.output_type
class GetFleetExportStatusResult:
    """
    A collection of values returned by getFleetExportStatus.
    """
    def __init__(__self__, fleet_id=None, id=None, latest_run_status=None, time_last_run=None, time_next_run=None):
        if fleet_id and not isinstance(fleet_id, str):
            raise TypeError("Expected argument 'fleet_id' to be a str")
        pulumi.set(__self__, "fleet_id", fleet_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if latest_run_status and not isinstance(latest_run_status, str):
            raise TypeError("Expected argument 'latest_run_status' to be a str")
        pulumi.set(__self__, "latest_run_status", latest_run_status)
        if time_last_run and not isinstance(time_last_run, str):
            raise TypeError("Expected argument 'time_last_run' to be a str")
        pulumi.set(__self__, "time_last_run", time_last_run)
        if time_next_run and not isinstance(time_next_run, str):
            raise TypeError("Expected argument 'time_next_run' to be a str")
        pulumi.set(__self__, "time_next_run", time_next_run)

    @_builtins.property
    @pulumi.getter(name="fleetId")
    def fleet_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet.
        """
        return pulumi.get(self, "fleet_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="latestRunStatus")
    def latest_run_status(self) -> _builtins.str:
        """
        The status of the latest export run.
        """
        return pulumi.get(self, "latest_run_status")

    @_builtins.property
    @pulumi.getter(name="timeLastRun")
    def time_last_run(self) -> _builtins.str:
        """
        The date and time of the last export run.
        """
        return pulumi.get(self, "time_last_run")

    @_builtins.property
    @pulumi.getter(name="timeNextRun")
    def time_next_run(self) -> _builtins.str:
        """
        The date and time of the next export run.
        """
        return pulumi.get(self, "time_next_run")


class AwaitableGetFleetExportStatusResult(GetFleetExportStatusResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFleetExportStatusResult(
            fleet_id=self.fleet_id,
            id=self.id,
            latest_run_status=self.latest_run_status,
            time_last_run=self.time_last_run,
            time_next_run=self.time_next_run)


def get_fleet_export_status(fleet_id: Optional[_builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFleetExportStatusResult:
    """
    This data source provides details about a specific Fleet Export Status resource in Oracle Cloud Infrastructure Jms service.

    Returns last export status for the specified fleet.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fleet_export_status = oci.Jms.get_fleet_export_status(fleet_id=test_fleet["id"])
    ```


    :param _builtins.str fleet_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
    """
    __args__ = dict()
    __args__['fleetId'] = fleet_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Jms/getFleetExportStatus:getFleetExportStatus', __args__, opts=opts, typ=GetFleetExportStatusResult).value

    return AwaitableGetFleetExportStatusResult(
        fleet_id=pulumi.get(__ret__, 'fleet_id'),
        id=pulumi.get(__ret__, 'id'),
        latest_run_status=pulumi.get(__ret__, 'latest_run_status'),
        time_last_run=pulumi.get(__ret__, 'time_last_run'),
        time_next_run=pulumi.get(__ret__, 'time_next_run'))
def get_fleet_export_status_output(fleet_id: Optional[pulumi.Input[_builtins.str]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetFleetExportStatusResult]:
    """
    This data source provides details about a specific Fleet Export Status resource in Oracle Cloud Infrastructure Jms service.

    Returns last export status for the specified fleet.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fleet_export_status = oci.Jms.get_fleet_export_status(fleet_id=test_fleet["id"])
    ```


    :param _builtins.str fleet_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
    """
    __args__ = dict()
    __args__['fleetId'] = fleet_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Jms/getFleetExportStatus:getFleetExportStatus', __args__, opts=opts, typ=GetFleetExportStatusResult)
    return __ret__.apply(lambda __response__: GetFleetExportStatusResult(
        fleet_id=pulumi.get(__response__, 'fleet_id'),
        id=pulumi.get(__response__, 'id'),
        latest_run_status=pulumi.get(__response__, 'latest_run_status'),
        time_last_run=pulumi.get(__response__, 'time_last_run'),
        time_next_run=pulumi.get(__response__, 'time_next_run')))
