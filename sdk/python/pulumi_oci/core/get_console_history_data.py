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
    'GetConsoleHistoryDataResult',
    'AwaitableGetConsoleHistoryDataResult',
    'get_console_history_data',
    'get_console_history_data_output',
]

@pulumi.output_type
class GetConsoleHistoryDataResult:
    """
    A collection of values returned by getConsoleHistoryData.
    """
    def __init__(__self__, console_history_id=None, data=None, id=None, length=None, offset=None):
        if console_history_id and not isinstance(console_history_id, str):
            raise TypeError("Expected argument 'console_history_id' to be a str")
        pulumi.set(__self__, "console_history_id", console_history_id)
        if data and not isinstance(data, str):
            raise TypeError("Expected argument 'data' to be a str")
        pulumi.set(__self__, "data", data)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if length and not isinstance(length, int):
            raise TypeError("Expected argument 'length' to be a int")
        pulumi.set(__self__, "length", length)
        if offset and not isinstance(offset, int):
            raise TypeError("Expected argument 'offset' to be a int")
        pulumi.set(__self__, "offset", offset)

    @_builtins.property
    @pulumi.getter(name="consoleHistoryId")
    def console_history_id(self) -> _builtins.str:
        return pulumi.get(self, "console_history_id")

    @_builtins.property
    @pulumi.getter
    def data(self) -> _builtins.str:
        """
        The console history data.
        """
        return pulumi.get(self, "data")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def length(self) -> Optional[_builtins.int]:
        return pulumi.get(self, "length")

    @_builtins.property
    @pulumi.getter
    def offset(self) -> Optional[_builtins.int]:
        return pulumi.get(self, "offset")


class AwaitableGetConsoleHistoryDataResult(GetConsoleHistoryDataResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetConsoleHistoryDataResult(
            console_history_id=self.console_history_id,
            data=self.data,
            id=self.id,
            length=self.length,
            offset=self.offset)


def get_console_history_data(console_history_id: Optional[_builtins.str] = None,
                             length: Optional[_builtins.int] = None,
                             offset: Optional[_builtins.int] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetConsoleHistoryDataResult:
    """
    This data source provides details about a specific Console History Content resource in Oracle Cloud Infrastructure Core service.

    Gets the actual console history data (not the metadata).
    See [CaptureConsoleHistory](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ConsoleHistory/CaptureConsoleHistory)
    for details about using the console history operations.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_console_history_data = oci.Core.get_console_history_data(console_history_id=test_console_history["id"],
        length=console_history_content_length,
        offset=console_history_content_offset)
    ```


    :param _builtins.str console_history_id: The OCID of the console history.
    :param _builtins.int length: Length of the snapshot data to retrieve. Cannot be less than 10240.
    :param _builtins.int offset: Offset of the snapshot data to retrieve.
    """
    __args__ = dict()
    __args__['consoleHistoryId'] = console_history_id
    __args__['length'] = length
    __args__['offset'] = offset
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getConsoleHistoryData:getConsoleHistoryData', __args__, opts=opts, typ=GetConsoleHistoryDataResult).value

    return AwaitableGetConsoleHistoryDataResult(
        console_history_id=pulumi.get(__ret__, 'console_history_id'),
        data=pulumi.get(__ret__, 'data'),
        id=pulumi.get(__ret__, 'id'),
        length=pulumi.get(__ret__, 'length'),
        offset=pulumi.get(__ret__, 'offset'))
def get_console_history_data_output(console_history_id: Optional[pulumi.Input[_builtins.str]] = None,
                                    length: Optional[pulumi.Input[Optional[_builtins.int]]] = None,
                                    offset: Optional[pulumi.Input[Optional[_builtins.int]]] = None,
                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetConsoleHistoryDataResult]:
    """
    This data source provides details about a specific Console History Content resource in Oracle Cloud Infrastructure Core service.

    Gets the actual console history data (not the metadata).
    See [CaptureConsoleHistory](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ConsoleHistory/CaptureConsoleHistory)
    for details about using the console history operations.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_console_history_data = oci.Core.get_console_history_data(console_history_id=test_console_history["id"],
        length=console_history_content_length,
        offset=console_history_content_offset)
    ```


    :param _builtins.str console_history_id: The OCID of the console history.
    :param _builtins.int length: Length of the snapshot data to retrieve. Cannot be less than 10240.
    :param _builtins.int offset: Offset of the snapshot data to retrieve.
    """
    __args__ = dict()
    __args__['consoleHistoryId'] = console_history_id
    __args__['length'] = length
    __args__['offset'] = offset
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getConsoleHistoryData:getConsoleHistoryData', __args__, opts=opts, typ=GetConsoleHistoryDataResult)
    return __ret__.apply(lambda __response__: GetConsoleHistoryDataResult(
        console_history_id=pulumi.get(__response__, 'console_history_id'),
        data=pulumi.get(__response__, 'data'),
        id=pulumi.get(__response__, 'id'),
        length=pulumi.get(__response__, 'length'),
        offset=pulumi.get(__response__, 'offset')))
