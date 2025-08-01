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
    'GetExadataInfrastructureDownloadConfigFileResult',
    'AwaitableGetExadataInfrastructureDownloadConfigFileResult',
    'get_exadata_infrastructure_download_config_file',
    'get_exadata_infrastructure_download_config_file_output',
]

@pulumi.output_type
class GetExadataInfrastructureDownloadConfigFileResult:
    """
    A collection of values returned by getExadataInfrastructureDownloadConfigFile.
    """
    def __init__(__self__, base64_encode_content=None, content=None, exadata_infrastructure_id=None, id=None):
        if base64_encode_content and not isinstance(base64_encode_content, bool):
            raise TypeError("Expected argument 'base64_encode_content' to be a bool")
        pulumi.set(__self__, "base64_encode_content", base64_encode_content)
        if content and not isinstance(content, str):
            raise TypeError("Expected argument 'content' to be a str")
        pulumi.set(__self__, "content", content)
        if exadata_infrastructure_id and not isinstance(exadata_infrastructure_id, str):
            raise TypeError("Expected argument 'exadata_infrastructure_id' to be a str")
        pulumi.set(__self__, "exadata_infrastructure_id", exadata_infrastructure_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @_builtins.property
    @pulumi.getter(name="base64EncodeContent")
    def base64_encode_content(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "base64_encode_content")

    @_builtins.property
    @pulumi.getter
    def content(self) -> _builtins.str:
        """
        content of the downloaded config file for exadata infrastructure. If `base64_encode_content` is set to `true`, then this content will be base64 encoded.
        """
        return pulumi.get(self, "content")

    @_builtins.property
    @pulumi.getter(name="exadataInfrastructureId")
    def exadata_infrastructure_id(self) -> _builtins.str:
        return pulumi.get(self, "exadata_infrastructure_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetExadataInfrastructureDownloadConfigFileResult(GetExadataInfrastructureDownloadConfigFileResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetExadataInfrastructureDownloadConfigFileResult(
            base64_encode_content=self.base64_encode_content,
            content=self.content,
            exadata_infrastructure_id=self.exadata_infrastructure_id,
            id=self.id)


def get_exadata_infrastructure_download_config_file(base64_encode_content: Optional[_builtins.bool] = None,
                                                    exadata_infrastructure_id: Optional[_builtins.str] = None,
                                                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetExadataInfrastructureDownloadConfigFileResult:
    """
    This data source provides details about a specific Exadata Infrastructure Download Config File resource in Oracle Cloud Infrastructure Database service.

    Downloads the configuration file for the specified Exadata Cloud@Customer infrastructure.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_exadata_infrastructure_download_config_file = oci.Database.get_exadata_infrastructure_download_config_file(exadata_infrastructure_id=test_exadata_infrastructure["id"],
        base64_encode_content=False)
    ```


    :param _builtins.str exadata_infrastructure_id: The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['base64EncodeContent'] = base64_encode_content
    __args__['exadataInfrastructureId'] = exadata_infrastructure_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getExadataInfrastructureDownloadConfigFile:getExadataInfrastructureDownloadConfigFile', __args__, opts=opts, typ=GetExadataInfrastructureDownloadConfigFileResult).value

    return AwaitableGetExadataInfrastructureDownloadConfigFileResult(
        base64_encode_content=pulumi.get(__ret__, 'base64_encode_content'),
        content=pulumi.get(__ret__, 'content'),
        exadata_infrastructure_id=pulumi.get(__ret__, 'exadata_infrastructure_id'),
        id=pulumi.get(__ret__, 'id'))
def get_exadata_infrastructure_download_config_file_output(base64_encode_content: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                                                           exadata_infrastructure_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetExadataInfrastructureDownloadConfigFileResult]:
    """
    This data source provides details about a specific Exadata Infrastructure Download Config File resource in Oracle Cloud Infrastructure Database service.

    Downloads the configuration file for the specified Exadata Cloud@Customer infrastructure.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_exadata_infrastructure_download_config_file = oci.Database.get_exadata_infrastructure_download_config_file(exadata_infrastructure_id=test_exadata_infrastructure["id"],
        base64_encode_content=False)
    ```


    :param _builtins.str exadata_infrastructure_id: The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['base64EncodeContent'] = base64_encode_content
    __args__['exadataInfrastructureId'] = exadata_infrastructure_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Database/getExadataInfrastructureDownloadConfigFile:getExadataInfrastructureDownloadConfigFile', __args__, opts=opts, typ=GetExadataInfrastructureDownloadConfigFileResult)
    return __ret__.apply(lambda __response__: GetExadataInfrastructureDownloadConfigFileResult(
        base64_encode_content=pulumi.get(__response__, 'base64_encode_content'),
        content=pulumi.get(__response__, 'content'),
        exadata_infrastructure_id=pulumi.get(__response__, 'exadata_infrastructure_id'),
        id=pulumi.get(__response__, 'id')))
