# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetRepositoryFileLineResult',
    'AwaitableGetRepositoryFileLineResult',
    'get_repository_file_line',
    'get_repository_file_line_output',
]

@pulumi.output_type
class GetRepositoryFileLineResult:
    """
    A collection of values returned by getRepositoryFileLine.
    """
    def __init__(__self__, file_path=None, id=None, lines=None, repository_id=None, revision=None, start_line_number=None):
        if file_path and not isinstance(file_path, str):
            raise TypeError("Expected argument 'file_path' to be a str")
        pulumi.set(__self__, "file_path", file_path)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lines and not isinstance(lines, list):
            raise TypeError("Expected argument 'lines' to be a list")
        pulumi.set(__self__, "lines", lines)
        if repository_id and not isinstance(repository_id, str):
            raise TypeError("Expected argument 'repository_id' to be a str")
        pulumi.set(__self__, "repository_id", repository_id)
        if revision and not isinstance(revision, str):
            raise TypeError("Expected argument 'revision' to be a str")
        pulumi.set(__self__, "revision", revision)
        if start_line_number and not isinstance(start_line_number, int):
            raise TypeError("Expected argument 'start_line_number' to be a int")
        pulumi.set(__self__, "start_line_number", start_line_number)

    @property
    @pulumi.getter(name="filePath")
    def file_path(self) -> str:
        return pulumi.get(self, "file_path")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def lines(self) -> Sequence['outputs.GetRepositoryFileLineLineResult']:
        """
        The list of lines in the file.
        """
        return pulumi.get(self, "lines")

    @property
    @pulumi.getter(name="repositoryId")
    def repository_id(self) -> str:
        return pulumi.get(self, "repository_id")

    @property
    @pulumi.getter
    def revision(self) -> str:
        return pulumi.get(self, "revision")

    @property
    @pulumi.getter(name="startLineNumber")
    def start_line_number(self) -> Optional[int]:
        return pulumi.get(self, "start_line_number")


class AwaitableGetRepositoryFileLineResult(GetRepositoryFileLineResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRepositoryFileLineResult(
            file_path=self.file_path,
            id=self.id,
            lines=self.lines,
            repository_id=self.repository_id,
            revision=self.revision,
            start_line_number=self.start_line_number)


def get_repository_file_line(file_path: Optional[str] = None,
                             repository_id: Optional[str] = None,
                             revision: Optional[str] = None,
                             start_line_number: Optional[int] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRepositoryFileLineResult:
    """
    This data source provides details about a specific Repository File Line resource in Oracle Cloud Infrastructure Devops service.

    Retrieve lines of a specified file. Supports starting line number and limit. This API will be deprecated on Wed, 29 Mar 2023 01:00:00 GMT as it does not get recognized when filePath has '/'. This will be replaced by "/repositories/{repositoryId}/file/lines"

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_repository_file_line = oci.DevOps.get_repository_file_line(repository_id=oci_devops_repository["test_repository"]["id"],
        revision=var["repository_file_line_revision"],
        file_path=var["repository_file_line_file_path"],
        start_line_number=var["repository_file_line_start_line_number"])
    ```


    :param str file_path: Path to a file within a repository.
    :param str repository_id: Unique repository identifier.
    :param str revision: Retrieve file lines from specific revision.
    :param int start_line_number: Line number from where to start returning file lines.
    """
    __args__ = dict()
    __args__['filePath'] = file_path
    __args__['repositoryId'] = repository_id
    __args__['revision'] = revision
    __args__['startLineNumber'] = start_line_number
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getRepositoryFileLine:getRepositoryFileLine', __args__, opts=opts, typ=GetRepositoryFileLineResult).value

    return AwaitableGetRepositoryFileLineResult(
        file_path=__ret__.file_path,
        id=__ret__.id,
        lines=__ret__.lines,
        repository_id=__ret__.repository_id,
        revision=__ret__.revision,
        start_line_number=__ret__.start_line_number)


@_utilities.lift_output_func(get_repository_file_line)
def get_repository_file_line_output(file_path: Optional[pulumi.Input[str]] = None,
                                    repository_id: Optional[pulumi.Input[str]] = None,
                                    revision: Optional[pulumi.Input[str]] = None,
                                    start_line_number: Optional[pulumi.Input[Optional[int]]] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetRepositoryFileLineResult]:
    """
    This data source provides details about a specific Repository File Line resource in Oracle Cloud Infrastructure Devops service.

    Retrieve lines of a specified file. Supports starting line number and limit. This API will be deprecated on Wed, 29 Mar 2023 01:00:00 GMT as it does not get recognized when filePath has '/'. This will be replaced by "/repositories/{repositoryId}/file/lines"

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_repository_file_line = oci.DevOps.get_repository_file_line(repository_id=oci_devops_repository["test_repository"]["id"],
        revision=var["repository_file_line_revision"],
        file_path=var["repository_file_line_file_path"],
        start_line_number=var["repository_file_line_start_line_number"])
    ```


    :param str file_path: Path to a file within a repository.
    :param str repository_id: Unique repository identifier.
    :param str revision: Retrieve file lines from specific revision.
    :param int start_line_number: Line number from where to start returning file lines.
    """
    ...
