# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetRepositoryPathsResult',
    'AwaitableGetRepositoryPathsResult',
    'get_repository_paths',
    'get_repository_paths_output',
]

@pulumi.output_type
class GetRepositoryPathsResult:
    """
    A collection of values returned by getRepositoryPaths.
    """
    def __init__(__self__, display_name=None, filters=None, folder_path=None, id=None, paths_in_subtree=None, ref=None, repository_id=None, repository_path_collections=None):
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if folder_path and not isinstance(folder_path, str):
            raise TypeError("Expected argument 'folder_path' to be a str")
        pulumi.set(__self__, "folder_path", folder_path)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if paths_in_subtree and not isinstance(paths_in_subtree, bool):
            raise TypeError("Expected argument 'paths_in_subtree' to be a bool")
        pulumi.set(__self__, "paths_in_subtree", paths_in_subtree)
        if ref and not isinstance(ref, str):
            raise TypeError("Expected argument 'ref' to be a str")
        pulumi.set(__self__, "ref", ref)
        if repository_id and not isinstance(repository_id, str):
            raise TypeError("Expected argument 'repository_id' to be a str")
        pulumi.set(__self__, "repository_id", repository_id)
        if repository_path_collections and not isinstance(repository_path_collections, list):
            raise TypeError("Expected argument 'repository_path_collections' to be a list")
        pulumi.set(__self__, "repository_path_collections", repository_path_collections)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetRepositoryPathsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter(name="folderPath")
    def folder_path(self) -> Optional[str]:
        return pulumi.get(self, "folder_path")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="pathsInSubtree")
    def paths_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "paths_in_subtree")

    @property
    @pulumi.getter
    def ref(self) -> Optional[str]:
        return pulumi.get(self, "ref")

    @property
    @pulumi.getter(name="repositoryId")
    def repository_id(self) -> str:
        return pulumi.get(self, "repository_id")

    @property
    @pulumi.getter(name="repositoryPathCollections")
    def repository_path_collections(self) -> Sequence['outputs.GetRepositoryPathsRepositoryPathCollectionResult']:
        """
        The list of repository_path_collection.
        """
        return pulumi.get(self, "repository_path_collections")


class AwaitableGetRepositoryPathsResult(GetRepositoryPathsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRepositoryPathsResult(
            display_name=self.display_name,
            filters=self.filters,
            folder_path=self.folder_path,
            id=self.id,
            paths_in_subtree=self.paths_in_subtree,
            ref=self.ref,
            repository_id=self.repository_id,
            repository_path_collections=self.repository_path_collections)


def get_repository_paths(display_name: Optional[str] = None,
                         filters: Optional[Sequence[pulumi.InputType['GetRepositoryPathsFilterArgs']]] = None,
                         folder_path: Optional[str] = None,
                         paths_in_subtree: Optional[bool] = None,
                         ref: Optional[str] = None,
                         repository_id: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRepositoryPathsResult:
    """
    This data source provides the list of Repository Paths in Oracle Cloud Infrastructure Devops service.

    Retrieves a list of files and directories in a repository.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_repository_paths = oci.DevOps.get_repository_paths(repository_id=oci_devops_repository["test_repository"]["id"],
        display_name=var["repository_path_display_name"],
        folder_path=var["repository_path_folder_path"],
        paths_in_subtree=var["repository_path_paths_in_subtree"],
        ref=var["repository_path_ref"])
    ```


    :param str display_name: A filter to return only resources that match the entire display name given.
    :param str folder_path: The fully qualified path to the folder whose contents are returned, including the folder name. For example, /examples is a fully-qualified path to a folder named examples that was created off of the root directory (/) of a repository.
    :param bool paths_in_subtree: Flag to determine if files must be retrived recursively. Flag is False by default.
    :param str ref: The name of branch/tag or commit hash it points to. If names conflict, order of preference is commit > branch > tag. You can disambiguate with "heads/foobar" and "tags/foobar". If left blank repository's default branch will be used.
    :param str repository_id: Unique repository identifier.
    """
    __args__ = dict()
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['folderPath'] = folder_path
    __args__['pathsInSubtree'] = paths_in_subtree
    __args__['ref'] = ref
    __args__['repositoryId'] = repository_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getRepositoryPaths:getRepositoryPaths', __args__, opts=opts, typ=GetRepositoryPathsResult).value

    return AwaitableGetRepositoryPathsResult(
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        folder_path=__ret__.folder_path,
        id=__ret__.id,
        paths_in_subtree=__ret__.paths_in_subtree,
        ref=__ret__.ref,
        repository_id=__ret__.repository_id,
        repository_path_collections=__ret__.repository_path_collections)


@_utilities.lift_output_func(get_repository_paths)
def get_repository_paths_output(display_name: Optional[pulumi.Input[Optional[str]]] = None,
                                filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetRepositoryPathsFilterArgs']]]]] = None,
                                folder_path: Optional[pulumi.Input[Optional[str]]] = None,
                                paths_in_subtree: Optional[pulumi.Input[Optional[bool]]] = None,
                                ref: Optional[pulumi.Input[Optional[str]]] = None,
                                repository_id: Optional[pulumi.Input[str]] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetRepositoryPathsResult]:
    """
    This data source provides the list of Repository Paths in Oracle Cloud Infrastructure Devops service.

    Retrieves a list of files and directories in a repository.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_repository_paths = oci.DevOps.get_repository_paths(repository_id=oci_devops_repository["test_repository"]["id"],
        display_name=var["repository_path_display_name"],
        folder_path=var["repository_path_folder_path"],
        paths_in_subtree=var["repository_path_paths_in_subtree"],
        ref=var["repository_path_ref"])
    ```


    :param str display_name: A filter to return only resources that match the entire display name given.
    :param str folder_path: The fully qualified path to the folder whose contents are returned, including the folder name. For example, /examples is a fully-qualified path to a folder named examples that was created off of the root directory (/) of a repository.
    :param bool paths_in_subtree: Flag to determine if files must be retrived recursively. Flag is False by default.
    :param str ref: The name of branch/tag or commit hash it points to. If names conflict, order of preference is commit > branch > tag. You can disambiguate with "heads/foobar" and "tags/foobar". If left blank repository's default branch will be used.
    :param str repository_id: Unique repository identifier.
    """
    ...