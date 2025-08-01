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
    'GetRepositoriesResult',
    'AwaitableGetRepositoriesResult',
    'get_repositories',
    'get_repositories_output',
]

@pulumi.output_type
class GetRepositoriesResult:
    """
    A collection of values returned by getRepositories.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, name=None, project_id=None, repository_collections=None, repository_id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if repository_collections and not isinstance(repository_collections, list):
            raise TypeError("Expected argument 'repository_collections' to be a list")
        pulumi.set(__self__, "repository_collections", repository_collections)
        if repository_id and not isinstance(repository_id, str):
            raise TypeError("Expected argument 'repository_id' to be a str")
        pulumi.set(__self__, "repository_id", repository_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the repository's compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetRepositoriesFilterResult']]:
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
    def name(self) -> Optional[_builtins.str]:
        """
        Name of the repository. Should be unique within the project. This value is mutable.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="projectId")
    def project_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the DevOps project containing the repository.
        """
        return pulumi.get(self, "project_id")

    @_builtins.property
    @pulumi.getter(name="repositoryCollections")
    def repository_collections(self) -> Sequence['outputs.GetRepositoriesRepositoryCollectionResult']:
        """
        The list of repository_collection.
        """
        return pulumi.get(self, "repository_collections")

    @_builtins.property
    @pulumi.getter(name="repositoryId")
    def repository_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "repository_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the repository.
        """
        return pulumi.get(self, "state")


class AwaitableGetRepositoriesResult(GetRepositoriesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRepositoriesResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            name=self.name,
            project_id=self.project_id,
            repository_collections=self.repository_collections,
            repository_id=self.repository_id,
            state=self.state)


def get_repositories(compartment_id: Optional[_builtins.str] = None,
                     filters: Optional[Sequence[Union['GetRepositoriesFilterArgs', 'GetRepositoriesFilterArgsDict']]] = None,
                     name: Optional[_builtins.str] = None,
                     project_id: Optional[_builtins.str] = None,
                     repository_id: Optional[_builtins.str] = None,
                     state: Optional[_builtins.str] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRepositoriesResult:
    """
    This data source provides the list of Repositories in Oracle Cloud Infrastructure Devops service.

    Returns a list of repositories given a compartment ID or a project ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_repositories = oci.DevOps.get_repositories(compartment_id=compartment_id,
        name=repository_name,
        project_id=test_project["id"],
        repository_id=test_repository["id"],
        state=repository_state)
    ```


    :param _builtins.str compartment_id: The OCID of the compartment in which to list resources.
    :param _builtins.str name: A filter to return only resources that match the entire name given.
    :param _builtins.str project_id: unique project identifier
    :param _builtins.str repository_id: Unique repository identifier.
    :param _builtins.str state: A filter to return only resources whose lifecycle state matches the given lifecycle state.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['projectId'] = project_id
    __args__['repositoryId'] = repository_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getRepositories:getRepositories', __args__, opts=opts, typ=GetRepositoriesResult).value

    return AwaitableGetRepositoriesResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        project_id=pulumi.get(__ret__, 'project_id'),
        repository_collections=pulumi.get(__ret__, 'repository_collections'),
        repository_id=pulumi.get(__ret__, 'repository_id'),
        state=pulumi.get(__ret__, 'state'))
def get_repositories_output(compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                            filters: Optional[pulumi.Input[Optional[Sequence[Union['GetRepositoriesFilterArgs', 'GetRepositoriesFilterArgsDict']]]]] = None,
                            name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                            project_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                            repository_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                            state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetRepositoriesResult]:
    """
    This data source provides the list of Repositories in Oracle Cloud Infrastructure Devops service.

    Returns a list of repositories given a compartment ID or a project ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_repositories = oci.DevOps.get_repositories(compartment_id=compartment_id,
        name=repository_name,
        project_id=test_project["id"],
        repository_id=test_repository["id"],
        state=repository_state)
    ```


    :param _builtins.str compartment_id: The OCID of the compartment in which to list resources.
    :param _builtins.str name: A filter to return only resources that match the entire name given.
    :param _builtins.str project_id: unique project identifier
    :param _builtins.str repository_id: Unique repository identifier.
    :param _builtins.str state: A filter to return only resources whose lifecycle state matches the given lifecycle state.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['projectId'] = project_id
    __args__['repositoryId'] = repository_id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DevOps/getRepositories:getRepositories', __args__, opts=opts, typ=GetRepositoriesResult)
    return __ret__.apply(lambda __response__: GetRepositoriesResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        project_id=pulumi.get(__response__, 'project_id'),
        repository_collections=pulumi.get(__response__, 'repository_collections'),
        repository_id=pulumi.get(__response__, 'repository_id'),
        state=pulumi.get(__response__, 'state')))
