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
    'GetRepositoryAuthorsResult',
    'AwaitableGetRepositoryAuthorsResult',
    'get_repository_authors',
    'get_repository_authors_output',
]

@pulumi.output_type
class GetRepositoryAuthorsResult:
    """
    A collection of values returned by getRepositoryAuthors.
    """
    def __init__(__self__, filters=None, id=None, ref_name=None, repository_author_collections=None, repository_id=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ref_name and not isinstance(ref_name, str):
            raise TypeError("Expected argument 'ref_name' to be a str")
        pulumi.set(__self__, "ref_name", ref_name)
        if repository_author_collections and not isinstance(repository_author_collections, list):
            raise TypeError("Expected argument 'repository_author_collections' to be a list")
        pulumi.set(__self__, "repository_author_collections", repository_author_collections)
        if repository_id and not isinstance(repository_id, str):
            raise TypeError("Expected argument 'repository_id' to be a str")
        pulumi.set(__self__, "repository_id", repository_id)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetRepositoryAuthorsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="refName")
    def ref_name(self) -> Optional[str]:
        return pulumi.get(self, "ref_name")

    @property
    @pulumi.getter(name="repositoryAuthorCollections")
    def repository_author_collections(self) -> Sequence['outputs.GetRepositoryAuthorsRepositoryAuthorCollectionResult']:
        """
        The list of repository_author_collection.
        """
        return pulumi.get(self, "repository_author_collections")

    @property
    @pulumi.getter(name="repositoryId")
    def repository_id(self) -> str:
        return pulumi.get(self, "repository_id")


class AwaitableGetRepositoryAuthorsResult(GetRepositoryAuthorsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRepositoryAuthorsResult(
            filters=self.filters,
            id=self.id,
            ref_name=self.ref_name,
            repository_author_collections=self.repository_author_collections,
            repository_id=self.repository_id)


def get_repository_authors(filters: Optional[Sequence[pulumi.InputType['GetRepositoryAuthorsFilterArgs']]] = None,
                           ref_name: Optional[str] = None,
                           repository_id: Optional[str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRepositoryAuthorsResult:
    """
    This data source provides the list of Repository Authors in Oracle Cloud Infrastructure Devops service.

    Retrieve a list of all the authors.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_repository_authors = oci.DevOps.get_repository_authors(repository_id=oci_devops_repository["test_repository"]["id"],
        ref_name=var["repository_author_ref_name"])
    ```


    :param str ref_name: A filter to return only resources that match the given reference name.
    :param str repository_id: Unique repository identifier.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['refName'] = ref_name
    __args__['repositoryId'] = repository_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getRepositoryAuthors:getRepositoryAuthors', __args__, opts=opts, typ=GetRepositoryAuthorsResult).value

    return AwaitableGetRepositoryAuthorsResult(
        filters=__ret__.filters,
        id=__ret__.id,
        ref_name=__ret__.ref_name,
        repository_author_collections=__ret__.repository_author_collections,
        repository_id=__ret__.repository_id)


@_utilities.lift_output_func(get_repository_authors)
def get_repository_authors_output(filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetRepositoryAuthorsFilterArgs']]]]] = None,
                                  ref_name: Optional[pulumi.Input[Optional[str]]] = None,
                                  repository_id: Optional[pulumi.Input[str]] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetRepositoryAuthorsResult]:
    """
    This data source provides the list of Repository Authors in Oracle Cloud Infrastructure Devops service.

    Retrieve a list of all the authors.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_repository_authors = oci.DevOps.get_repository_authors(repository_id=oci_devops_repository["test_repository"]["id"],
        ref_name=var["repository_author_ref_name"])
    ```


    :param str ref_name: A filter to return only resources that match the given reference name.
    :param str repository_id: Unique repository identifier.
    """
    ...