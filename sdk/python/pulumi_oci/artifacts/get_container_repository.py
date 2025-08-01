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
    'GetContainerRepositoryResult',
    'AwaitableGetContainerRepositoryResult',
    'get_container_repository',
    'get_container_repository_output',
]

@pulumi.output_type
class GetContainerRepositoryResult:
    """
    A collection of values returned by getContainerRepository.
    """
    def __init__(__self__, billable_size_in_gbs=None, compartment_id=None, created_by=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, image_count=None, is_immutable=None, is_public=None, layer_count=None, layers_size_in_bytes=None, namespace=None, readmes=None, repository_id=None, state=None, system_tags=None, time_created=None, time_last_pushed=None):
        if billable_size_in_gbs and not isinstance(billable_size_in_gbs, str):
            raise TypeError("Expected argument 'billable_size_in_gbs' to be a str")
        pulumi.set(__self__, "billable_size_in_gbs", billable_size_in_gbs)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by and not isinstance(created_by, str):
            raise TypeError("Expected argument 'created_by' to be a str")
        pulumi.set(__self__, "created_by", created_by)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if image_count and not isinstance(image_count, int):
            raise TypeError("Expected argument 'image_count' to be a int")
        pulumi.set(__self__, "image_count", image_count)
        if is_immutable and not isinstance(is_immutable, bool):
            raise TypeError("Expected argument 'is_immutable' to be a bool")
        pulumi.set(__self__, "is_immutable", is_immutable)
        if is_public and not isinstance(is_public, bool):
            raise TypeError("Expected argument 'is_public' to be a bool")
        pulumi.set(__self__, "is_public", is_public)
        if layer_count and not isinstance(layer_count, int):
            raise TypeError("Expected argument 'layer_count' to be a int")
        pulumi.set(__self__, "layer_count", layer_count)
        if layers_size_in_bytes and not isinstance(layers_size_in_bytes, str):
            raise TypeError("Expected argument 'layers_size_in_bytes' to be a str")
        pulumi.set(__self__, "layers_size_in_bytes", layers_size_in_bytes)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if readmes and not isinstance(readmes, list):
            raise TypeError("Expected argument 'readmes' to be a list")
        pulumi.set(__self__, "readmes", readmes)
        if repository_id and not isinstance(repository_id, str):
            raise TypeError("Expected argument 'repository_id' to be a str")
        pulumi.set(__self__, "repository_id", repository_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_last_pushed and not isinstance(time_last_pushed, str):
            raise TypeError("Expected argument 'time_last_pushed' to be a str")
        pulumi.set(__self__, "time_last_pushed", time_last_pushed)

    @_builtins.property
    @pulumi.getter(name="billableSizeInGbs")
    def billable_size_in_gbs(self) -> _builtins.str:
        """
        Total storage size in GBs that will be charged.
        """
        return pulumi.get(self, "billable_size_in_gbs")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment in which the container repository exists.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> _builtins.str:
        """
        The id of the user or principal that created the resource.
        """
        return pulumi.get(self, "created_by")

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
        The container repository name.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container repository.  Example: `ocid1.containerrepo.oc1..exampleuniqueID`
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="imageCount")
    def image_count(self) -> _builtins.int:
        """
        Total number of images.
        """
        return pulumi.get(self, "image_count")

    @_builtins.property
    @pulumi.getter(name="isImmutable")
    def is_immutable(self) -> _builtins.bool:
        """
        Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
        """
        return pulumi.get(self, "is_immutable")

    @_builtins.property
    @pulumi.getter(name="isPublic")
    def is_public(self) -> _builtins.bool:
        """
        Whether the repository is public. A public repository allows unauthenticated access.
        """
        return pulumi.get(self, "is_public")

    @_builtins.property
    @pulumi.getter(name="layerCount")
    def layer_count(self) -> _builtins.int:
        """
        Total number of layers.
        """
        return pulumi.get(self, "layer_count")

    @_builtins.property
    @pulumi.getter(name="layersSizeInBytes")
    def layers_size_in_bytes(self) -> _builtins.str:
        """
        Total storage in bytes consumed by layers.
        """
        return pulumi.get(self, "layers_size_in_bytes")

    @_builtins.property
    @pulumi.getter
    def namespace(self) -> _builtins.str:
        """
        The tenancy namespace used in the container repository path.
        """
        return pulumi.get(self, "namespace")

    @_builtins.property
    @pulumi.getter
    def readmes(self) -> Sequence['outputs.GetContainerRepositoryReadmeResult']:
        """
        Container repository readme.
        """
        return pulumi.get(self, "readmes")

    @_builtins.property
    @pulumi.getter(name="repositoryId")
    def repository_id(self) -> _builtins.str:
        return pulumi.get(self, "repository_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the container repository.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        The system tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        An RFC 3339 timestamp indicating when the repository was created.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeLastPushed")
    def time_last_pushed(self) -> _builtins.str:
        """
        An RFC 3339 timestamp indicating when an image was last pushed to the repository.
        """
        return pulumi.get(self, "time_last_pushed")


class AwaitableGetContainerRepositoryResult(GetContainerRepositoryResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetContainerRepositoryResult(
            billable_size_in_gbs=self.billable_size_in_gbs,
            compartment_id=self.compartment_id,
            created_by=self.created_by,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            image_count=self.image_count,
            is_immutable=self.is_immutable,
            is_public=self.is_public,
            layer_count=self.layer_count,
            layers_size_in_bytes=self.layers_size_in_bytes,
            namespace=self.namespace,
            readmes=self.readmes,
            repository_id=self.repository_id,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_last_pushed=self.time_last_pushed)


def get_container_repository(repository_id: Optional[_builtins.str] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetContainerRepositoryResult:
    """
    This data source provides details about a specific Container Repository resource in Oracle Cloud Infrastructure Artifacts service.

    Get container repository.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_container_repository = oci.Artifacts.get_container_repository(repository_id=test_repository["id"])
    ```


    :param _builtins.str repository_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container repository.  Example: `ocid1.containerrepo.oc1..exampleuniqueID`
    """
    __args__ = dict()
    __args__['repositoryId'] = repository_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Artifacts/getContainerRepository:getContainerRepository', __args__, opts=opts, typ=GetContainerRepositoryResult).value

    return AwaitableGetContainerRepositoryResult(
        billable_size_in_gbs=pulumi.get(__ret__, 'billable_size_in_gbs'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        created_by=pulumi.get(__ret__, 'created_by'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        image_count=pulumi.get(__ret__, 'image_count'),
        is_immutable=pulumi.get(__ret__, 'is_immutable'),
        is_public=pulumi.get(__ret__, 'is_public'),
        layer_count=pulumi.get(__ret__, 'layer_count'),
        layers_size_in_bytes=pulumi.get(__ret__, 'layers_size_in_bytes'),
        namespace=pulumi.get(__ret__, 'namespace'),
        readmes=pulumi.get(__ret__, 'readmes'),
        repository_id=pulumi.get(__ret__, 'repository_id'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_last_pushed=pulumi.get(__ret__, 'time_last_pushed'))
def get_container_repository_output(repository_id: Optional[pulumi.Input[_builtins.str]] = None,
                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetContainerRepositoryResult]:
    """
    This data source provides details about a specific Container Repository resource in Oracle Cloud Infrastructure Artifacts service.

    Get container repository.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_container_repository = oci.Artifacts.get_container_repository(repository_id=test_repository["id"])
    ```


    :param _builtins.str repository_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container repository.  Example: `ocid1.containerrepo.oc1..exampleuniqueID`
    """
    __args__ = dict()
    __args__['repositoryId'] = repository_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Artifacts/getContainerRepository:getContainerRepository', __args__, opts=opts, typ=GetContainerRepositoryResult)
    return __ret__.apply(lambda __response__: GetContainerRepositoryResult(
        billable_size_in_gbs=pulumi.get(__response__, 'billable_size_in_gbs'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        created_by=pulumi.get(__response__, 'created_by'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        image_count=pulumi.get(__response__, 'image_count'),
        is_immutable=pulumi.get(__response__, 'is_immutable'),
        is_public=pulumi.get(__response__, 'is_public'),
        layer_count=pulumi.get(__response__, 'layer_count'),
        layers_size_in_bytes=pulumi.get(__response__, 'layers_size_in_bytes'),
        namespace=pulumi.get(__response__, 'namespace'),
        readmes=pulumi.get(__response__, 'readmes'),
        repository_id=pulumi.get(__response__, 'repository_id'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_last_pushed=pulumi.get(__response__, 'time_last_pushed')))
