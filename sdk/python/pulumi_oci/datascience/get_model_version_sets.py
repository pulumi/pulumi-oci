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
    'GetModelVersionSetsResult',
    'AwaitableGetModelVersionSetsResult',
    'get_model_version_sets',
    'get_model_version_sets_output',
]

@pulumi.output_type
class GetModelVersionSetsResult:
    """
    A collection of values returned by getModelVersionSets.
    """
    def __init__(__self__, compartment_id=None, created_by=None, filters=None, id=None, model_version_sets=None, name=None, project_id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by and not isinstance(created_by, str):
            raise TypeError("Expected argument 'created_by' to be a str")
        pulumi.set(__self__, "created_by", created_by)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if model_version_sets and not isinstance(model_version_sets, list):
            raise TypeError("Expected argument 'model_version_sets' to be a list")
        pulumi.set(__self__, "model_version_sets", model_version_sets)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model version set.
        """
        return pulumi.get(self, "created_by")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetModelVersionSetsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="modelVersionSets")
    def model_version_sets(self) -> Sequence['outputs.GetModelVersionSetsModelVersionSetResult']:
        """
        The list of model_version_sets.
        """
        return pulumi.get(self, "model_version_sets")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        A user-friendly name for the resource. It must be unique and can't be modified.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the model version set.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The state of the model version set.
        """
        return pulumi.get(self, "state")


class AwaitableGetModelVersionSetsResult(GetModelVersionSetsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetModelVersionSetsResult(
            compartment_id=self.compartment_id,
            created_by=self.created_by,
            filters=self.filters,
            id=self.id,
            model_version_sets=self.model_version_sets,
            name=self.name,
            project_id=self.project_id,
            state=self.state)


def get_model_version_sets(compartment_id: Optional[str] = None,
                           created_by: Optional[str] = None,
                           filters: Optional[Sequence[pulumi.InputType['GetModelVersionSetsFilterArgs']]] = None,
                           id: Optional[str] = None,
                           name: Optional[str] = None,
                           project_id: Optional[str] = None,
                           state: Optional[str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetModelVersionSetsResult:
    """
    This data source provides the list of Model Version Sets in Oracle Cloud Infrastructure Data Science service.

    Lists model version sets in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_model_version_sets = oci.DataScience.get_model_version_sets(compartment_id=var["compartment_id"],
        created_by=var["model_version_set_created_by"],
        id=var["model_version_set_id"],
        name=var["model_version_set_name"],
        project_id=oci_datascience_project["test_project"]["id"],
        state=var["model_version_set_state"])
    ```


    :param str compartment_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str created_by: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
    :param str id: <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
    :param str name: A filter to return only resources that match the entire name given.
    :param str project_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
    :param str state: <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['createdBy'] = created_by
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['name'] = name
    __args__['projectId'] = project_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataScience/getModelVersionSets:getModelVersionSets', __args__, opts=opts, typ=GetModelVersionSetsResult).value

    return AwaitableGetModelVersionSetsResult(
        compartment_id=__ret__.compartment_id,
        created_by=__ret__.created_by,
        filters=__ret__.filters,
        id=__ret__.id,
        model_version_sets=__ret__.model_version_sets,
        name=__ret__.name,
        project_id=__ret__.project_id,
        state=__ret__.state)


@_utilities.lift_output_func(get_model_version_sets)
def get_model_version_sets_output(compartment_id: Optional[pulumi.Input[str]] = None,
                                  created_by: Optional[pulumi.Input[Optional[str]]] = None,
                                  filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetModelVersionSetsFilterArgs']]]]] = None,
                                  id: Optional[pulumi.Input[Optional[str]]] = None,
                                  name: Optional[pulumi.Input[Optional[str]]] = None,
                                  project_id: Optional[pulumi.Input[Optional[str]]] = None,
                                  state: Optional[pulumi.Input[Optional[str]]] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetModelVersionSetsResult]:
    """
    This data source provides the list of Model Version Sets in Oracle Cloud Infrastructure Data Science service.

    Lists model version sets in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_model_version_sets = oci.DataScience.get_model_version_sets(compartment_id=var["compartment_id"],
        created_by=var["model_version_set_created_by"],
        id=var["model_version_set_id"],
        name=var["model_version_set_name"],
        project_id=oci_datascience_project["test_project"]["id"],
        state=var["model_version_set_state"])
    ```


    :param str compartment_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str created_by: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
    :param str id: <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
    :param str name: A filter to return only resources that match the entire name given.
    :param str project_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
    :param str state: <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    ...