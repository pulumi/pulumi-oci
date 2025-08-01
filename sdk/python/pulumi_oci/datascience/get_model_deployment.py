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
    'GetModelDeploymentResult',
    'AwaitableGetModelDeploymentResult',
    'get_model_deployment',
    'get_model_deployment_output',
]

@pulumi.output_type
class GetModelDeploymentResult:
    """
    A collection of values returned by getModelDeployment.
    """
    def __init__(__self__, category_log_details=None, compartment_id=None, created_by=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, model_deployment_configuration_details=None, model_deployment_id=None, model_deployment_system_datas=None, model_deployment_url=None, opc_parent_rpt_url=None, project_id=None, state=None, time_created=None):
        if category_log_details and not isinstance(category_log_details, list):
            raise TypeError("Expected argument 'category_log_details' to be a list")
        pulumi.set(__self__, "category_log_details", category_log_details)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by and not isinstance(created_by, str):
            raise TypeError("Expected argument 'created_by' to be a str")
        pulumi.set(__self__, "created_by", created_by)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if model_deployment_configuration_details and not isinstance(model_deployment_configuration_details, list):
            raise TypeError("Expected argument 'model_deployment_configuration_details' to be a list")
        pulumi.set(__self__, "model_deployment_configuration_details", model_deployment_configuration_details)
        if model_deployment_id and not isinstance(model_deployment_id, str):
            raise TypeError("Expected argument 'model_deployment_id' to be a str")
        pulumi.set(__self__, "model_deployment_id", model_deployment_id)
        if model_deployment_system_datas and not isinstance(model_deployment_system_datas, list):
            raise TypeError("Expected argument 'model_deployment_system_datas' to be a list")
        pulumi.set(__self__, "model_deployment_system_datas", model_deployment_system_datas)
        if model_deployment_url and not isinstance(model_deployment_url, str):
            raise TypeError("Expected argument 'model_deployment_url' to be a str")
        pulumi.set(__self__, "model_deployment_url", model_deployment_url)
        if opc_parent_rpt_url and not isinstance(opc_parent_rpt_url, str):
            raise TypeError("Expected argument 'opc_parent_rpt_url' to be a str")
        pulumi.set(__self__, "opc_parent_rpt_url", opc_parent_rpt_url)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter(name="categoryLogDetails")
    def category_log_details(self) -> Sequence['outputs.GetModelDeploymentCategoryLogDetailResult']:
        """
        The log details for each category.
        """
        return pulumi.get(self, "category_log_details")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment's compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model deployment.
        """
        return pulumi.get(self, "created_by")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        A short description of the model deployment.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        Details about the state of the model deployment.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="modelDeploymentConfigurationDetails")
    def model_deployment_configuration_details(self) -> Sequence['outputs.GetModelDeploymentModelDeploymentConfigurationDetailResult']:
        """
        The model deployment configuration details.
        """
        return pulumi.get(self, "model_deployment_configuration_details")

    @_builtins.property
    @pulumi.getter(name="modelDeploymentId")
    def model_deployment_id(self) -> _builtins.str:
        return pulumi.get(self, "model_deployment_id")

    @_builtins.property
    @pulumi.getter(name="modelDeploymentSystemDatas")
    def model_deployment_system_datas(self) -> Sequence['outputs.GetModelDeploymentModelDeploymentSystemDataResult']:
        """
        Model deployment system data.
        """
        return pulumi.get(self, "model_deployment_system_datas")

    @_builtins.property
    @pulumi.getter(name="modelDeploymentUrl")
    def model_deployment_url(self) -> _builtins.str:
        """
        The URL to interact with the model deployment.
        """
        return pulumi.get(self, "model_deployment_url")

    @_builtins.property
    @pulumi.getter(name="opcParentRptUrl")
    def opc_parent_rpt_url(self) -> _builtins.str:
        return pulumi.get(self, "opc_parent_rpt_url")

    @_builtins.property
    @pulumi.getter(name="projectId")
    def project_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the model deployment.
        """
        return pulumi.get(self, "project_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The state of the model deployment.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the resource was created, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
        """
        return pulumi.get(self, "time_created")


class AwaitableGetModelDeploymentResult(GetModelDeploymentResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetModelDeploymentResult(
            category_log_details=self.category_log_details,
            compartment_id=self.compartment_id,
            created_by=self.created_by,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            model_deployment_configuration_details=self.model_deployment_configuration_details,
            model_deployment_id=self.model_deployment_id,
            model_deployment_system_datas=self.model_deployment_system_datas,
            model_deployment_url=self.model_deployment_url,
            opc_parent_rpt_url=self.opc_parent_rpt_url,
            project_id=self.project_id,
            state=self.state,
            time_created=self.time_created)


def get_model_deployment(model_deployment_id: Optional[_builtins.str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetModelDeploymentResult:
    """
    This data source provides details about a specific Model Deployment resource in Oracle Cloud Infrastructure Datascience service.

    Retrieves the model deployment for the specified `modelDeploymentId`.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_model_deployment = oci.DataScience.get_model_deployment(model_deployment_id=test_model_deployment_oci_datascience_model_deployment["id"])
    ```


    :param _builtins.str model_deployment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment.
    """
    __args__ = dict()
    __args__['modelDeploymentId'] = model_deployment_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataScience/getModelDeployment:getModelDeployment', __args__, opts=opts, typ=GetModelDeploymentResult).value

    return AwaitableGetModelDeploymentResult(
        category_log_details=pulumi.get(__ret__, 'category_log_details'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        created_by=pulumi.get(__ret__, 'created_by'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        model_deployment_configuration_details=pulumi.get(__ret__, 'model_deployment_configuration_details'),
        model_deployment_id=pulumi.get(__ret__, 'model_deployment_id'),
        model_deployment_system_datas=pulumi.get(__ret__, 'model_deployment_system_datas'),
        model_deployment_url=pulumi.get(__ret__, 'model_deployment_url'),
        opc_parent_rpt_url=pulumi.get(__ret__, 'opc_parent_rpt_url'),
        project_id=pulumi.get(__ret__, 'project_id'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'))
def get_model_deployment_output(model_deployment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetModelDeploymentResult]:
    """
    This data source provides details about a specific Model Deployment resource in Oracle Cloud Infrastructure Datascience service.

    Retrieves the model deployment for the specified `modelDeploymentId`.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_model_deployment = oci.DataScience.get_model_deployment(model_deployment_id=test_model_deployment_oci_datascience_model_deployment["id"])
    ```


    :param _builtins.str model_deployment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment.
    """
    __args__ = dict()
    __args__['modelDeploymentId'] = model_deployment_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataScience/getModelDeployment:getModelDeployment', __args__, opts=opts, typ=GetModelDeploymentResult)
    return __ret__.apply(lambda __response__: GetModelDeploymentResult(
        category_log_details=pulumi.get(__response__, 'category_log_details'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        created_by=pulumi.get(__response__, 'created_by'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        model_deployment_configuration_details=pulumi.get(__response__, 'model_deployment_configuration_details'),
        model_deployment_id=pulumi.get(__response__, 'model_deployment_id'),
        model_deployment_system_datas=pulumi.get(__response__, 'model_deployment_system_datas'),
        model_deployment_url=pulumi.get(__response__, 'model_deployment_url'),
        opc_parent_rpt_url=pulumi.get(__response__, 'opc_parent_rpt_url'),
        project_id=pulumi.get(__response__, 'project_id'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created')))
