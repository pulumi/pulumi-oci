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
    'GetDataMaskRuleResult',
    'AwaitableGetDataMaskRuleResult',
    'get_data_mask_rule',
    'get_data_mask_rule_output',
]

@pulumi.output_type
class GetDataMaskRuleResult:
    """
    A collection of values returned by getDataMaskRule.
    """
    def __init__(__self__, compartment_id=None, data_mask_categories=None, data_mask_rule_id=None, data_mask_rule_status=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, iam_group_id=None, id=None, lifecyle_details=None, state=None, system_tags=None, target_selecteds=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if data_mask_categories and not isinstance(data_mask_categories, list):
            raise TypeError("Expected argument 'data_mask_categories' to be a list")
        pulumi.set(__self__, "data_mask_categories", data_mask_categories)
        if data_mask_rule_id and not isinstance(data_mask_rule_id, str):
            raise TypeError("Expected argument 'data_mask_rule_id' to be a str")
        pulumi.set(__self__, "data_mask_rule_id", data_mask_rule_id)
        if data_mask_rule_status and not isinstance(data_mask_rule_status, str):
            raise TypeError("Expected argument 'data_mask_rule_status' to be a str")
        pulumi.set(__self__, "data_mask_rule_status", data_mask_rule_status)
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
        if iam_group_id and not isinstance(iam_group_id, str):
            raise TypeError("Expected argument 'iam_group_id' to be a str")
        pulumi.set(__self__, "iam_group_id", iam_group_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecyle_details and not isinstance(lifecyle_details, str):
            raise TypeError("Expected argument 'lifecyle_details' to be a str")
        pulumi.set(__self__, "lifecyle_details", lifecyle_details)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if target_selecteds and not isinstance(target_selecteds, list):
            raise TypeError("Expected argument 'target_selecteds' to be a list")
        pulumi.set(__self__, "target_selecteds", target_selecteds)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        Compartment OCID where the resource is created
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="dataMaskCategories")
    def data_mask_categories(self) -> Sequence[_builtins.str]:
        """
        List of data mask rule categories
        """
        return pulumi.get(self, "data_mask_categories")

    @_builtins.property
    @pulumi.getter(name="dataMaskRuleId")
    def data_mask_rule_id(self) -> _builtins.str:
        return pulumi.get(self, "data_mask_rule_id")

    @_builtins.property
    @pulumi.getter(name="dataMaskRuleStatus")
    def data_mask_rule_status(self) -> _builtins.str:
        """
        The current status of the data mask rule
        """
        return pulumi.get(self, "data_mask_rule_status")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        The data mask rule description
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        Data mask rule display name
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="iamGroupId")
    def iam_group_id(self) -> _builtins.str:
        """
        IAM Group ID associated with the data mask rule
        """
        return pulumi.get(self, "iam_group_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        Unique identifier that can't be changed after creation
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecyleDetails")
    def lifecyle_details(self) -> _builtins.str:
        """
        Additional details on the substate of the lifecycle state [DEPRECATE]
        """
        return pulumi.get(self, "lifecyle_details")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current lifecycle state of the data mask rule
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="targetSelecteds")
    def target_selecteds(self) -> Sequence['outputs.GetDataMaskRuleTargetSelectedResult']:
        """
        Specification of how targets are to be selected (select ALL, or select by TargetResourceType or TargetId).
        """
        return pulumi.get(self, "target_selecteds")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the target was created. Format defined by RFC3339.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the target was updated. Format defined by RFC3339.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDataMaskRuleResult(GetDataMaskRuleResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDataMaskRuleResult(
            compartment_id=self.compartment_id,
            data_mask_categories=self.data_mask_categories,
            data_mask_rule_id=self.data_mask_rule_id,
            data_mask_rule_status=self.data_mask_rule_status,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            iam_group_id=self.iam_group_id,
            id=self.id,
            lifecyle_details=self.lifecyle_details,
            state=self.state,
            system_tags=self.system_tags,
            target_selecteds=self.target_selecteds,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_data_mask_rule(data_mask_rule_id: Optional[_builtins.str] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDataMaskRuleResult:
    """
    This data source provides details about a specific Data Mask Rule resource in Oracle Cloud Infrastructure Cloud Guard service.

    Returns a DataMaskRule resource, identified by dataMaskRuleId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_data_mask_rule = oci.CloudGuard.get_data_mask_rule(data_mask_rule_id=test_data_mask_rule_oci_cloud_guard_data_mask_rule["id"])
    ```


    :param _builtins.str data_mask_rule_id: OCID of the data mask rule
    """
    __args__ = dict()
    __args__['dataMaskRuleId'] = data_mask_rule_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:CloudGuard/getDataMaskRule:getDataMaskRule', __args__, opts=opts, typ=GetDataMaskRuleResult).value

    return AwaitableGetDataMaskRuleResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        data_mask_categories=pulumi.get(__ret__, 'data_mask_categories'),
        data_mask_rule_id=pulumi.get(__ret__, 'data_mask_rule_id'),
        data_mask_rule_status=pulumi.get(__ret__, 'data_mask_rule_status'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        iam_group_id=pulumi.get(__ret__, 'iam_group_id'),
        id=pulumi.get(__ret__, 'id'),
        lifecyle_details=pulumi.get(__ret__, 'lifecyle_details'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        target_selecteds=pulumi.get(__ret__, 'target_selecteds'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_data_mask_rule_output(data_mask_rule_id: Optional[pulumi.Input[_builtins.str]] = None,
                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDataMaskRuleResult]:
    """
    This data source provides details about a specific Data Mask Rule resource in Oracle Cloud Infrastructure Cloud Guard service.

    Returns a DataMaskRule resource, identified by dataMaskRuleId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_data_mask_rule = oci.CloudGuard.get_data_mask_rule(data_mask_rule_id=test_data_mask_rule_oci_cloud_guard_data_mask_rule["id"])
    ```


    :param _builtins.str data_mask_rule_id: OCID of the data mask rule
    """
    __args__ = dict()
    __args__['dataMaskRuleId'] = data_mask_rule_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:CloudGuard/getDataMaskRule:getDataMaskRule', __args__, opts=opts, typ=GetDataMaskRuleResult)
    return __ret__.apply(lambda __response__: GetDataMaskRuleResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        data_mask_categories=pulumi.get(__response__, 'data_mask_categories'),
        data_mask_rule_id=pulumi.get(__response__, 'data_mask_rule_id'),
        data_mask_rule_status=pulumi.get(__response__, 'data_mask_rule_status'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        iam_group_id=pulumi.get(__response__, 'iam_group_id'),
        id=pulumi.get(__response__, 'id'),
        lifecyle_details=pulumi.get(__response__, 'lifecyle_details'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        target_selecteds=pulumi.get(__response__, 'target_selecteds'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
