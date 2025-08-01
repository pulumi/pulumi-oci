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
    'GetOrganizationResult',
    'AwaitableGetOrganizationResult',
    'get_organization',
    'get_organization_output',
]

@pulumi.output_type
class GetOrganizationResult:
    """
    A collection of values returned by getOrganization.
    """
    def __init__(__self__, compartment_id=None, default_ucm_subscription_id=None, display_name=None, id=None, organization_id=None, parent_name=None, state=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if default_ucm_subscription_id and not isinstance(default_ucm_subscription_id, str):
            raise TypeError("Expected argument 'default_ucm_subscription_id' to be a str")
        pulumi.set(__self__, "default_ucm_subscription_id", default_ucm_subscription_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if organization_id and not isinstance(organization_id, str):
            raise TypeError("Expected argument 'organization_id' to be a str")
        pulumi.set(__self__, "organization_id", organization_id)
        if parent_name and not isinstance(parent_name, str):
            raise TypeError("Expected argument 'parent_name' to be a str")
        pulumi.set(__self__, "parent_name", parent_name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
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
        OCID of the compartment containing the organization. Always a tenancy OCID.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="defaultUcmSubscriptionId")
    def default_ucm_subscription_id(self) -> _builtins.str:
        """
        OCID of the default Universal Credits Model subscription. Any tenancy joining the organization will automatically get assigned this subscription, if a subscription is not explictly assigned.
        """
        return pulumi.get(self, "default_ucm_subscription_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A display name for the organization. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="organizationId")
    def organization_id(self) -> _builtins.str:
        return pulumi.get(self, "organization_id")

    @_builtins.property
    @pulumi.getter(name="parentName")
    def parent_name(self) -> _builtins.str:
        """
        The name of the tenancy that is the organization parent.
        """
        return pulumi.get(self, "parent_name")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        Lifecycle state of the organization.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Date and time when the organization was created.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        Date and time when the organization was last updated.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetOrganizationResult(GetOrganizationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetOrganizationResult(
            compartment_id=self.compartment_id,
            default_ucm_subscription_id=self.default_ucm_subscription_id,
            display_name=self.display_name,
            id=self.id,
            organization_id=self.organization_id,
            parent_name=self.parent_name,
            state=self.state,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_organization(organization_id: Optional[_builtins.str] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetOrganizationResult:
    """
    This data source provides details about a specific Organization resource in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.

    Gets information about the organization.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_organization = oci.Tenantmanagercontrolplane.get_organization(organization_id=test_organization_oci_tenantmanagercontrolplane_organization["id"])
    ```


    :param _builtins.str organization_id: OCID of the organization to retrieve.
    """
    __args__ = dict()
    __args__['organizationId'] = organization_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Tenantmanagercontrolplane/getOrganization:getOrganization', __args__, opts=opts, typ=GetOrganizationResult).value

    return AwaitableGetOrganizationResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        default_ucm_subscription_id=pulumi.get(__ret__, 'default_ucm_subscription_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        id=pulumi.get(__ret__, 'id'),
        organization_id=pulumi.get(__ret__, 'organization_id'),
        parent_name=pulumi.get(__ret__, 'parent_name'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_organization_output(organization_id: Optional[pulumi.Input[_builtins.str]] = None,
                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetOrganizationResult]:
    """
    This data source provides details about a specific Organization resource in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.

    Gets information about the organization.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_organization = oci.Tenantmanagercontrolplane.get_organization(organization_id=test_organization_oci_tenantmanagercontrolplane_organization["id"])
    ```


    :param _builtins.str organization_id: OCID of the organization to retrieve.
    """
    __args__ = dict()
    __args__['organizationId'] = organization_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Tenantmanagercontrolplane/getOrganization:getOrganization', __args__, opts=opts, typ=GetOrganizationResult)
    return __ret__.apply(lambda __response__: GetOrganizationResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        default_ucm_subscription_id=pulumi.get(__response__, 'default_ucm_subscription_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        id=pulumi.get(__response__, 'id'),
        organization_id=pulumi.get(__response__, 'organization_id'),
        parent_name=pulumi.get(__response__, 'parent_name'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
