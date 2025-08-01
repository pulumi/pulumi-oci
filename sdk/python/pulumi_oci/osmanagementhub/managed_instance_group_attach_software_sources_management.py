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

__all__ = ['ManagedInstanceGroupAttachSoftwareSourcesManagementArgs', 'ManagedInstanceGroupAttachSoftwareSourcesManagement']

@pulumi.input_type
class ManagedInstanceGroupAttachSoftwareSourcesManagementArgs:
    def __init__(__self__, *,
                 managed_instance_group_id: pulumi.Input[_builtins.str],
                 software_sources: pulumi.Input[Sequence[pulumi.Input[_builtins.str]]],
                 work_request_details: Optional[pulumi.Input['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs']] = None):
        """
        The set of arguments for constructing a ManagedInstanceGroupAttachSoftwareSourcesManagement resource.
        :param pulumi.Input[_builtins.str] managed_instance_group_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] software_sources: List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the group.
        :param pulumi.Input['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs'] work_request_details: Provides the name and description of the job.
        """
        pulumi.set(__self__, "managed_instance_group_id", managed_instance_group_id)
        pulumi.set(__self__, "software_sources", software_sources)
        if work_request_details is not None:
            pulumi.set(__self__, "work_request_details", work_request_details)

    @_builtins.property
    @pulumi.getter(name="managedInstanceGroupId")
    def managed_instance_group_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        """
        return pulumi.get(self, "managed_instance_group_id")

    @managed_instance_group_id.setter
    def managed_instance_group_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "managed_instance_group_id", value)

    @_builtins.property
    @pulumi.getter(name="softwareSources")
    def software_sources(self) -> pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]:
        """
        List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the group.
        """
        return pulumi.get(self, "software_sources")

    @software_sources.setter
    def software_sources(self, value: pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]):
        pulumi.set(self, "software_sources", value)

    @_builtins.property
    @pulumi.getter(name="workRequestDetails")
    def work_request_details(self) -> Optional[pulumi.Input['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs']]:
        """
        Provides the name and description of the job.
        """
        return pulumi.get(self, "work_request_details")

    @work_request_details.setter
    def work_request_details(self, value: Optional[pulumi.Input['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs']]):
        pulumi.set(self, "work_request_details", value)


@pulumi.input_type
class _ManagedInstanceGroupAttachSoftwareSourcesManagementState:
    def __init__(__self__, *,
                 managed_instance_group_id: Optional[pulumi.Input[_builtins.str]] = None,
                 software_sources: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 work_request_details: Optional[pulumi.Input['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs']] = None):
        """
        Input properties used for looking up and filtering ManagedInstanceGroupAttachSoftwareSourcesManagement resources.
        :param pulumi.Input[_builtins.str] managed_instance_group_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] software_sources: List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the group.
        :param pulumi.Input['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs'] work_request_details: Provides the name and description of the job.
        """
        if managed_instance_group_id is not None:
            pulumi.set(__self__, "managed_instance_group_id", managed_instance_group_id)
        if software_sources is not None:
            pulumi.set(__self__, "software_sources", software_sources)
        if work_request_details is not None:
            pulumi.set(__self__, "work_request_details", work_request_details)

    @_builtins.property
    @pulumi.getter(name="managedInstanceGroupId")
    def managed_instance_group_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        """
        return pulumi.get(self, "managed_instance_group_id")

    @managed_instance_group_id.setter
    def managed_instance_group_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "managed_instance_group_id", value)

    @_builtins.property
    @pulumi.getter(name="softwareSources")
    def software_sources(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the group.
        """
        return pulumi.get(self, "software_sources")

    @software_sources.setter
    def software_sources(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "software_sources", value)

    @_builtins.property
    @pulumi.getter(name="workRequestDetails")
    def work_request_details(self) -> Optional[pulumi.Input['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs']]:
        """
        Provides the name and description of the job.
        """
        return pulumi.get(self, "work_request_details")

    @work_request_details.setter
    def work_request_details(self, value: Optional[pulumi.Input['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs']]):
        pulumi.set(self, "work_request_details", value)


@pulumi.type_token("oci:OsManagementHub/managedInstanceGroupAttachSoftwareSourcesManagement:ManagedInstanceGroupAttachSoftwareSourcesManagement")
class ManagedInstanceGroupAttachSoftwareSourcesManagement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 managed_instance_group_id: Optional[pulumi.Input[_builtins.str]] = None,
                 software_sources: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 work_request_details: Optional[pulumi.Input[Union['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs', 'ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgsDict']]] = None,
                 __props__=None):
        """
        This resource provides the Managed Instance Group Attach Software Sources Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Attaches software sources to the specified managed instance group. The software sources must be compatible with the type of instances in the group.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_managed_instance_group_attach_software_sources_management = oci.osmanagementhub.ManagedInstanceGroupAttachSoftwareSourcesManagement("test_managed_instance_group_attach_software_sources_management",
            managed_instance_group_id=test_managed_instance_group["id"],
            software_sources=managed_instance_group_attach_software_sources_management_software_sources,
            work_request_details={
                "description": managed_instance_group_attach_software_sources_management_work_request_details_description,
                "display_name": managed_instance_group_attach_software_sources_management_work_request_details_display_name,
            })
        ```

        ## Import

        ManagedInstanceGroupAttachSoftwareSourcesManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/managedInstanceGroupAttachSoftwareSourcesManagement:ManagedInstanceGroupAttachSoftwareSourcesManagement test_managed_instance_group_attach_software_sources_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] managed_instance_group_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] software_sources: List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the group.
        :param pulumi.Input[Union['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs', 'ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgsDict']] work_request_details: Provides the name and description of the job.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ManagedInstanceGroupAttachSoftwareSourcesManagementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Managed Instance Group Attach Software Sources Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Attaches software sources to the specified managed instance group. The software sources must be compatible with the type of instances in the group.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_managed_instance_group_attach_software_sources_management = oci.osmanagementhub.ManagedInstanceGroupAttachSoftwareSourcesManagement("test_managed_instance_group_attach_software_sources_management",
            managed_instance_group_id=test_managed_instance_group["id"],
            software_sources=managed_instance_group_attach_software_sources_management_software_sources,
            work_request_details={
                "description": managed_instance_group_attach_software_sources_management_work_request_details_description,
                "display_name": managed_instance_group_attach_software_sources_management_work_request_details_display_name,
            })
        ```

        ## Import

        ManagedInstanceGroupAttachSoftwareSourcesManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/managedInstanceGroupAttachSoftwareSourcesManagement:ManagedInstanceGroupAttachSoftwareSourcesManagement test_managed_instance_group_attach_software_sources_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param ManagedInstanceGroupAttachSoftwareSourcesManagementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ManagedInstanceGroupAttachSoftwareSourcesManagementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 managed_instance_group_id: Optional[pulumi.Input[_builtins.str]] = None,
                 software_sources: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 work_request_details: Optional[pulumi.Input[Union['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs', 'ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgsDict']]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ManagedInstanceGroupAttachSoftwareSourcesManagementArgs.__new__(ManagedInstanceGroupAttachSoftwareSourcesManagementArgs)

            if managed_instance_group_id is None and not opts.urn:
                raise TypeError("Missing required property 'managed_instance_group_id'")
            __props__.__dict__["managed_instance_group_id"] = managed_instance_group_id
            if software_sources is None and not opts.urn:
                raise TypeError("Missing required property 'software_sources'")
            __props__.__dict__["software_sources"] = software_sources
            __props__.__dict__["work_request_details"] = work_request_details
        super(ManagedInstanceGroupAttachSoftwareSourcesManagement, __self__).__init__(
            'oci:OsManagementHub/managedInstanceGroupAttachSoftwareSourcesManagement:ManagedInstanceGroupAttachSoftwareSourcesManagement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            managed_instance_group_id: Optional[pulumi.Input[_builtins.str]] = None,
            software_sources: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
            work_request_details: Optional[pulumi.Input[Union['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs', 'ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgsDict']]] = None) -> 'ManagedInstanceGroupAttachSoftwareSourcesManagement':
        """
        Get an existing ManagedInstanceGroupAttachSoftwareSourcesManagement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] managed_instance_group_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] software_sources: List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the group.
        :param pulumi.Input[Union['ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs', 'ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgsDict']] work_request_details: Provides the name and description of the job.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ManagedInstanceGroupAttachSoftwareSourcesManagementState.__new__(_ManagedInstanceGroupAttachSoftwareSourcesManagementState)

        __props__.__dict__["managed_instance_group_id"] = managed_instance_group_id
        __props__.__dict__["software_sources"] = software_sources
        __props__.__dict__["work_request_details"] = work_request_details
        return ManagedInstanceGroupAttachSoftwareSourcesManagement(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="managedInstanceGroupId")
    def managed_instance_group_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        """
        return pulumi.get(self, "managed_instance_group_id")

    @_builtins.property
    @pulumi.getter(name="softwareSources")
    def software_sources(self) -> pulumi.Output[Sequence[_builtins.str]]:
        """
        List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the group.
        """
        return pulumi.get(self, "software_sources")

    @_builtins.property
    @pulumi.getter(name="workRequestDetails")
    def work_request_details(self) -> pulumi.Output['outputs.ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetails']:
        """
        Provides the name and description of the job.
        """
        return pulumi.get(self, "work_request_details")

