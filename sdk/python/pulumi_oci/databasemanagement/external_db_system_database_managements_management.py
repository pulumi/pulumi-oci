# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['ExternalDbSystemDatabaseManagementsManagementArgs', 'ExternalDbSystemDatabaseManagementsManagement']

@pulumi.input_type
class ExternalDbSystemDatabaseManagementsManagementArgs:
    def __init__(__self__, *,
                 enable_database_management: pulumi.Input[bool],
                 external_db_system_id: pulumi.Input[str],
                 license_model: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a ExternalDbSystemDatabaseManagementsManagement resource.
        :param pulumi.Input[bool] enable_database_management: (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        :param pulumi.Input[str] external_db_system_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        :param pulumi.Input[str] license_model: The Oracle license model that applies to the external database.
        """
        pulumi.set(__self__, "enable_database_management", enable_database_management)
        pulumi.set(__self__, "external_db_system_id", external_db_system_id)
        if license_model is not None:
            pulumi.set(__self__, "license_model", license_model)

    @property
    @pulumi.getter(name="enableDatabaseManagement")
    def enable_database_management(self) -> pulumi.Input[bool]:
        """
        (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        """
        return pulumi.get(self, "enable_database_management")

    @enable_database_management.setter
    def enable_database_management(self, value: pulumi.Input[bool]):
        pulumi.set(self, "enable_database_management", value)

    @property
    @pulumi.getter(name="externalDbSystemId")
    def external_db_system_id(self) -> pulumi.Input[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        """
        return pulumi.get(self, "external_db_system_id")

    @external_db_system_id.setter
    def external_db_system_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "external_db_system_id", value)

    @property
    @pulumi.getter(name="licenseModel")
    def license_model(self) -> Optional[pulumi.Input[str]]:
        """
        The Oracle license model that applies to the external database.
        """
        return pulumi.get(self, "license_model")

    @license_model.setter
    def license_model(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "license_model", value)


@pulumi.input_type
class _ExternalDbSystemDatabaseManagementsManagementState:
    def __init__(__self__, *,
                 enable_database_management: Optional[pulumi.Input[bool]] = None,
                 external_db_system_id: Optional[pulumi.Input[str]] = None,
                 license_model: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering ExternalDbSystemDatabaseManagementsManagement resources.
        :param pulumi.Input[bool] enable_database_management: (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        :param pulumi.Input[str] external_db_system_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        :param pulumi.Input[str] license_model: The Oracle license model that applies to the external database.
        """
        if enable_database_management is not None:
            pulumi.set(__self__, "enable_database_management", enable_database_management)
        if external_db_system_id is not None:
            pulumi.set(__self__, "external_db_system_id", external_db_system_id)
        if license_model is not None:
            pulumi.set(__self__, "license_model", license_model)

    @property
    @pulumi.getter(name="enableDatabaseManagement")
    def enable_database_management(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        """
        return pulumi.get(self, "enable_database_management")

    @enable_database_management.setter
    def enable_database_management(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_database_management", value)

    @property
    @pulumi.getter(name="externalDbSystemId")
    def external_db_system_id(self) -> Optional[pulumi.Input[str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        """
        return pulumi.get(self, "external_db_system_id")

    @external_db_system_id.setter
    def external_db_system_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "external_db_system_id", value)

    @property
    @pulumi.getter(name="licenseModel")
    def license_model(self) -> Optional[pulumi.Input[str]]:
        """
        The Oracle license model that applies to the external database.
        """
        return pulumi.get(self, "license_model")

    @license_model.setter
    def license_model(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "license_model", value)


class ExternalDbSystemDatabaseManagementsManagement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 enable_database_management: Optional[pulumi.Input[bool]] = None,
                 external_db_system_id: Optional[pulumi.Input[str]] = None,
                 license_model: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the External Db System Database Managements Management resource in Oracle Cloud Infrastructure Database Management service.

        Enables Database Management service for all the components of the specified
        external DB system (except databases).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_external_db_system_database_managements_management = oci.database_management.ExternalDbSystemDatabaseManagementsManagement("testExternalDbSystemDatabaseManagementsManagement",
            external_db_system_id=oci_database_management_external_db_system["test_external_db_system"]["id"],
            enable_database_management=var["enable_database_management"],
            license_model=var["external_db_system_database_managements_management_license_model"])
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[bool] enable_database_management: (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        :param pulumi.Input[str] external_db_system_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        :param pulumi.Input[str] license_model: The Oracle license model that applies to the external database.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ExternalDbSystemDatabaseManagementsManagementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the External Db System Database Managements Management resource in Oracle Cloud Infrastructure Database Management service.

        Enables Database Management service for all the components of the specified
        external DB system (except databases).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_external_db_system_database_managements_management = oci.database_management.ExternalDbSystemDatabaseManagementsManagement("testExternalDbSystemDatabaseManagementsManagement",
            external_db_system_id=oci_database_management_external_db_system["test_external_db_system"]["id"],
            enable_database_management=var["enable_database_management"],
            license_model=var["external_db_system_database_managements_management_license_model"])
        ```

        :param str resource_name: The name of the resource.
        :param ExternalDbSystemDatabaseManagementsManagementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ExternalDbSystemDatabaseManagementsManagementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 enable_database_management: Optional[pulumi.Input[bool]] = None,
                 external_db_system_id: Optional[pulumi.Input[str]] = None,
                 license_model: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ExternalDbSystemDatabaseManagementsManagementArgs.__new__(ExternalDbSystemDatabaseManagementsManagementArgs)

            if enable_database_management is None and not opts.urn:
                raise TypeError("Missing required property 'enable_database_management'")
            __props__.__dict__["enable_database_management"] = enable_database_management
            if external_db_system_id is None and not opts.urn:
                raise TypeError("Missing required property 'external_db_system_id'")
            __props__.__dict__["external_db_system_id"] = external_db_system_id
            __props__.__dict__["license_model"] = license_model
        super(ExternalDbSystemDatabaseManagementsManagement, __self__).__init__(
            'oci:DatabaseManagement/externalDbSystemDatabaseManagementsManagement:ExternalDbSystemDatabaseManagementsManagement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            enable_database_management: Optional[pulumi.Input[bool]] = None,
            external_db_system_id: Optional[pulumi.Input[str]] = None,
            license_model: Optional[pulumi.Input[str]] = None) -> 'ExternalDbSystemDatabaseManagementsManagement':
        """
        Get an existing ExternalDbSystemDatabaseManagementsManagement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[bool] enable_database_management: (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        :param pulumi.Input[str] external_db_system_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        :param pulumi.Input[str] license_model: The Oracle license model that applies to the external database.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ExternalDbSystemDatabaseManagementsManagementState.__new__(_ExternalDbSystemDatabaseManagementsManagementState)

        __props__.__dict__["enable_database_management"] = enable_database_management
        __props__.__dict__["external_db_system_id"] = external_db_system_id
        __props__.__dict__["license_model"] = license_model
        return ExternalDbSystemDatabaseManagementsManagement(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="enableDatabaseManagement")
    def enable_database_management(self) -> pulumi.Output[bool]:
        """
        (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        """
        return pulumi.get(self, "enable_database_management")

    @property
    @pulumi.getter(name="externalDbSystemId")
    def external_db_system_id(self) -> pulumi.Output[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        """
        return pulumi.get(self, "external_db_system_id")

    @property
    @pulumi.getter(name="licenseModel")
    def license_model(self) -> pulumi.Output[str]:
        """
        The Oracle license model that applies to the external database.
        """
        return pulumi.get(self, "license_model")
