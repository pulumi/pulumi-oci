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

__all__ = ['ExternalMySqlDatabaseArgs', 'ExternalMySqlDatabase']

@pulumi.input_type
class ExternalMySqlDatabaseArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[_builtins.str],
                 db_name: pulumi.Input[_builtins.str]):
        """
        The set of arguments for constructing a ExternalMySqlDatabase resource.
        :param pulumi.Input[_builtins.str] compartment_id: OCID of compartment for the External MySQL Database.
        :param pulumi.Input[_builtins.str] db_name: (Updatable) Name of the External MySQL Database.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "db_name", db_name)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[_builtins.str]:
        """
        OCID of compartment for the External MySQL Database.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="dbName")
    def db_name(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) Name of the External MySQL Database.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "db_name")

    @db_name.setter
    def db_name(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "db_name", value)


@pulumi.input_type
class _ExternalMySqlDatabaseState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 db_name: Optional[pulumi.Input[_builtins.str]] = None,
                 external_database_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering ExternalMySqlDatabase resources.
        :param pulumi.Input[_builtins.str] compartment_id: OCID of compartment for the External MySQL Database.
        :param pulumi.Input[_builtins.str] db_name: (Updatable) Name of the External MySQL Database.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] external_database_id: OCID of External MySQL Database.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if db_name is not None:
            pulumi.set(__self__, "db_name", db_name)
        if external_database_id is not None:
            pulumi.set(__self__, "external_database_id", external_database_id)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        OCID of compartment for the External MySQL Database.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="dbName")
    def db_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Name of the External MySQL Database.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "db_name")

    @db_name.setter
    def db_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "db_name", value)

    @_builtins.property
    @pulumi.getter(name="externalDatabaseId")
    def external_database_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        OCID of External MySQL Database.
        """
        return pulumi.get(self, "external_database_id")

    @external_database_id.setter
    def external_database_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "external_database_id", value)


@pulumi.type_token("oci:DatabaseManagement/externalMySqlDatabase:ExternalMySqlDatabase")
class ExternalMySqlDatabase(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 db_name: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the External My Sql Database resource in Oracle Cloud Infrastructure Database Management service.

        Creates an external MySQL database.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_external_my_sql_database = oci.databasemanagement.ExternalMySqlDatabase("test_external_my_sql_database",
            compartment_id=compartment_id,
            db_name=external_my_sql_database_db_name)
        ```

        ## Import

        ExternalMySqlDatabases can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:DatabaseManagement/externalMySqlDatabase:ExternalMySqlDatabase test_external_my_sql_database "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: OCID of compartment for the External MySQL Database.
        :param pulumi.Input[_builtins.str] db_name: (Updatable) Name of the External MySQL Database.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ExternalMySqlDatabaseArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the External My Sql Database resource in Oracle Cloud Infrastructure Database Management service.

        Creates an external MySQL database.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_external_my_sql_database = oci.databasemanagement.ExternalMySqlDatabase("test_external_my_sql_database",
            compartment_id=compartment_id,
            db_name=external_my_sql_database_db_name)
        ```

        ## Import

        ExternalMySqlDatabases can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:DatabaseManagement/externalMySqlDatabase:ExternalMySqlDatabase test_external_my_sql_database "id"
        ```

        :param str resource_name: The name of the resource.
        :param ExternalMySqlDatabaseArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ExternalMySqlDatabaseArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 db_name: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ExternalMySqlDatabaseArgs.__new__(ExternalMySqlDatabaseArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            if db_name is None and not opts.urn:
                raise TypeError("Missing required property 'db_name'")
            __props__.__dict__["db_name"] = db_name
            __props__.__dict__["external_database_id"] = None
        super(ExternalMySqlDatabase, __self__).__init__(
            'oci:DatabaseManagement/externalMySqlDatabase:ExternalMySqlDatabase',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
            db_name: Optional[pulumi.Input[_builtins.str]] = None,
            external_database_id: Optional[pulumi.Input[_builtins.str]] = None) -> 'ExternalMySqlDatabase':
        """
        Get an existing ExternalMySqlDatabase resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: OCID of compartment for the External MySQL Database.
        :param pulumi.Input[_builtins.str] db_name: (Updatable) Name of the External MySQL Database.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] external_database_id: OCID of External MySQL Database.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ExternalMySqlDatabaseState.__new__(_ExternalMySqlDatabaseState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["db_name"] = db_name
        __props__.__dict__["external_database_id"] = external_database_id
        return ExternalMySqlDatabase(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        OCID of compartment for the External MySQL Database.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="dbName")
    def db_name(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Name of the External MySQL Database.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "db_name")

    @_builtins.property
    @pulumi.getter(name="externalDatabaseId")
    def external_database_id(self) -> pulumi.Output[_builtins.str]:
        """
        OCID of External MySQL Database.
        """
        return pulumi.get(self, "external_database_id")

