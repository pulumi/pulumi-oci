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
    'GetSecurityPolicyReportDatabaseTableAccessEntryResult',
    'AwaitableGetSecurityPolicyReportDatabaseTableAccessEntryResult',
    'get_security_policy_report_database_table_access_entry',
    'get_security_policy_report_database_table_access_entry_output',
]

@pulumi.output_type
class GetSecurityPolicyReportDatabaseTableAccessEntryResult:
    """
    A collection of values returned by getSecurityPolicyReportDatabaseTableAccessEntry.
    """
    def __init__(__self__, access_through_object=None, access_type=None, are_all_tables_accessible=None, column_name=None, database_table_access_entry_key=None, grant_from_role=None, grantee=None, grantor=None, id=None, is_access_constrained_by_database_vault=None, is_access_constrained_by_label_security=None, is_access_constrained_by_real_application_security=None, is_access_constrained_by_redaction=None, is_access_constrained_by_sql_firewall=None, is_access_constrained_by_view=None, is_access_constrained_by_virtual_private_database=None, is_sensitive=None, key=None, privilege=None, privilege_grantable=None, privilege_type=None, security_policy_report_id=None, table_name=None, table_schema=None, target_id=None):
        if access_through_object and not isinstance(access_through_object, str):
            raise TypeError("Expected argument 'access_through_object' to be a str")
        pulumi.set(__self__, "access_through_object", access_through_object)
        if access_type and not isinstance(access_type, str):
            raise TypeError("Expected argument 'access_type' to be a str")
        pulumi.set(__self__, "access_type", access_type)
        if are_all_tables_accessible and not isinstance(are_all_tables_accessible, bool):
            raise TypeError("Expected argument 'are_all_tables_accessible' to be a bool")
        pulumi.set(__self__, "are_all_tables_accessible", are_all_tables_accessible)
        if column_name and not isinstance(column_name, str):
            raise TypeError("Expected argument 'column_name' to be a str")
        pulumi.set(__self__, "column_name", column_name)
        if database_table_access_entry_key and not isinstance(database_table_access_entry_key, str):
            raise TypeError("Expected argument 'database_table_access_entry_key' to be a str")
        pulumi.set(__self__, "database_table_access_entry_key", database_table_access_entry_key)
        if grant_from_role and not isinstance(grant_from_role, str):
            raise TypeError("Expected argument 'grant_from_role' to be a str")
        pulumi.set(__self__, "grant_from_role", grant_from_role)
        if grantee and not isinstance(grantee, str):
            raise TypeError("Expected argument 'grantee' to be a str")
        pulumi.set(__self__, "grantee", grantee)
        if grantor and not isinstance(grantor, str):
            raise TypeError("Expected argument 'grantor' to be a str")
        pulumi.set(__self__, "grantor", grantor)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_access_constrained_by_database_vault and not isinstance(is_access_constrained_by_database_vault, bool):
            raise TypeError("Expected argument 'is_access_constrained_by_database_vault' to be a bool")
        pulumi.set(__self__, "is_access_constrained_by_database_vault", is_access_constrained_by_database_vault)
        if is_access_constrained_by_label_security and not isinstance(is_access_constrained_by_label_security, bool):
            raise TypeError("Expected argument 'is_access_constrained_by_label_security' to be a bool")
        pulumi.set(__self__, "is_access_constrained_by_label_security", is_access_constrained_by_label_security)
        if is_access_constrained_by_real_application_security and not isinstance(is_access_constrained_by_real_application_security, bool):
            raise TypeError("Expected argument 'is_access_constrained_by_real_application_security' to be a bool")
        pulumi.set(__self__, "is_access_constrained_by_real_application_security", is_access_constrained_by_real_application_security)
        if is_access_constrained_by_redaction and not isinstance(is_access_constrained_by_redaction, bool):
            raise TypeError("Expected argument 'is_access_constrained_by_redaction' to be a bool")
        pulumi.set(__self__, "is_access_constrained_by_redaction", is_access_constrained_by_redaction)
        if is_access_constrained_by_sql_firewall and not isinstance(is_access_constrained_by_sql_firewall, bool):
            raise TypeError("Expected argument 'is_access_constrained_by_sql_firewall' to be a bool")
        pulumi.set(__self__, "is_access_constrained_by_sql_firewall", is_access_constrained_by_sql_firewall)
        if is_access_constrained_by_view and not isinstance(is_access_constrained_by_view, bool):
            raise TypeError("Expected argument 'is_access_constrained_by_view' to be a bool")
        pulumi.set(__self__, "is_access_constrained_by_view", is_access_constrained_by_view)
        if is_access_constrained_by_virtual_private_database and not isinstance(is_access_constrained_by_virtual_private_database, bool):
            raise TypeError("Expected argument 'is_access_constrained_by_virtual_private_database' to be a bool")
        pulumi.set(__self__, "is_access_constrained_by_virtual_private_database", is_access_constrained_by_virtual_private_database)
        if is_sensitive and not isinstance(is_sensitive, bool):
            raise TypeError("Expected argument 'is_sensitive' to be a bool")
        pulumi.set(__self__, "is_sensitive", is_sensitive)
        if key and not isinstance(key, str):
            raise TypeError("Expected argument 'key' to be a str")
        pulumi.set(__self__, "key", key)
        if privilege and not isinstance(privilege, str):
            raise TypeError("Expected argument 'privilege' to be a str")
        pulumi.set(__self__, "privilege", privilege)
        if privilege_grantable and not isinstance(privilege_grantable, str):
            raise TypeError("Expected argument 'privilege_grantable' to be a str")
        pulumi.set(__self__, "privilege_grantable", privilege_grantable)
        if privilege_type and not isinstance(privilege_type, str):
            raise TypeError("Expected argument 'privilege_type' to be a str")
        pulumi.set(__self__, "privilege_type", privilege_type)
        if security_policy_report_id and not isinstance(security_policy_report_id, str):
            raise TypeError("Expected argument 'security_policy_report_id' to be a str")
        pulumi.set(__self__, "security_policy_report_id", security_policy_report_id)
        if table_name and not isinstance(table_name, str):
            raise TypeError("Expected argument 'table_name' to be a str")
        pulumi.set(__self__, "table_name", table_name)
        if table_schema and not isinstance(table_schema, str):
            raise TypeError("Expected argument 'table_schema' to be a str")
        pulumi.set(__self__, "table_schema", table_schema)
        if target_id and not isinstance(target_id, str):
            raise TypeError("Expected argument 'target_id' to be a str")
        pulumi.set(__self__, "target_id", target_id)

    @_builtins.property
    @pulumi.getter(name="accessThroughObject")
    def access_through_object(self) -> _builtins.str:
        """
        A non-null value in this field indicates the object through which user has access to table, possible values could be table or view.
        """
        return pulumi.get(self, "access_through_object")

    @_builtins.property
    @pulumi.getter(name="accessType")
    def access_type(self) -> _builtins.str:
        """
        The type of the access the user has on the table, there can be one or more from SELECT, UPDATE, INSERT, OWNER or DELETE.
        """
        return pulumi.get(self, "access_type")

    @_builtins.property
    @pulumi.getter(name="areAllTablesAccessible")
    def are_all_tables_accessible(self) -> _builtins.bool:
        """
        Indicates whether the user has access to all the tables in the schema.
        """
        return pulumi.get(self, "are_all_tables_accessible")

    @_builtins.property
    @pulumi.getter(name="columnName")
    def column_name(self) -> _builtins.str:
        """
        If there are column level privileges on a table or view.
        """
        return pulumi.get(self, "column_name")

    @_builtins.property
    @pulumi.getter(name="databaseTableAccessEntryKey")
    def database_table_access_entry_key(self) -> _builtins.str:
        return pulumi.get(self, "database_table_access_entry_key")

    @_builtins.property
    @pulumi.getter(name="grantFromRole")
    def grant_from_role(self) -> _builtins.str:
        """
        This can be empty in case of direct grant, in case of indirect grant, this attribute displays the name of the  role which is granted to the user though which the user has access to the table.
        """
        return pulumi.get(self, "grant_from_role")

    @_builtins.property
    @pulumi.getter
    def grantee(self) -> _builtins.str:
        """
        Grantee is the user who can access the table
        """
        return pulumi.get(self, "grantee")

    @_builtins.property
    @pulumi.getter
    def grantor(self) -> _builtins.str:
        """
        The one who granted this privilege.
        """
        return pulumi.get(self, "grantor")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isAccessConstrainedByDatabaseVault")
    def is_access_constrained_by_database_vault(self) -> _builtins.bool:
        """
        Indicates whether the table access is constrained via Oracle Database Vault.
        """
        return pulumi.get(self, "is_access_constrained_by_database_vault")

    @_builtins.property
    @pulumi.getter(name="isAccessConstrainedByLabelSecurity")
    def is_access_constrained_by_label_security(self) -> _builtins.bool:
        """
        Indicates whether the table access is constrained via Oracle Label Security.
        """
        return pulumi.get(self, "is_access_constrained_by_label_security")

    @_builtins.property
    @pulumi.getter(name="isAccessConstrainedByRealApplicationSecurity")
    def is_access_constrained_by_real_application_security(self) -> _builtins.bool:
        """
        Indicates whether the table access is constrained via Real Application Security.
        """
        return pulumi.get(self, "is_access_constrained_by_real_application_security")

    @_builtins.property
    @pulumi.getter(name="isAccessConstrainedByRedaction")
    def is_access_constrained_by_redaction(self) -> _builtins.bool:
        """
        Indicates whether the table access is constrained via Oracle Data Redaction.
        """
        return pulumi.get(self, "is_access_constrained_by_redaction")

    @_builtins.property
    @pulumi.getter(name="isAccessConstrainedBySqlFirewall")
    def is_access_constrained_by_sql_firewall(self) -> _builtins.bool:
        """
        Indicates whether the table access is constrained via Oracle Database SQL Firewall.
        """
        return pulumi.get(self, "is_access_constrained_by_sql_firewall")

    @_builtins.property
    @pulumi.getter(name="isAccessConstrainedByView")
    def is_access_constrained_by_view(self) -> _builtins.bool:
        """
        Indicates whether the access is constrained on a table via a view.
        """
        return pulumi.get(self, "is_access_constrained_by_view")

    @_builtins.property
    @pulumi.getter(name="isAccessConstrainedByVirtualPrivateDatabase")
    def is_access_constrained_by_virtual_private_database(self) -> _builtins.bool:
        """
        Indicates whether the table access is constrained via Virtual Private Database.
        """
        return pulumi.get(self, "is_access_constrained_by_virtual_private_database")

    @_builtins.property
    @pulumi.getter(name="isSensitive")
    def is_sensitive(self) -> _builtins.bool:
        """
        Indicates whether the table is marked as sensitive.
        """
        return pulumi.get(self, "is_sensitive")

    @_builtins.property
    @pulumi.getter
    def key(self) -> _builtins.str:
        """
        The unique key that identifies the table access report. It is numeric and unique within a security policy report.
        """
        return pulumi.get(self, "key")

    @_builtins.property
    @pulumi.getter
    def privilege(self) -> _builtins.str:
        """
        Name of the privilege.
        """
        return pulumi.get(self, "privilege")

    @_builtins.property
    @pulumi.getter(name="privilegeGrantable")
    def privilege_grantable(self) -> _builtins.str:
        """
        Indicates whether the grantee can grant this privilege to other users. Privileges can be granted to a user or role with  GRANT_OPTION or ADMIN_OPTION
        """
        return pulumi.get(self, "privilege_grantable")

    @_builtins.property
    @pulumi.getter(name="privilegeType")
    def privilege_type(self) -> _builtins.str:
        """
        Type of the privilege user has, this includes System Privilege, Schema Privilege, Object Privilege, Column Privilege, Owner or Schema Privilege on a schema.
        """
        return pulumi.get(self, "privilege_type")

    @_builtins.property
    @pulumi.getter(name="securityPolicyReportId")
    def security_policy_report_id(self) -> _builtins.str:
        return pulumi.get(self, "security_policy_report_id")

    @_builtins.property
    @pulumi.getter(name="tableName")
    def table_name(self) -> _builtins.str:
        """
        The name of the database table the user has access to.
        """
        return pulumi.get(self, "table_name")

    @_builtins.property
    @pulumi.getter(name="tableSchema")
    def table_schema(self) -> _builtins.str:
        """
        The name of the schema the table belongs to.
        """
        return pulumi.get(self, "table_schema")

    @_builtins.property
    @pulumi.getter(name="targetId")
    def target_id(self) -> _builtins.str:
        """
        The OCID of the of the  target database.
        """
        return pulumi.get(self, "target_id")


class AwaitableGetSecurityPolicyReportDatabaseTableAccessEntryResult(GetSecurityPolicyReportDatabaseTableAccessEntryResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSecurityPolicyReportDatabaseTableAccessEntryResult(
            access_through_object=self.access_through_object,
            access_type=self.access_type,
            are_all_tables_accessible=self.are_all_tables_accessible,
            column_name=self.column_name,
            database_table_access_entry_key=self.database_table_access_entry_key,
            grant_from_role=self.grant_from_role,
            grantee=self.grantee,
            grantor=self.grantor,
            id=self.id,
            is_access_constrained_by_database_vault=self.is_access_constrained_by_database_vault,
            is_access_constrained_by_label_security=self.is_access_constrained_by_label_security,
            is_access_constrained_by_real_application_security=self.is_access_constrained_by_real_application_security,
            is_access_constrained_by_redaction=self.is_access_constrained_by_redaction,
            is_access_constrained_by_sql_firewall=self.is_access_constrained_by_sql_firewall,
            is_access_constrained_by_view=self.is_access_constrained_by_view,
            is_access_constrained_by_virtual_private_database=self.is_access_constrained_by_virtual_private_database,
            is_sensitive=self.is_sensitive,
            key=self.key,
            privilege=self.privilege,
            privilege_grantable=self.privilege_grantable,
            privilege_type=self.privilege_type,
            security_policy_report_id=self.security_policy_report_id,
            table_name=self.table_name,
            table_schema=self.table_schema,
            target_id=self.target_id)


def get_security_policy_report_database_table_access_entry(database_table_access_entry_key: Optional[_builtins.str] = None,
                                                           security_policy_report_id: Optional[_builtins.str] = None,
                                                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSecurityPolicyReportDatabaseTableAccessEntryResult:
    """
    This data source provides details about a specific Security Policy Report Database Table Access Entry resource in Oracle Cloud Infrastructure Data Safe service.

    Gets a database table access entry object by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_policy_report_database_table_access_entry = oci.DataSafe.get_security_policy_report_database_table_access_entry(database_table_access_entry_key=security_policy_report_database_table_access_entry_database_table_access_entry_key,
        security_policy_report_id=test_security_policy_report["id"])
    ```


    :param _builtins.str database_table_access_entry_key: The unique key that identifies the table access object. This is a system-generated identifier.
    :param _builtins.str security_policy_report_id: The OCID of the security policy report resource.
    """
    __args__ = dict()
    __args__['databaseTableAccessEntryKey'] = database_table_access_entry_key
    __args__['securityPolicyReportId'] = security_policy_report_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getSecurityPolicyReportDatabaseTableAccessEntry:getSecurityPolicyReportDatabaseTableAccessEntry', __args__, opts=opts, typ=GetSecurityPolicyReportDatabaseTableAccessEntryResult).value

    return AwaitableGetSecurityPolicyReportDatabaseTableAccessEntryResult(
        access_through_object=pulumi.get(__ret__, 'access_through_object'),
        access_type=pulumi.get(__ret__, 'access_type'),
        are_all_tables_accessible=pulumi.get(__ret__, 'are_all_tables_accessible'),
        column_name=pulumi.get(__ret__, 'column_name'),
        database_table_access_entry_key=pulumi.get(__ret__, 'database_table_access_entry_key'),
        grant_from_role=pulumi.get(__ret__, 'grant_from_role'),
        grantee=pulumi.get(__ret__, 'grantee'),
        grantor=pulumi.get(__ret__, 'grantor'),
        id=pulumi.get(__ret__, 'id'),
        is_access_constrained_by_database_vault=pulumi.get(__ret__, 'is_access_constrained_by_database_vault'),
        is_access_constrained_by_label_security=pulumi.get(__ret__, 'is_access_constrained_by_label_security'),
        is_access_constrained_by_real_application_security=pulumi.get(__ret__, 'is_access_constrained_by_real_application_security'),
        is_access_constrained_by_redaction=pulumi.get(__ret__, 'is_access_constrained_by_redaction'),
        is_access_constrained_by_sql_firewall=pulumi.get(__ret__, 'is_access_constrained_by_sql_firewall'),
        is_access_constrained_by_view=pulumi.get(__ret__, 'is_access_constrained_by_view'),
        is_access_constrained_by_virtual_private_database=pulumi.get(__ret__, 'is_access_constrained_by_virtual_private_database'),
        is_sensitive=pulumi.get(__ret__, 'is_sensitive'),
        key=pulumi.get(__ret__, 'key'),
        privilege=pulumi.get(__ret__, 'privilege'),
        privilege_grantable=pulumi.get(__ret__, 'privilege_grantable'),
        privilege_type=pulumi.get(__ret__, 'privilege_type'),
        security_policy_report_id=pulumi.get(__ret__, 'security_policy_report_id'),
        table_name=pulumi.get(__ret__, 'table_name'),
        table_schema=pulumi.get(__ret__, 'table_schema'),
        target_id=pulumi.get(__ret__, 'target_id'))
def get_security_policy_report_database_table_access_entry_output(database_table_access_entry_key: Optional[pulumi.Input[_builtins.str]] = None,
                                                                  security_policy_report_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                                  opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSecurityPolicyReportDatabaseTableAccessEntryResult]:
    """
    This data source provides details about a specific Security Policy Report Database Table Access Entry resource in Oracle Cloud Infrastructure Data Safe service.

    Gets a database table access entry object by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_policy_report_database_table_access_entry = oci.DataSafe.get_security_policy_report_database_table_access_entry(database_table_access_entry_key=security_policy_report_database_table_access_entry_database_table_access_entry_key,
        security_policy_report_id=test_security_policy_report["id"])
    ```


    :param _builtins.str database_table_access_entry_key: The unique key that identifies the table access object. This is a system-generated identifier.
    :param _builtins.str security_policy_report_id: The OCID of the security policy report resource.
    """
    __args__ = dict()
    __args__['databaseTableAccessEntryKey'] = database_table_access_entry_key
    __args__['securityPolicyReportId'] = security_policy_report_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getSecurityPolicyReportDatabaseTableAccessEntry:getSecurityPolicyReportDatabaseTableAccessEntry', __args__, opts=opts, typ=GetSecurityPolicyReportDatabaseTableAccessEntryResult)
    return __ret__.apply(lambda __response__: GetSecurityPolicyReportDatabaseTableAccessEntryResult(
        access_through_object=pulumi.get(__response__, 'access_through_object'),
        access_type=pulumi.get(__response__, 'access_type'),
        are_all_tables_accessible=pulumi.get(__response__, 'are_all_tables_accessible'),
        column_name=pulumi.get(__response__, 'column_name'),
        database_table_access_entry_key=pulumi.get(__response__, 'database_table_access_entry_key'),
        grant_from_role=pulumi.get(__response__, 'grant_from_role'),
        grantee=pulumi.get(__response__, 'grantee'),
        grantor=pulumi.get(__response__, 'grantor'),
        id=pulumi.get(__response__, 'id'),
        is_access_constrained_by_database_vault=pulumi.get(__response__, 'is_access_constrained_by_database_vault'),
        is_access_constrained_by_label_security=pulumi.get(__response__, 'is_access_constrained_by_label_security'),
        is_access_constrained_by_real_application_security=pulumi.get(__response__, 'is_access_constrained_by_real_application_security'),
        is_access_constrained_by_redaction=pulumi.get(__response__, 'is_access_constrained_by_redaction'),
        is_access_constrained_by_sql_firewall=pulumi.get(__response__, 'is_access_constrained_by_sql_firewall'),
        is_access_constrained_by_view=pulumi.get(__response__, 'is_access_constrained_by_view'),
        is_access_constrained_by_virtual_private_database=pulumi.get(__response__, 'is_access_constrained_by_virtual_private_database'),
        is_sensitive=pulumi.get(__response__, 'is_sensitive'),
        key=pulumi.get(__response__, 'key'),
        privilege=pulumi.get(__response__, 'privilege'),
        privilege_grantable=pulumi.get(__response__, 'privilege_grantable'),
        privilege_type=pulumi.get(__response__, 'privilege_type'),
        security_policy_report_id=pulumi.get(__response__, 'security_policy_report_id'),
        table_name=pulumi.get(__response__, 'table_name'),
        table_schema=pulumi.get(__response__, 'table_schema'),
        target_id=pulumi.get(__response__, 'target_id')))
