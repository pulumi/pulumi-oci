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

__all__ = [
    'GetFileSystemQuotaRulesResult',
    'AwaitableGetFileSystemQuotaRulesResult',
    'get_file_system_quota_rules',
    'get_file_system_quota_rules_output',
]

@pulumi.output_type
class GetFileSystemQuotaRulesResult:
    """
    A collection of values returned by getFileSystemQuotaRules.
    """
    def __init__(__self__, are_violators_only=None, file_system_id=None, filters=None, id=None, principal_id=None, principal_type=None, quota_rules=None):
        if are_violators_only and not isinstance(are_violators_only, bool):
            raise TypeError("Expected argument 'are_violators_only' to be a bool")
        pulumi.set(__self__, "are_violators_only", are_violators_only)
        if file_system_id and not isinstance(file_system_id, str):
            raise TypeError("Expected argument 'file_system_id' to be a str")
        pulumi.set(__self__, "file_system_id", file_system_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if principal_id and not isinstance(principal_id, int):
            raise TypeError("Expected argument 'principal_id' to be a int")
        pulumi.set(__self__, "principal_id", principal_id)
        if principal_type and not isinstance(principal_type, str):
            raise TypeError("Expected argument 'principal_type' to be a str")
        pulumi.set(__self__, "principal_type", principal_type)
        if quota_rules and not isinstance(quota_rules, list):
            raise TypeError("Expected argument 'quota_rules' to be a list")
        pulumi.set(__self__, "quota_rules", quota_rules)

    @_builtins.property
    @pulumi.getter(name="areViolatorsOnly")
    def are_violators_only(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "are_violators_only")

    @_builtins.property
    @pulumi.getter(name="fileSystemId")
    def file_system_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file System.
        """
        return pulumi.get(self, "file_system_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetFileSystemQuotaRulesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="principalId")
    def principal_id(self) -> Optional[_builtins.int]:
        """
        An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
        """
        return pulumi.get(self, "principal_id")

    @_builtins.property
    @pulumi.getter(name="principalType")
    def principal_type(self) -> _builtins.str:
        """
        The type of the owner of this quota rule and usage.
        """
        return pulumi.get(self, "principal_type")

    @_builtins.property
    @pulumi.getter(name="quotaRules")
    def quota_rules(self) -> Sequence['outputs.GetFileSystemQuotaRulesQuotaRuleResult']:
        """
        The list of quota_rules.
        """
        return pulumi.get(self, "quota_rules")


class AwaitableGetFileSystemQuotaRulesResult(GetFileSystemQuotaRulesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFileSystemQuotaRulesResult(
            are_violators_only=self.are_violators_only,
            file_system_id=self.file_system_id,
            filters=self.filters,
            id=self.id,
            principal_id=self.principal_id,
            principal_type=self.principal_type,
            quota_rules=self.quota_rules)


def get_file_system_quota_rules(are_violators_only: Optional[_builtins.bool] = None,
                                file_system_id: Optional[_builtins.str] = None,
                                filters: Optional[Sequence[Union['GetFileSystemQuotaRulesFilterArgs', 'GetFileSystemQuotaRulesFilterArgsDict']]] = None,
                                principal_id: Optional[_builtins.int] = None,
                                principal_type: Optional[_builtins.str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFileSystemQuotaRulesResult:
    """
    This data source provides the list of File System Quota Rules in Oracle Cloud Infrastructure File Storage service.

    List user or group usages and their quota rules by certain principal type.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_file_system_quota_rules = oci.FileStorage.get_file_system_quota_rules(file_system_id=test_file_system["id"],
        principal_type=file_system_quota_rule_principal_type,
        are_violators_only=file_system_quota_rule_are_violators_only,
        principal_id=test_principal["id"])
    ```


    :param _builtins.bool are_violators_only: An option to only display the users or groups that violate their quota rules. If `areViolatorsOnly` is false, the list result will display all the quota and usage report. If `areViolatorsOnly` is true, the list result will only display the quota and usage report for the users or groups that violate their quota rules.
    :param _builtins.str file_system_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
    :param _builtins.int principal_id: An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
    :param _builtins.str principal_type: The type of the owner of this quota rule and usage.
    """
    __args__ = dict()
    __args__['areViolatorsOnly'] = are_violators_only
    __args__['fileSystemId'] = file_system_id
    __args__['filters'] = filters
    __args__['principalId'] = principal_id
    __args__['principalType'] = principal_type
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:FileStorage/getFileSystemQuotaRules:getFileSystemQuotaRules', __args__, opts=opts, typ=GetFileSystemQuotaRulesResult).value

    return AwaitableGetFileSystemQuotaRulesResult(
        are_violators_only=pulumi.get(__ret__, 'are_violators_only'),
        file_system_id=pulumi.get(__ret__, 'file_system_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        principal_id=pulumi.get(__ret__, 'principal_id'),
        principal_type=pulumi.get(__ret__, 'principal_type'),
        quota_rules=pulumi.get(__ret__, 'quota_rules'))
def get_file_system_quota_rules_output(are_violators_only: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                                       file_system_id: Optional[pulumi.Input[_builtins.str]] = None,
                                       filters: Optional[pulumi.Input[Optional[Sequence[Union['GetFileSystemQuotaRulesFilterArgs', 'GetFileSystemQuotaRulesFilterArgsDict']]]]] = None,
                                       principal_id: Optional[pulumi.Input[Optional[_builtins.int]]] = None,
                                       principal_type: Optional[pulumi.Input[_builtins.str]] = None,
                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetFileSystemQuotaRulesResult]:
    """
    This data source provides the list of File System Quota Rules in Oracle Cloud Infrastructure File Storage service.

    List user or group usages and their quota rules by certain principal type.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_file_system_quota_rules = oci.FileStorage.get_file_system_quota_rules(file_system_id=test_file_system["id"],
        principal_type=file_system_quota_rule_principal_type,
        are_violators_only=file_system_quota_rule_are_violators_only,
        principal_id=test_principal["id"])
    ```


    :param _builtins.bool are_violators_only: An option to only display the users or groups that violate their quota rules. If `areViolatorsOnly` is false, the list result will display all the quota and usage report. If `areViolatorsOnly` is true, the list result will only display the quota and usage report for the users or groups that violate their quota rules.
    :param _builtins.str file_system_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
    :param _builtins.int principal_id: An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
    :param _builtins.str principal_type: The type of the owner of this quota rule and usage.
    """
    __args__ = dict()
    __args__['areViolatorsOnly'] = are_violators_only
    __args__['fileSystemId'] = file_system_id
    __args__['filters'] = filters
    __args__['principalId'] = principal_id
    __args__['principalType'] = principal_type
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:FileStorage/getFileSystemQuotaRules:getFileSystemQuotaRules', __args__, opts=opts, typ=GetFileSystemQuotaRulesResult)
    return __ret__.apply(lambda __response__: GetFileSystemQuotaRulesResult(
        are_violators_only=pulumi.get(__response__, 'are_violators_only'),
        file_system_id=pulumi.get(__response__, 'file_system_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        principal_id=pulumi.get(__response__, 'principal_id'),
        principal_type=pulumi.get(__response__, 'principal_type'),
        quota_rules=pulumi.get(__response__, 'quota_rules')))
